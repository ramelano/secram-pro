import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from secram.services.application import ApplicationService


class HtmlHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=never-store-this-test-token")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HtmlHandler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    yield server
    server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_real_http_ui_findings_and_persistence(tmp_path, http_server):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from secram.ui.main_window import MainWindow
    qt = QApplication.instance() or QApplication([])
    service = ApplicationService(tmp_path / "data")
    window = MainWindow(service)
    port = http_server.server_port
    assessment_id = None
    try:
        window.title_input.setText("Yerel HTTP aday bulgu testi")
        window.cidrs_input.setText("127.0.0.1/32")
        window.approved_by_input.setText("Yerel test sahibi")
        window.evidence_reference_input.setText("Yerel test HTTP servisi")
        window.http_permission_checkbox.setChecked(True)
        window.scope_ports_input.setText(str(port))
        window.authorization_checkbox.setChecked(True)
        window.create_assessment_button.click()
        assessment_id = window.selected_assessment_id
        assert assessment_id
        assert window.start_http_button.isEnabled()
        assert not window.start_tls_button.isEnabled()
        window.web_target_input.setText("127.0.0.1")
        window.web_port_input.setValue(port)
        window.web_scheme_input.setCurrentText("http")
        window.start_http_button.click(); service.wait_idle(); window.refresh_data(); qt.processEvents()
        task = service.list_tasks()[0]
        assert task.state.value == "succeeded", task.error
        assert task.result["status"] == "complete"
        findings = service.list_findings(assessment_id)
        assert findings
        assert all(finding.status.value == "candidate" for finding in findings)
        assert all(finding.evidence and finding.recommendation for finding in findings)
        assert window.findings_table.rowCount() == len(findings)
        assert "recommendation" in window.finding_detail_view.toPlainText()
        assert "never-store-this-test-token" not in task.model_dump_json()
        before = len(findings)
        window.start_http_button.click(); service.wait_idle(); window.refresh_data()
        merged = service.list_findings(assessment_id)
        assert len(merged) == before
        assert all(len(finding.task_ids) == 2 for finding in merged)
    finally:
        window.close(); service.close(); qt.processEvents()
    reopened = ApplicationService(tmp_path / "data")
    try:
        assert reopened.list_findings(assessment_id)
    finally:
        reopened.close()


def test_web_scope_denial_before_network(tmp_path, monkeypatch):
    service = ApplicationService(tmp_path / "data")
    try:
        a = service.create_assessment("Web scope", ["127.0.0.1/32"], "owner", "ref",
            allowed_operations={"web.http_headers"}, allowed_ports={8080})
        called = []
        async def forbidden(*args):
            called.append(True); raise AssertionError("Invalid scope reached network")
        monkeypatch.setattr(service.web_checks, "run", forbidden)
        for target, port, params in [("192.0.2.1",8080,{"scheme":"http"}),
                                     ("127.0.0.1",8081,{"scheme":"http"}),
                                     ("localhost",8080,{"scheme":"http"}),
                                     ("127.0.0.1",8080,{"scheme":"http","path":"/admin"})]:
            with pytest.raises(ValueError):
                service.submit_operation(a.id, "HTTP", "web.http_headers", target=target, port=port, params=params)
        assert called == [] and service.counts()["tasks"] == 0
        assert service.list_findings() == []
    finally:
        service.close()


def test_default_assessment_has_no_new_web_permissions(tmp_path):
    service = ApplicationService(tmp_path / "data")
    try:
        a = service.create_assessment("Old scope", ["127.0.0.1/32"], "owner", "ref")
        assert a.scope.allowed_operations == {"core.self_check"}
        with pytest.raises(ValueError):
            service.submit_operation(a.id, "HTTP", "web.http_headers", target="127.0.0.1", port=80,
                                     params={"scheme":"http"})
    finally:
        service.close()
