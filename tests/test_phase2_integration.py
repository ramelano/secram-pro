import hashlib
import json
import os
import socket

import pytest

from secram.services.application import ApplicationService


@pytest.fixture
def service(tmp_path):
    app = ApplicationService(tmp_path / "data")
    yield app
    app.close()


def create_scope(service, *, operations=None, ports=None):
    return service.create_assessment("Yerel yetkili Phase 2 testi", ["127.0.0.1/32"],
        "Yerel test sahibi", "Geçici sandbox testi",
        allowed_operations=operations, allowed_ports=ports)


def test_existing_scope_not_silently_expanded(service):
    assessment = create_scope(service)
    assert assessment.scope.allowed_operations == {"core.self_check"}
    with pytest.raises(ValueError, match="outside the authorized scope"):
        service.submit_operation(assessment.id, "Host", "host.snapshot")
    assert service.counts()["tasks"] == 0


def test_host_service_real_snapshot_and_local_only(service):
    assessment = create_scope(service, operations={"host.snapshot"})
    task = service.submit_operation(assessment.id, "Host", "host.snapshot")
    service.wait_idle()
    finished = service.repository.get_task(task.id)
    assert finished.state.value == "succeeded"
    assert finished.result["operation"] == "host.snapshot"
    assert finished.result["memory"]["total"] > 0
    assert finished.result["storage"]["total"] > 0
    assert len(finished.result["processes"]["items"]) <= 200
    with pytest.raises(ValueError, match="local-only"):
        service.submit_operation(assessment.id, "Remote Host", "host.snapshot", target="127.0.0.1")


def test_nmap_invalid_scope_params_rejected_before_execution(service, monkeypatch):
    assessment = create_scope(service, operations={"nmap.tcp_scan"}, ports={443})
    called = []
    async def forbidden_run(request):
        called.append(request)
        raise AssertionError("Invalid request reached the execution layer")
    monkeypatch.setattr(service.registry.get("nmap"), "run", forbidden_run)
    for target, params in [
        ("127.0.0.1", {"ports": [80]}),
        ("192.0.2.1", {"ports": [443]}),
        ("localhost", {"ports": [443]}),
        ("127.0.0.1", {"ports": [443], "args": ["--script"]}),
        ("127.0.0.1", {"ports": [True]}),
    ]:
        with pytest.raises(ValueError):
            service.submit_operation(assessment.id, "Invalid scan", "nmap.tcp_scan", target=target, params=params)
    assert called == []
    assert service.counts()["tasks"] == 0


@pytest.mark.parametrize("operations,ports", [
    ({"unknown"}, set()), ({"nmap.tcp_scan"}, set()),
    ({"host.snapshot"}, {443}), ({"nmap.tcp_scan"}, {True}),
    ({"nmap.tcp_scan"}, {0}), ({"nmap.tcp_scan"}, set(range(1, 34))),
])
def test_assessment_permissions_are_explicit(service, operations, ports):
    with pytest.raises(ValueError):
        create_scope(service, operations=operations, ports=ports)
    assert service.counts()["assessments"] == 0


def test_real_qt_host_and_nmap_flow(service):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from secram.ui.main_window import MainWindow
    app = QApplication.instance() or QApplication([])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0)); listener.listen(4)
    port = listener.getsockname()[1]
    window = MainWindow(service)
    try:
        window.title_input.setText("Gerçek yerel Host + Nmap")
        window.cidrs_input.setText("127.0.0.1/32")
        window.approved_by_input.setText("Sandbox test sahibi")
        window.evidence_reference_input.setText("Geçici yerel TCP servisi")
        window.host_permission_checkbox.setChecked(True)
        window.nmap_permission_checkbox.setChecked(True)
        window.scope_ports_input.setText(str(port))
        window.authorization_checkbox.setChecked(True)
        window.create_assessment_button.click()
        assert service.counts()["assessments"] == 1
        assert not window.authorization_checkbox.isChecked()
        assert window.start_host_button.isEnabled()
        window.start_host_button.click(); service.wait_idle(); window.refresh_data()
        assert '"host.snapshot"' in window.host_result_view.toPlainText()
        assert window.start_nmap_button.isEnabled()
        window.nmap_target_input.setText("127.0.0.1")
        window.nmap_ports_input.setText(str(port))
        window.start_nmap_button.click(); service.wait_idle(); window.refresh_data(); app.processEvents()
        task = next(task for task in service.list_tasks() if task.operation == "nmap.tcp_scan")
        assert task.state.value == "succeeded", task.error
        result = task.result
        assert result["target"] == "127.0.0.1"
        assert result["requested_ports"] == [port]
        assert any(p["port"] == port and p["state"] == "open" for p in result["hosts"][0]["ports"])
        assert result["raw_xml_sha256"] == hashlib.sha256(result["stdout"].encode()).hexdigest()
        assert '"open"' in window.nmap_result_view.toPlainText()
        assert next(tool for tool in service.list_tools() if tool["name"] == "nmap")["tested"] is True
        assert any(record.event == "tool.completed" for record in service.list_audit())
        assert json.loads(window.nmap_result_view.toPlainText())["state"] == "succeeded"
    finally:
        window.close(); listener.close(); app.processEvents()


@pytest.mark.parametrize("text", ["1-100", "80,80", "80;id", "", "65536", "-1", "８０"])
def test_ui_port_list_rejects_invalid_or_empty_input(text):
    from secram.ui.main_window import _parse_ports
    if text == "":
        assert _parse_ports(text) == []
    else:
        with pytest.raises(ValueError):
            _parse_ports(text)
