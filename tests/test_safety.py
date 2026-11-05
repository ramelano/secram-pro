import asyncio
import os
import sys

import pytest

from secram.tools.adapters.python_runtime import PythonRuntimeAdapter
from secram.tools.base import ToolRequest


def test_real_subprocess_timeout_is_reaped(monkeypatch):
    async def scenario():
        original = asyncio.create_subprocess_exec
        processes = []
        async def delayed_runtime(*args, **kwargs):
            # Test-only local child: exercises the adapter's cleanup path, no network.
            process = await original(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
            processes.append(process)
            return process
        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_runtime)
        with pytest.raises(TimeoutError):
            await PythonRuntimeAdapter().run(ToolRequest("version", timeout=0.1))
        assert processes[0].returncode is not None
        with pytest.raises(ProcessLookupError):
            os.kill(processes[0].pid, 0)
    asyncio.run(scenario())


def test_real_subprocess_cancellation_is_reaped(monkeypatch):
    async def scenario():
        original = asyncio.create_subprocess_exec
        processes = []; created = asyncio.Event()
        async def delayed_runtime(*args, **kwargs):
            process = await original(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
            processes.append(process); created.set()
            return process
        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_runtime)
        task = asyncio.create_task(PythonRuntimeAdapter().run(ToolRequest("version")))
        await created.wait(); task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert processes[0].returncode is not None
        with pytest.raises(ProcessLookupError):
            os.kill(processes[0].pid, 0)
    asyncio.run(scenario())


def test_unknown_tool_status_not_displayed_as_absent():
    from secram.ui.main_window import MainWindow
    assert MainWindow._yes_no(None) == "Doğrulanmadı"
    assert MainWindow._yes_no(False) == "Hayır"
    assert MainWindow._yes_no(True) == "Evet"


def test_task_port_is_immutable(tmp_path):
    from datetime import timedelta
    from secram.core.models import Assessment, Authorization, Scope, Task, utcnow
    from secram.storage.repository import Repository
    repo = Repository(tmp_path / "data" / "test.sqlite3")
    try:
        a = Assessment(title="test", scope=Scope(cidrs=["127.0.0.1/32"],
            allowed_operations={"test"}, allowed_ports={443}, expires_at=utcnow()+timedelta(hours=1)),
            authorization=Authorization(approved_by="owner", evidence_reference="ref", statement="test"))
        repo.save_assessment(a)
        task = Task(assessment_id=a.id, name="test", operation="test", target="127.0.0.1", port=443)
        repo.save_task(task)
        task.port = 80
        with pytest.raises(ValueError, match="immutable field 'port'"):
            repo.save_task(task)
        assert repo.get_task(task.id).port == 443
    finally:
        repo.close()


def test_real_ui_service_connection(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from secram.services.application import ApplicationService
    from secram.ui.main_window import MainWindow
    app = QApplication.instance() or QApplication([])
    service = ApplicationService(tmp_path / "data")
    window = MainWindow(service)
    try:
        window.title_input.setText("Gerçek UI çekirdek kontrolü")
        window.cidrs_input.setText("127.0.0.1/32")
        window.approved_by_input.setText("Yerel test sahibi")
        window.evidence_reference_input.setText("UI yerel entegrasyon testi")
        window.authorization_checkbox.setChecked(True)
        window.create_assessment_button.click()
        assert service.counts()["assessments"] == 1
        window.start_self_check_button.click()
        service.wait_idle(); window.refresh_data(); app.processEvents()
        assert service.list_tasks()[0].state.value == "succeeded"
        assert '"security_assessment": false' in window.task_result_view.toPlainText()
        assert "Python" in window.task_result_view.toPlainText()
    finally:
        window.close(); service.close(); app.processEvents()


def test_single_instance_protects_recovery(tmp_path):
    from secram.services.application import ApplicationService
    first = ApplicationService(tmp_path / "data")
    try:
        with pytest.raises(RuntimeError, match="Another SecRam-Pro instance"):
            ApplicationService(tmp_path / "data")
        assert first.counts()["tasks"] == 0
    finally:
        first.close()
    reopened = ApplicationService(tmp_path / "data")
    reopened.close()
