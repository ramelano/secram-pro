import asyncio
import stat

import pytest

from secram.core.models import TaskState
from secram.services.application import ApplicationService
from secram.tools.adapters.python_runtime import PythonRuntimeAdapter
from secram.tools.base import ToolRequest
from secram.tools.registry import ToolRegistry


def test_real_python_adapter():
    adapter = PythonRuntimeAdapter()
    assert adapter.probe().tested is False
    result = asyncio.run(adapter.run(ToolRequest("version")))
    assert result.returncode == 0
    assert adapter.normalize(result)["version"].startswith("Python 3.")
    assert adapter.probe().tested is True


@pytest.mark.parametrize("tool_request", [ToolRequest("scan"), ToolRequest("version", target="127.0.0.1"),
                                    ToolRequest("version", parameters={"code": "bad"}),
                                    ToolRequest("version", timeout=0), ToolRequest("version", timeout=31)])
def test_adapter_rejects_parameters(tool_request):
    with pytest.raises(ValueError):
        PythonRuntimeAdapter().validate(tool_request)


def test_registry_truthful_status():
    registry = ToolRegistry(); adapter = PythonRuntimeAdapter(); registry.register(adapter)
    registry.declare_planned("nmap", "Not Implemented")
    statuses = {item["name"]: item for item in registry.statuses()}
    assert statuses["nmap"]["installed"] is None
    assert statuses["nmap"]["integrated"] is False
    assert statuses["nmap"]["tested"] is False
    with pytest.raises(KeyError):
        registry.get("nmap")
    with pytest.raises(ValueError):
        registry.register(adapter)


def test_service_end_to_end(tmp_path):
    service = ApplicationService(tmp_path / "data")
    try:
        a = service.create_assessment("Yerel çekirdek", ["127.0.0.1/32"], "Test sahibi", "Yerel test")
        submitted = service.submit_operation(a.id, "Çekirdek kontrolü", "core.self_check")
        service.wait_idle()
        completed = service.repository.get_task(submitted.id)
        assert completed.state == TaskState.SUCCEEDED
        assert completed.result["security_assessment"] is False
        assert completed.result["runtime"]["version"].startswith("Python")
        assert service.counts()["assessments"] == 1
        assert any(item["tested"] for item in service.list_tools())
    finally:
        service.close()
    assert not service._thread.is_alive()
    reopened = ApplicationService(tmp_path / "data")
    try:
        assert reopened.list_tasks()[0].state == TaskState.SUCCEEDED
    finally:
        reopened.close()


def test_task_result_is_saved_as_private_json(tmp_path):
    service = ApplicationService(tmp_path / "data")
    try:
        assessment = service.create_assessment("Yerel çekirdek", ["127.0.0.1/32"], "Test sahibi", "Yerel test")
        task = service.submit_operation(assessment.id, "Çekirdek kontrolü", "core.self_check")
        service.wait_idle()
        output = service.save_task_result(task.id)
        assert output.is_file()
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert '"task_id"' in output.read_text(encoding="utf-8")
    finally:
        service.close()


def test_service_rejects_blank_authorization(tmp_path):
    service = ApplicationService(tmp_path / "data")
    try:
        with pytest.raises(ValueError):
            service.create_assessment("test", ["127.0.0.1/32"], " ", "reference")
        assert service.counts()["assessments"] == 0
    finally:
        service.close()


def test_unknown_scanning_operation_is_rejected(tmp_path):
    service = ApplicationService(tmp_path / "data")
    try:
        a = service.create_assessment("test", ["127.0.0.1/32"], "owner", "ref")
        with pytest.raises(KeyError):
            service.submit_operation(a.id, "scan", "nmap.scan", target="127.0.0.1")
        assert service.counts()["tasks"] == 0
    finally:
        service.close()
