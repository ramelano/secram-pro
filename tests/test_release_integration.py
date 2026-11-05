import asyncio
import json
from pathlib import Path

import pytest

from secram.services.application import ApplicationService
from secram.core.models import Task, TaskState
from secram.storage.repository import Repository


@pytest.fixture
def service(tmp_path):
    app = ApplicationService(tmp_path / "data")
    yield app
    app.close()


def authorized(service, port):
    return service.create_assessment("Gerçek kontrollü otonom test", ["127.0.0.1/32"], "Yerel test sahibi",
        "Yalnız owned rootless lab gateway", allowed_operations={"orchestrator.run","nmap.tcp_scan",
        "web.http_headers","blue.monitor"}, allowed_ports={port})


def test_actual_autonomous_lab_and_all_reports(service):
    lab = service.create_lab()
    if lab["status"] != "running":
        pytest.skip("Rootless lab unavailable: " + lab.get("reason", "unknown"))
    assessment = authorized(service, lab["port"])
    task = service.submit_operation(assessment.id,"Otonom profil","orchestrator.run",target=lab["target"],
        params={"ports":[lab["port"]],"web_services":{str(lab["port"]):"http"}})
    service.wait_idle(90)
    finished = service.repository.get_task(task.id)
    assert finished.state.value == "succeeded", finished.error
    assert finished.result["status"] == "complete"
    operations = {service.repository.get_task(identity).operation for identity in finished.result["child_task_ids"]}
    assert {"nmap.tcp_scan","web.http_headers","blue.monitor"} <= operations
    assert service.list_findings(assessment.id)
    assert any(e["source"]=="lab_sensor" and e["details"]["method"]=="HEAD" for e in service.list_events(assessment.id))
    assert finished.result["purple"]["metrics"]["detection_rate"] is None
    assert finished.result["purple"]["metrics"]["false_positive_rate"] is None
    report = finished.result["report"]
    assert not report["unavailable_formats"], report["limitations"]
    assert set(report["files"]) == {"json","md","html","csv","pdf"}
    assert Path(report["files"]["pdf"]).read_bytes().startswith(b"%PDF")
    assert not service.blue_status()["running"]
    assert service.stop_lab()["status"] != "running"


def test_controller_works_with_single_execution_slot(service):
    async def one_slot():
        service.engine._semaphore = asyncio.Semaphore(1)
    service._call(one_slot())
    lab = service.create_lab()
    if lab["status"] != "running":
        pytest.skip("Rootless lab unavailable: " + lab.get("reason", "unknown"))
    a = authorized(service, lab["port"])
    task = service.submit_operation(a.id,"No nested slot deadlock","orchestrator.run",target="127.0.0.1",
        params={"ports":[lab["port"]],"web_services":{str(lab["port"]):"http"}})
    service.wait_idle(90)
    assert service.repository.get_task(task.id).state.value == "succeeded"


def test_new_profile_requires_its_own_scope_and_ports(service):
    a = service.create_assessment("Old scope",["127.0.0.1/32"],"owner","ref")
    for operation in ("blue.monitor","orchestrator.run","host.advisories"):
        with pytest.raises(ValueError):
            service.submit_operation(a.id,operation,operation,target="127.0.0.1" if operation=="orchestrator.run" else None)
    a = authorized(service,8080)
    for params in ({"ports":[8081]}, {"ports":[8080],"web_services":{"8080":"file"}},
                   {"ports":[8080],"command":"id"}):
        with pytest.raises(ValueError):
            service.submit_operation(a.id,"Bad plan","orchestrator.run",target="127.0.0.1",params=params)


def test_transaction_rolls_back_task_if_audit_fails(service, monkeypatch):
    a = service.create_assessment("Atomic test",["127.0.0.1/32"],"owner","ref")
    task = Task(assessment_id=a.id,name="Atomic",operation="core.self_check")
    service.repository.save_task(task)
    audit_count = service.repository.counts()["audit"]
    updated = task.model_copy(update={"state":TaskState.RUNNING})
    def fail(_):
        raise RuntimeError("controlled audit serialization failure")
    monkeypatch.setattr(service.repository,"_audit_row",fail)
    with pytest.raises(RuntimeError):
        service.repository.save_task_and_audit(updated,"task.transition",{})
    assert service.repository.get_task(task.id).state == TaskState.PENDING
    assert service.repository.counts()["audit"] == audit_count


def test_symlink_database_rejected(tmp_path):
    target = tmp_path / "real.db"; target.write_bytes(b"preserve")
    path = tmp_path / "link.db"; path.symlink_to(target)
    with pytest.raises(ValueError,match="symlink"):
        Repository(path)
    assert target.read_bytes() == b"preserve"


def test_offline_advisories_missing_data_not_clean(service):
    assert service.advisory_status()["data_available"] is False
    a=service.create_assessment("Offline advisory",["127.0.0.1/32"],"owner","ref",
                               allowed_operations={"host.advisories"})
    task=service.submit_operation(a.id,"OSV","host.advisories")
    service.wait_idle()
    result=service.repository.get_task(task.id).result
    assert result["status"] == "data_unavailable"
    assert result["clean"] is False
