from types import SimpleNamespace
from pathlib import Path
import json

import pytest

from secram.modules.blue.monitor import BlueMonitor
from secram.modules.vulnerability.advisories import AdvisoryStore
from secram.services.application import ApplicationService


def test_process_identity_cache_bounded_to_current_sample(monkeypatch):
    monitor=BlueMonitor(lambda event: None)
    for number in range(40):
        process=SimpleNamespace(pid=number,info={"pid":number,"create_time":float(number),"name":"test fixture"})
        monkeypatch.setattr("secram.modules.blue.monitor.psutil.process_iter",lambda fields,p=process:iter([p]))
        monitor._sample_processes()
        assert len(monitor._process_known)==1


def test_auth_batch_does_not_drop_complete_lines(tmp_path):
    path=tmp_path/"auth.log"; path.write_text("")
    observed=[]; monitor=BlueMonitor(observed.append)
    monitor._running=True
    monitor._auth_path=path
    with monitor._callback_condition: monitor._prepare_auth_locked(path)
    path.write_text("Failed password for test from 127.0.0.1 port 22\n"*300)
    monitor._poll_auth_log()
    assert len(observed)==300
    monitor.stop()


def test_mixed_integrity_sources_remain_limited(tmp_path):
    good=tmp_path/"good.txt"; good.write_text("owned")
    monitor=BlueMonitor(lambda event:None)
    monitor._integrity_paths=[tmp_path/"missing",good]
    monitor._poll_integrity()
    assert monitor.snapshot()["sources"]["integrity"]=="limited"


def test_sparse_advisory_feed_never_claims_clean(tmp_path):
    source=tmp_path/"fixture.json"
    source.write_text(json.dumps({"id":"OSV-TEST-SPARSE","affected":[{"package":{"name":"unrelated-test","ecosystem":"PyPI"},"versions":["1.0"]}]}))
    store=AdvisoryStore(tmp_path/"private"/"store.json")
    assert store.import_osv(source)["accepted"]
    result=store.match_packages([{"name":"another-test","version":"1.0"}])
    assert result["matches"]==[] and result["clean"] is False


def test_failed_constructor_releases_instance_lock(tmp_path):
    data=tmp_path/"data"; data.mkdir()
    target=tmp_path/"somewhere"; target.mkdir()
    (data/"lab").symlink_to(target,target_is_directory=True)
    with pytest.raises(ValueError): ApplicationService(data)
    (data/"lab").unlink()
    app=ApplicationService(data)
    app.close()


def test_expiry_requires_integer_hours(tmp_path):
    app=ApplicationService(tmp_path/"data")
    try:
        for invalid in (True,1.5,"1"):
            with pytest.raises(ValueError): app.create_assessment("Invalid",["127.0.0.1/32"],"owner","ref",expires_hours=invalid)
    finally: app.close()


def test_actual_gui_lab_autonomous_controls(stable_qt_application,tmp_path):
    from secram.ui.main_window import MainWindow
    qt_app=stable_qt_application
    app=ApplicationService(tmp_path/"data")
    window=MainWindow(app)
    try:
        panel=window.operations_panel
        panel.create_lab()
        if app.lab_status()["status"]!="running":
            pytest.skip("Rootless lab unavailable: "+app.lab_status().get("reason","unknown"))
        panel.lab_assessment(); window.refresh_data()
        assert panel.auto_button.isEnabled()
        panel.start_auto(); app.wait_idle(90); window.refresh_data()
        assert '"status": "complete"' in panel.auto_view.toPlainText()
        assert '"detection_rate": null' in panel.purple_view.toPlainText()
        panel.export_report()
        assert '"pdf"' in panel.report_view.toPlainText()
    finally:
        window.close(); qt_app.processEvents(); app.close()


def test_running_operation_stops_at_scope_deadline(tmp_path):
    import asyncio
    from datetime import timedelta
    from secram.core.models import Assessment,Authorization,Scope,Task,utcnow
    from secram.core.tasks import TaskEngine,Operation
    from secram.storage.repository import Repository
    async def scenario():
        repo=Repository(tmp_path/"deadline.db")
        a=Assessment(title="Deadline",scope=Scope(cidrs=["127.0.0.1/32"],allowed_operations={"test.local_wait"},
            expires_at=utcnow()+timedelta(seconds=0.3)),authorization=Authorization(approved_by="owner",evidence_reference="owned unit fixture",statement="Only owned local fixture"))
        repo.save_assessment(a)
        engine=TaskEngine(repo)
        completed=[]
        async def handler(task):
            await asyncio.sleep(1)
            completed.append(True)
            return {"complete":True}
        engine.register(Operation("test.local_wait",handler,target_required=False,timeout=5))
        task=Task(assessment_id=a.id,name="Deadline",operation="test.local_wait")
        await engine.submit(task); await engine.wait_idle()
        assert repo.get_task(task.id).state.value=="failed"
        assert completed==[]
        await engine.close(); repo.close()
    asyncio.run(scenario())
