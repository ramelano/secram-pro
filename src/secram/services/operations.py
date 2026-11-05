"""Application-owned offline operations; no second task engine or scheduler."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from secram.core.models import Task, utcnow
from secram.core.policies import PolicyEngine
from secram.modules.blue.monitor import BlueMonitor
from secram.modules.purple.correlation import correlate
from secram.modules.vulnerability.advisories import AdvisoryStore
from secram.lab.manager import LabManager
from secram.reporting.exporter import export_assessment


class Operations:
    def __init__(self, application):
        self.app = application
        self.monitor = None
        self.monitor_assessment = None
        self.expiry_task = None
        self.lab_poll_task = None
        self.lab = LabManager(application.data_dir / "lab")
        self.advisories = AdvisoryStore(application.data_dir / "advisories" / "osv.json")
        self._lab_seen = set()
        self.monitor_started = None

    def validate_blue(self, task: Task):
        if task.target is not None or task.port is not None:
            raise ValueError("Blue monitoring is local-only")
        if set(task.params) - {"auth_log", "integrity_paths", "ioc_ips"}:
            raise ValueError("Only explicit log, integrity paths and IOC IPs are supported")
        auth = task.params.get("auth_log")
        paths = task.params.get("integrity_paths", [])
        iocs = task.params.get("ioc_ips", [])
        if auth is not None and (not isinstance(auth, str) or not auth or len(auth) > 4096):
            raise ValueError("auth_log must be an explicit local path")
        if not isinstance(paths, list) or len(paths) > 16 or any(not isinstance(p, str) or not p or len(p) > 4096 for p in paths):
            raise ValueError("At most 16 explicit integrity paths are accepted")
        if not isinstance(iocs, list) or len(iocs) > 256 or any(not isinstance(ip, str) for ip in iocs):
            raise ValueError("At most 256 explicit IOC IP strings are accepted")

    @staticmethod
    def validate_local(task: Task):
        if task.target is not None or task.port is not None or task.params:
            raise ValueError("This local operation accepts no target, port or parameters")

    async def start_blue(self, task: Task):
        self.validate_blue(task)
        assessment = self.app.repository.get_assessment(task.assessment_id)
        PolicyEngine().check(assessment, task, target_required=False)
        if self.monitor is not None and self.monitor.snapshot()["running"]:
            if self.monitor_assessment != task.assessment_id:
                raise RuntimeError("A different assessment owns the active monitor")
            return self.blue_status()
        if self.monitor is not None:
            await self.stop_blue()
        self.monitor_assessment = task.assessment_id
        self.monitor_started = utcnow()
        self.monitor = BlueMonitor(lambda event: self._record_event(event, task.assessment_id), interval=0.5)
        result = await asyncio.to_thread(self.monitor.start,
            Path(task.params["auth_log"]) if task.params.get("auth_log") else None,
            [Path(p) for p in task.params.get("integrity_paths", [])], set(task.params.get("ioc_ips", [])))
        self.expiry_task = asyncio.create_task(self._expire_at(assessment.scope.expires_at))
        self.lab_poll_task = asyncio.create_task(self._poll_lab(task.assessment_id))
        return {**result, "assessment_id": task.assessment_id, "coverage_complete": False}

    def _record_event(self, event, assessment_id):
        assessment = self.app.repository.get_assessment(assessment_id)
        if utcnow() >= assessment.scope.expires_at:
            return
        event = dict(event, assessment_id=assessment_id)
        self.app.repository.audit("blue.event", assessment_id, payload=event)

    async def _expire_at(self, expires):
        await asyncio.sleep(max(0, (expires - utcnow()).total_seconds()))
        await self.stop_blue()

    async def _poll_lab(self, assessment_id):
        while self.monitor is not None and self.monitor.snapshot()["running"]:
            self.flush_lab_events(assessment_id)
            await asyncio.sleep(0.25)

    def flush_lab_events(self, assessment_id):
        if self.monitor_assessment != assessment_id or self.monitor is None or not self.monitor.snapshot()["running"]:
            return
        status = self.lab.status()
        path = Path(status["telemetry_path"])
        if not path.is_file() or path.is_symlink():
            return
        if path.stat().st_size > 2 * 1024 * 1024 or len(self._lab_seen) >= 4096:
            return  # A capped log is never claimed as complete coverage.
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            identity = event.get("id") if isinstance(event, dict) else None
            if not identity or identity in self._lab_seen or event.get("source") != "lab_sensor":
                continue
            try:
                observed = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
                if observed.tzinfo is None or self.monitor_started is None or observed.astimezone(timezone.utc) < self.monitor_started:
                    continue
            except (KeyError, ValueError, TypeError):
                continue
            self._record_event(event, assessment_id)
            self._lab_seen.add(identity)
            if len(self._lab_seen) >= 4096:
                break

    def blue_status(self):
        if self.monitor is None:
            return {"running": False, "assessment_id": None, "sources": {}, "coverage_complete": False}
        result = self.monitor.snapshot()
        result.pop("events", None)
        return dict(result, assessment_id=self.monitor_assessment, coverage_complete=False,
                    coverage_note="Polling and fixture observations are not complete packet/IDS coverage")

    async def stop_blue(self):
        current = asyncio.current_task()
        for worker in (self.expiry_task, self.lab_poll_task):
            if worker is not None and worker is not current:
                worker.cancel()
        workers = [w for w in (self.expiry_task, self.lab_poll_task) if w is not None and w is not current]
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        self.expiry_task = self.lab_poll_task = None
        if self.monitor is not None:
            result = await asyncio.to_thread(self.monitor.stop)
            result.pop("events", None)
            return dict(result, assessment_id=self.monitor_assessment)
        return {"running": False}

    def events(self, assessment_id=None, limit=2000):
        records = self.app.repository.list_audit(10000)
        events = [record.payload for record in records if record.event == "blue.event"
                  and (assessment_id is None or record.assessment_id == assessment_id)]
        return events[-limit:]

    def purple(self, assessment_id):
        tasks = [task.model_dump(mode="json") for task in self.app.list_tasks()
                 if task.assessment_id == assessment_id and task.operation != "orchestrator.run"]
        return correlate(tasks, self.events(assessment_id), coverage=None)

    async def match_advisories(self, task):
        self.validate_local(task)
        return await asyncio.to_thread(self.advisories.match_installed)

    async def export(self, assessment_id, output_dir=None):
        assessment = self.app.repository.get_assessment(assessment_id)
        tasks = [task.model_dump(mode="json") for task in self.app.list_tasks()
                 if task.assessment_id == assessment_id and task.operation != "orchestrator.run"]
        findings = [finding.model_dump(mode="json") for finding in self.app.list_findings(assessment_id)]
        return await asyncio.to_thread(export_assessment, assessment.model_dump(mode="json"), tasks,
            findings, self.events(assessment_id), self.purple(assessment_id),
            Path(output_dir) if output_dir is not None else self.app.data_dir / "reports")

    async def close(self):
        await self.stop_blue()
        await asyncio.to_thread(self.lab.close)
