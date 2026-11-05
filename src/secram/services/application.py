from __future__ import annotations

import asyncio
import fcntl
import os
from pathlib import Path
import sys
from threading import Event, Thread
from datetime import timedelta

from secram.core.models import Assessment, Authorization, Scope, Task, utcnow
from secram.core.tasks import Operation, TaskEngine
from secram.storage.repository import Repository
from secram.tools.base import ToolRequest
from secram.tools.registry import ToolRegistry
from secram.tools.adapters.python_runtime import PythonRuntimeAdapter
from secram.tools.adapters.nmap import NmapAdapter
from secram.platforms.linux.host import LinuxHostProvider
from secram.modules.vulnerability.checks import WebChecks
from secram.modules.vulnerability.findings import Finding, normalize_findings, merge_findings
from secram.services.operations import Operations
from secram.agents.orchestrator import Orchestrator


def default_data_dir() -> Path:
    configured = os.environ.get("XDG_DATA_HOME")
    base = Path(configured) if configured and Path(configured).is_absolute() else Path.home() / ".local/share"
    return base / "secram-pro"


class ApplicationService:
    def __init__(self, data_dir: Path | None = None) -> None:
        if sys.platform != "linux":
            raise RuntimeError("This release supports Linux only")
        self.data_dir = data_dir or default_data_dir()
        self.repository = Repository(self.data_dir / "secram.sqlite3")
        try:
            self._lock_fd = os.open(self.data_dir / ".instance.lock",
                                    os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError:
            self.repository.close()
            raise
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_fd)
            self.repository.close()
            raise RuntimeError("Another SecRam-Pro instance is using this data directory") from exc
        self.repository.recover_interrupted()
        self.registry = ToolRegistry()
        self.registry.register(PythonRuntimeAdapter())
        self.registry.register(NmapAdapter())
        self.host_provider = LinuxHostProvider()
        self.web_checks = WebChecks()
        self.engine = TaskEngine(self.repository)
        try:
            self.ops = Operations(self)
            self.orchestrator = Orchestrator(self)
        except Exception:
            self.repository.close()
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            raise
        self.engine.register(Operation("core.self_check", self._self_check,
                                       target_required=False, timeout=10))
        self.engine.register(Operation("host.snapshot", self._host_snapshot, target_required=False,
                                       timeout=15, validate=self._validate_host_task))
        self.engine.register(Operation("nmap.tcp_scan", self._nmap_scan, timeout=45,
                                       validate=self._validate_nmap_task))
        self.engine.register(Operation("web.http_headers", self._web_check, timeout=15,
                                       validate=self._validate_web_task))
        self.engine.register(Operation("web.tls_check", self._web_check, timeout=15,
                                       validate=self._validate_web_task))
        self.engine.register(Operation("blue.monitor", self.ops.start_blue, target_required=False,
                                       timeout=10, validate=self.ops.validate_blue))
        self.engine.register(Operation("host.advisories", self.ops.match_advisories, target_required=False,
                                       timeout=30, validate=self.ops.validate_local))
        self.engine.register(Operation("orchestrator.run", self.orchestrator.run, timeout=240,
                                       validate=self.orchestrator.validate, consume_slot=False))
        self._ready = Event()
        self._loop = asyncio.new_event_loop()
        self._closed = False
        self._thread = Thread(target=self._run_loop, name="secram-task-engine", daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("Task engine failed to start")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()
        self._loop.run_until_complete(self._loop.shutdown_asyncgens())
        self._loop.run_until_complete(self._loop.shutdown_default_executor(timeout=5))
        self._loop.close()

    def _call(self, coroutine, *, timeout: float = 5):
        if self._closed:
            coroutine.close()
            raise RuntimeError("Application is closed")
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            raise RuntimeError(f"Task engine did not respond within {timeout:g} seconds") from None

    async def _self_check(self, task: Task) -> dict:
        if task.target is not None or task.port is not None or task.params:
            raise ValueError("Local self-check accepts no target, port or parameters")
        adapter = self.registry.get("python-runtime")
        result = await adapter.run(ToolRequest("version", timeout=5))
        return {"check": "core.self_check", "security_assessment": False,
                "platform": sys.platform, "runtime": adapter.normalize(result),
                "database_counts": self.repository.counts()}

    @staticmethod
    def _validate_host_task(task: Task) -> None:
        if task.target is not None or task.port is not None or task.params:
            raise ValueError("Host snapshot is local-only and accepts no target or parameters")

    async def _host_snapshot(self, task: Task) -> dict:
        self._validate_host_task(task)
        return await asyncio.to_thread(self.host_provider.collect)

    def _nmap_request(self, task: Task) -> ToolRequest:
        if task.port is not None:
            raise ValueError("Nmap port list must be supplied through validated ports parameters")
        return ToolRequest("tcp_scan", timeout=30, target=task.target, parameters=task.params,
                           assessment=self.repository.get_assessment(task.assessment_id))

    def _validate_nmap_task(self, task: Task) -> None:
        self.registry.get("nmap").validate(self._nmap_request(task))

    async def _nmap_scan(self, task: Task) -> dict:
        adapter = self.registry.get("nmap")
        result = await adapter.run(self._nmap_request(task))
        normalized = adapter.normalize(result)
        self.repository.audit("tool.completed", task.assessment_id, task.id,
                              {"tool": "nmap", "target": task.target,
                               "raw_xml_sha256": normalized.get("raw_xml_sha256"),
                               "scan_status": normalized.get("scan_status")})
        return normalized

    def _validate_web_task(self, task: Task) -> None:
        self.web_checks.validate(task, self.repository.get_assessment(task.assessment_id))

    async def _web_check(self, task: Task) -> dict:
        result = await self.web_checks.run(task, self.repository.get_assessment(task.assessment_id))
        findings = normalize_findings(task, result)
        result["findings"] = [finding.model_dump(mode="json") for finding in findings]
        self.repository.audit("web.completed", task.assessment_id, task.id,
                              {"operation": task.operation, "target": task.target, "port": task.port,
                               "status": result.get("status"), "candidate_count": len(findings)})
        return result

    def create_assessment(self, title: str, cidrs: list[str], approved_by: str,
                          evidence_reference: str, expires_hours: int = 24,
                          allowed_operations: set[str] | None = None,
                          allowed_ports: set[int] | None = None) -> Assessment:
        if self._closed:
            raise RuntimeError("Application is closed")
        if not title.strip() or type(expires_hours) is not int or not 1 <= expires_hours <= 168:
            raise ValueError("A title and authorization duration of 1–168 hours are required")
        operations = set(allowed_operations) if allowed_operations is not None else {"core.self_check"}
        ports = set(allowed_ports) if allowed_ports is not None else set()
        network_ops = {"nmap.tcp_scan", "web.http_headers", "web.tls_check", "orchestrator.run"}
        local_ops = {"core.self_check", "host.snapshot", "blue.monitor", "host.advisories"}
        if not operations or not operations <= local_ops | network_ops:
            raise ValueError("Only implemented operation identifiers can be authorized")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("Authorized ports must be literal integers between 1 and 65535")
        if operations & network_ops and not 1 <= len(ports) <= 32:
            raise ValueError("Network checks require 1–32 explicitly authorized TCP ports")
        if ports and not operations & network_ops:
            raise ValueError("Port authorization requires an implemented network operation")
        assessment = Assessment(
            title=title.strip(),
            scope=Scope(cidrs=cidrs, allowed_operations=operations, allowed_ports=ports,
                        expires_at=utcnow() + timedelta(hours=expires_hours)),
            authorization=Authorization(
                approved_by=approved_by, evidence_reference=evidence_reference,
                statement="Kullanıcı seçilen kapsam için yetki sahibi olduğunu beyan etti. "
                          "Bu kayıt, yetkinin bağımsız olarak doğrulandığı anlamına gelmez.",
            ),
        )
        self.repository.save_assessment(assessment)
        self.repository.audit("assessment.created", assessment.id,
                              payload={"cidrs": assessment.scope.cidrs,
                                       "allowed_operations": sorted(operations),
                                       "allowed_ports": sorted(ports),
                                       "approved_by": assessment.authorization.approved_by})
        return assessment

    def submit_operation(self, assessment_id: str, name: str, operation: str,
                         target: str | None = None, port: int | None = None,
                         params: dict | None = None, dependencies: list[str] | None = None) -> Task:
        task = Task(assessment_id=assessment_id, name=name, operation=operation,
                    target=target, port=port, params=params or {}, dependencies=dependencies or [])
        return self._call(self.engine.submit(task))

    def cancel_task(self, task_id: str) -> None:
        self._call(self.engine.cancel(task_id))

    def wait_idle(self, timeout: float = 60) -> None:
        self._call(self.engine.wait_idle(), timeout=timeout)

    def list_assessments(self) -> list[Assessment]:
        return self.repository.list_assessments()

    def list_tasks(self) -> list[Task]:
        return self.repository.list_tasks()

    def list_audit(self, limit: int = 200):
        return self.repository.list_audit(limit)

    def list_tools(self) -> list[dict]:
        return self.registry.statuses()

    def start_blue(self, assessment_id, auth_log=None, integrity_paths=None, ioc_ips=None):
        params = {"integrity_paths": [str(p) for p in (integrity_paths or [])], "ioc_ips": sorted(ioc_ips or [])}
        if auth_log is not None:
            params["auth_log"] = str(auth_log)
        return self.submit_operation(assessment_id, "Yerel Blue izleme başlangıcı", "blue.monitor", params=params)

    def stop_blue(self):
        return self._call(self.ops.stop_blue(), timeout=10)

    def blue_status(self):
        return self.ops.blue_status()

    def list_events(self, assessment_id=None):
        return self.ops.events(assessment_id)

    def purple_result(self, assessment_id):
        return self.ops.purple(assessment_id)

    def create_lab(self):
        return self._call(asyncio.to_thread(self.ops.lab.create), timeout=10)

    def stop_lab(self):
        return self._call(asyncio.to_thread(self.ops.lab.stop), timeout=10)

    def lab_status(self):
        return self.ops.lab.status()

    def export_report(self, assessment_id, output_dir=None):
        return self._call(self.ops.export(assessment_id, output_dir), timeout=30)

    def import_advisories(self, source):
        return self.ops.advisories.import_osv(Path(source))

    def advisory_status(self):
        return self.ops.advisories.status()

    def list_findings(self, assessment_id: str | None = None) -> list[Finding]:
        findings = []
        for task in self.repository.list_tasks():
            if assessment_id is not None and task.assessment_id != assessment_id:
                continue
            for payload in task.result.get("findings", []):
                findings.append(Finding.model_validate(payload))
        return merge_findings(findings)

    def counts(self) -> dict[str, int]:
        counts = self.repository.counts()
        counts["findings"] = len(self.list_findings())
        return counts

    def close(self) -> None:
        if self._closed:
            return
        async def shutdown():
            await self.engine.close()
            await self.ops.close()
        self._call(shutdown(), timeout=15)
        self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=8)
        if self._thread.is_alive():
            raise RuntimeError("Task engine did not stop; repository remains open")
        self.repository.close()
        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
