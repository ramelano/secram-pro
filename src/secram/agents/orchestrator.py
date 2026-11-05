"""One bounded rule-based controller over the existing persistent TaskEngine."""
import asyncio

from secram.agents.red import RedAgent
from secram.core.models import Task, TaskState, TERMINAL_STATES


class Orchestrator:
    def __init__(self, application):
        self.app = application
        self._lock = asyncio.Lock()

    def validate(self, task):
        RedAgent.validate(task, self.app.repository.get_assessment(task.assessment_id))

    async def _child(self, parent, operation, created, **kwargs):
        child = Task(assessment_id=parent.assessment_id, name=f"Auto: {operation}", operation=operation, **kwargs)
        await self.app.engine.submit(child)
        created.append(child.id)
        return child

    async def _wait(self, child):
        while True:
            task = self.app.repository.get_task(child.id)
            if task.state in TERMINAL_STATES:
                return task
            await asyncio.sleep(0.05)

    async def run(self, task):
        created, decisions, auto_blue = [], [], False
        async with self._lock:
            self.validate(task)
            assessment = self.app.repository.get_assessment(task.assessment_id)
            allowed = assessment.scope.allowed_operations
            self.app.repository.audit("red.assessment.started", task.assessment_id, task.id,
                                      {"target": task.target, "ports": task.params.get("ports", []),
                                       "technique": "T1046", "mode": "scoped_network_service_discovery"})
            try:
                if "blue.monitor" in allowed and not self.app.ops.blue_status()["running"]:
                    blue = await self._child(task, "blue.monitor", created)
                    blue = await self._wait(blue)
                    auto_blue = blue.state == TaskState.SUCCEEDED
                    decisions.append({"operation": "blue.monitor", "state": blue.state.value})
                if "host.snapshot" in allowed:
                    host = await self._child(task, "host.snapshot", created)
                    await self._wait(host)
                scan = await self._child(task, "nmap.tcp_scan", created, target=task.target,
                                         params={"ports": task.params["ports"]})
                scan = await self._wait(scan)
                if scan.state == TaskState.SUCCEEDED:
                    actions, red_decisions = RedAgent.next_steps(task.target, scan.result, allowed, task.params.get("web_services", {}))
                    decisions.extend(red_decisions)
                    children = [await self._child(task, action.pop("operation"), created, **action) for action in actions]
                    if children:
                        await asyncio.gather(*(self._wait(child) for child in children))
                else:
                    decisions.append({"reason": "Nmap execution failed; no blind follow-up", "error": scan.error})
                self.app.ops.flush_lab_events(task.assessment_id)
                if auto_blue:
                    await self.app.ops.stop_blue()
                    auto_blue = False
                report = await self.app.ops.export(task.assessment_id)
                children = [self.app.repository.get_task(identity) for identity in created]
                conclusive = scan.state == TaskState.SUCCEEDED and scan.result.get("scan_status") == "complete"
                checks_conclusive = all(child.state == TaskState.SUCCEEDED and child.result.get("status") != "inconclusive" for child in children)
                red_summary = {"version": "0.1", "target": task.target,
                               "technique": "T1046 Network Service Scanning",
                               "requested_ports": list(task.params["ports"]),
                               "open_ports": sorted({p["port"] for h in scan.result.get("hosts", [])
                                                      for p in h.get("ports", []) if p.get("state") == "open"})
                               if scan.state == TaskState.SUCCEEDED else [],
                               "follow_up_operations": [decision.get("operation") for decision in decisions
                                                         if decision.get("operation")],
                               "limitations": ["TCP connect discovery only", "No exploitation, credential attack, persistence or evasion"]}
                self.app.repository.audit("red.assessment.completed", task.assessment_id, task.id,
                                          {"status": "complete" if conclusive and checks_conclusive else "inconclusive",
                                           "open_ports": red_summary["open_ports"], "technique": "T1046"})
                return {"profile": "red_team_v0.1_scoped", "target": task.target,
                        "status": "complete" if conclusive and checks_conclusive else "inconclusive",
                        "child_task_ids": created, "decisions": decisions, "red": red_summary,
                        "finding_count": len(self.app.list_findings(task.assessment_id)),
                        "purple": self.app.ops.purple(task.assessment_id), "report": report,
                        "limitations": ["No LLM, exploit or unrestricted command execution",
                                        "Unknown service ports are not blindly tested",
                                        "Blue polling is not complete IDS/packet coverage; unmeasurable rates stay unknown"]}
            finally:
                for identity in created:
                    if self.app.repository.get_task(identity).state not in TERMINAL_STATES:
                        await self.app.engine.cancel(identity)
                if auto_blue:
                    await self.app.ops.stop_blue()
