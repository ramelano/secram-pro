from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Awaitable, Callable

from secram.core.models import Task, TaskState, TERMINAL_STATES, utcnow
from secram.core.policies import PolicyEngine
from secram.storage.repository import Repository

Handler = Callable[[Task], Awaitable[dict]]


@dataclass(frozen=True)
class Operation:
    name: str
    handler: Handler
    target_required: bool = True
    requires_approval: bool = False
    timeout: float = 30.0
    validate: Callable[[Task], None] | None = None
    consume_slot: bool = True


TRANSITIONS = {
    TaskState.PENDING: {TaskState.READY, TaskState.AWAITING_APPROVAL, TaskState.FAILED, TaskState.CANCELLED},
    TaskState.READY: {TaskState.RUNNING, TaskState.FAILED, TaskState.CANCELLED},
    TaskState.RUNNING: TERMINAL_STATES,
    TaskState.AWAITING_APPROVAL: {TaskState.READY, TaskState.FAILED, TaskState.CANCELLED},
}


class TaskEngine:
    """One event-loop owner; all operations pass policy and parameter gates."""

    def __init__(self, repository: Repository, *, concurrency: int = 2) -> None:
        if concurrency < 1:
            raise ValueError("Concurrency must be positive")
        self.repository = repository
        self.policy = PolicyEngine()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._operations: dict[str, Operation] = {}
        self._workers: dict[str, asyncio.Task] = {}
        self._closed = False

    def register(self, operation: Operation) -> None:
        if not operation.name or operation.name in self._operations or not 0 < operation.timeout <= 3600:
            raise ValueError("Invalid or duplicate operation")
        self._operations[operation.name] = operation

    def _check(self, task: Task, operation: Operation) -> None:
        self.policy.check(self.repository.get_assessment(task.assessment_id), task,
                          target_required=operation.target_required)
        if operation.validate is not None:
            operation.validate(task)

    def _transition(self, task: Task, state: TaskState, *, error: str | None = None,
                    result: dict | None = None) -> Task:
        if state not in TRANSITIONS.get(task.state, set()):
            raise ValueError(f"Illegal transition: {task.state} -> {state}")
        previous = task.state
        updated = task.model_copy(deep=True)
        updated.state = state
        updated.error = error
        if result is not None:
            updated.result = result
        if state == TaskState.RUNNING:
            updated.started_at = utcnow()
        if state in TERMINAL_STATES:
            updated.finished_at = utcnow()
        self.repository.save_task_and_audit(updated, "task.transition",
                                            {"from": previous.value, "to": state.value, "error": error})
        return updated

    async def submit(self, task: Task) -> Task:
        if self._closed:
            raise RuntimeError("Task engine is closed")
        try:
            operation = self._operations[task.operation]
            if task.state != TaskState.PENDING or task.result or task.started_at or task.finished_at:
                raise ValueError("Only new pending tasks can be submitted")
            try:
                self.repository.get_task(task.id)
            except KeyError:
                pass
            else:
                raise ValueError("Task identity already exists")
            self._check(task, operation)
            if len(set(task.dependencies)) != len(task.dependencies) or task.id in task.dependencies:
                raise ValueError("Invalid task dependencies")
            for dep_id in task.dependencies:
                dependency = self.repository.get_task(dep_id)
                if dependency.assessment_id != task.assessment_id:
                    raise ValueError("Cross-assessment dependencies are forbidden")
        except Exception as exc:
            self.repository.audit("task.rejected", task.assessment_id, None,
                                  {"operation": task.operation, "error": str(exc)})
            raise
        # Only existing dependencies are accepted, so new tasks cannot create cycles.
        self.repository.save_task_and_audit(task, "task.created",
                                            {"operation": task.operation, "target": task.target})
        if operation.requires_approval:
            return self._transition(task, TaskState.AWAITING_APPROVAL)
        return self._dispatch(task, operation)

    def _dispatch(self, task: Task, operation: Operation) -> Task:
        ready = self._transition(task, TaskState.READY)
        self._workers[task.id] = asyncio.create_task(self._execute(ready, operation), name=task.id)
        self._workers[task.id].add_done_callback(lambda _: self._workers.pop(task.id, None))
        return ready

    async def approve(self, task_id: str, *, approved_by: str, evidence_reference: str) -> Task:
        if self._closed:
            raise RuntimeError("Task engine is closed")
        if not approved_by.strip() or not evidence_reference.strip():
            raise ValueError("Explicit approver and approval evidence are required")
        task = self.repository.get_task(task_id)
        if task.state != TaskState.AWAITING_APPROVAL:
            raise ValueError("Task is not awaiting approval")
        operation = self._operations[task.operation]
        self._check(task, operation)
        self.repository.audit("task.approved", task.assessment_id, task.id,
                              {"approved_by": approved_by.strip(),
                               "evidence_reference": evidence_reference.strip()})
        return self._dispatch(task, operation)

    @asynccontextmanager
    async def _execution_slot(self, operation: Operation):
        if operation.consume_slot:
            async with self._semaphore:
                yield
        else:
            yield

    async def _execute(self, task: Task, operation: Operation) -> None:
        try:
            # A bounded wait prevents indefinitely blocked dependency chains.
            assessment = self.repository.get_assessment(task.assessment_id)
            remaining = (assessment.scope.expires_at - utcnow()).total_seconds()
            if remaining <= 0:
                raise ValueError("Authorization expired before execution")
            async with asyncio.timeout(min(operation.timeout, remaining)):
                while task.dependencies:
                    dependencies = [self.repository.get_task(dep) for dep in task.dependencies]
                    if any(dep.state in {TaskState.FAILED, TaskState.CANCELLED} for dep in dependencies):
                        raise RuntimeError("A prerequisite task did not succeed")
                    if all(dep.state == TaskState.SUCCEEDED for dep in dependencies):
                        break
                    await asyncio.sleep(0.05)
                async with self._execution_slot(operation):
                    self._check(task, operation)  # Recheck after waiting: scope may have expired.
                    task = self._transition(task, TaskState.RUNNING)
                    result = await operation.handler(task)
                    if not isinstance(result, dict):
                        raise TypeError("Operation result must be a dictionary")
                    task = self._transition(task, TaskState.SUCCEEDED, result=result)
        except asyncio.CancelledError:
            current = self.repository.get_task(task.id)
            if current.state not in TERMINAL_STATES:
                self._transition(current, TaskState.CANCELLED, error="Cancelled by operator or shutdown")
            raise
        except Exception as exc:
            current = self.repository.get_task(task.id)
            if current.state not in TERMINAL_STATES:
                detail = str(exc) or "Operation failed"
                if isinstance(exc, TimeoutError):
                    scope = self.repository.get_assessment(task.assessment_id).scope
                    detail = "Authorization expired during operation or queue wait" if utcnow() >= scope.expires_at else "Operation timeout"
                self._transition(current, TaskState.FAILED,
                                 error=f"{type(exc).__name__}: {detail}")

    async def cancel(self, task_id: str) -> None:
        task = self.repository.get_task(task_id)
        if task.state in TERMINAL_STATES:
            return
        self.repository.audit("task.cancel_requested", task.assessment_id, task.id)
        worker = self._workers.get(task_id)
        if worker is not None:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
        # A coroutine can be cancelled before it starts, bypassing its try/finally.
        current = self.repository.get_task(task_id)
        if current.state not in TERMINAL_STATES:
            self._transition(current, TaskState.CANCELLED, error="Cancelled before execution")

    async def wait_idle(self) -> None:
        while self._workers:
            await asyncio.gather(*(asyncio.shield(worker) for worker in tuple(self._workers.values())),
                                 return_exceptions=True)

    async def close(self) -> None:
        self._closed = True
        for task_id in tuple(self._workers):
            await self.cancel(task_id)
        for task in self.repository.list_tasks():
            if task.state == TaskState.AWAITING_APPROVAL:
                await self.cancel(task.id)
