import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError

from secram.core.models import Assessment, Authorization, Scope, Task, TaskState, utcnow
from secram.core.policies import PolicyDenied, PolicyEngine
from secram.core.tasks import Operation, TaskEngine
from secram.storage.repository import Repository


def assessment(**scope_overrides):
    data = dict(cidrs=["192.0.2.0/24", "2001:db8::/32"],
                allowed_operations={"test.check"}, allowed_ports={443},
                expires_at=utcnow() + timedelta(hours=1))
    data.update(scope_overrides)
    return Assessment(title="Yetkili test kapsamı", scope=Scope(**data),
                      authorization=Authorization(approved_by="Test sahibi",
                                                  evidence_reference="Yerel test fixture",
                                                  statement="Yalnızca yazılım birim testi"))


@pytest.fixture
def repo(tmp_path):
    repository = Repository(tmp_path / "private" / "test.sqlite3")
    yield repository
    repository.close()


@pytest.mark.parametrize("target,port", [("192.0.2.7", 443), ("2001:db8::7", None)])
def test_allowed_target(target, port):
    a = assessment()
    PolicyEngine().check(a, Task(assessment_id=a.id, name="test", operation="test.check",
                                target=target, port=port), target_required=True)


@pytest.mark.parametrize("target,port", [
    ("198.51.100.1", None), ("127.0.0.1", None), ("example.org", None),
    ("192.0.2.1; whoami", None), ("192.0.2.1", 80), (None, None),
    (" 192.0.2.1", None), ("2001:db8::1%eth0", None),
])
def test_scope_rejects(target, port):
    a = assessment()
    with pytest.raises(PolicyDenied):
        PolicyEngine().check(a, Task(assessment_id=a.id, name="test", operation="test.check",
                                    target=target, port=port), target_required=True)


def test_expired_authorization():
    a = assessment(starts_at=utcnow() - timedelta(hours=2),
                   expires_at=utcnow() - timedelta(hours=1))
    with pytest.raises(PolicyDenied):
        PolicyEngine().check(a, Task(assessment_id=a.id, name="test", operation="test.check",
                                    target="192.0.2.1"), target_required=True)


def test_operation_denied():
    a = assessment()
    with pytest.raises(PolicyDenied):
        PolicyEngine().check(a, Task(assessment_id=a.id, name="test", operation="scan",
                                    target="192.0.2.1"), target_required=True)


@pytest.mark.parametrize("field,value", [("cidrs", ["192.0.2.7/24"]),
                                         ("allowed_ports", {65536}),
                                         ("allowed_ports", {0}),
                                         ("allowed_operations", set()),
                                         ("expires_at", utcnow().replace(tzinfo=None))])
def test_invalid_scope(field, value):
    with pytest.raises(ValidationError):
        assessment(**{field: value})


def test_authorization_blank_rejected():
    with pytest.raises(ValidationError):
        Authorization(approved_by=" ", evidence_reference="ref", statement="yes")


def new_task(a, **kwargs):
    return Task(assessment_id=a.id, name="test", operation="test.check",
                target="192.0.2.1", **kwargs)


async def success(task):
    return {"task": task.id}


def test_task_success_and_audit(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        engine = TaskEngine(repo); engine.register(Operation("test.check", success))
        task = await engine.submit(new_task(a))
        await engine.wait_idle()
        finished = repo.get_task(task.id)
        assert finished.state == TaskState.SUCCEEDED
        assert finished.result == {"task": task.id}
        assert finished.started_at is not None and finished.finished_at is not None
        states = [r.payload["to"] for r in repo.list_audit() if r.event == "task.transition"]
        assert states == ["ready", "running", "succeeded"]
        await engine.close()
    asyncio.run(scenario())


def test_dependency_order(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        order = []
        async def handler(task):
            order.append(task.id); await asyncio.sleep(0.02); return {}
        engine = TaskEngine(repo); engine.register(Operation("test.check", handler))
        first = await engine.submit(new_task(a))
        second = await engine.submit(new_task(a, dependencies=[first.id]))
        await engine.wait_idle()
        assert order == [first.id, second.id]
        assert repo.get_task(second.id).state == TaskState.SUCCEEDED
        await engine.close()
    asyncio.run(scenario())


def test_failed_dependency_blocks_handler(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        calls = []
        async def handler(task):
            calls.append(task.id); raise RuntimeError("expected failure")
        engine = TaskEngine(repo); engine.register(Operation("test.check", handler))
        first = await engine.submit(new_task(a))
        second = await engine.submit(new_task(a, dependencies=[first.id]))
        await engine.wait_idle()
        assert calls == [first.id]
        assert "prerequisite" in repo.get_task(second.id).error
        await engine.close()
    asyncio.run(scenario())


def test_running_cancel_and_cleanup(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        entered = asyncio.Event(); cleaned = asyncio.Event()
        async def handler(task):
            entered.set()
            try:
                await asyncio.sleep(60)
            finally:
                cleaned.set()
        engine = TaskEngine(repo); engine.register(Operation("test.check", handler))
        task = await engine.submit(new_task(a)); await entered.wait()
        await engine.cancel(task.id)
        assert cleaned.is_set()
        assert repo.get_task(task.id).state == TaskState.CANCELLED
        await engine.close()
    asyncio.run(scenario())


def test_immediate_cancel(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        engine = TaskEngine(repo); engine.register(Operation("test.check", success))
        task = await engine.submit(new_task(a)); await engine.cancel(task.id)
        assert repo.get_task(task.id).state == TaskState.CANCELLED
        await engine.close()
    asyncio.run(scenario())


def test_approval_gate(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        engine = TaskEngine(repo)
        engine.register(Operation("test.check", success, requires_approval=True))
        task = await engine.submit(new_task(a))
        assert task.state == TaskState.AWAITING_APPROVAL
        await engine.wait_idle()
        assert repo.get_task(task.id).started_at is None
        with pytest.raises(ValueError):
            await engine.approve(task.id, approved_by=" ", evidence_reference="ref")
        await engine.approve(task.id, approved_by="Operator", evidence_reference="Task-specific consent")
        await engine.wait_idle()
        assert repo.get_task(task.id).state == TaskState.SUCCEEDED
        assert any(r.event == "task.approved" for r in repo.list_audit())
        await engine.close()
    asyncio.run(scenario())


def test_timeout(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        async def handler(task):
            await asyncio.sleep(60)
        engine = TaskEngine(repo); engine.register(Operation("test.check", handler, timeout=0.02))
        task = await engine.submit(new_task(a)); await engine.wait_idle()
        assert repo.get_task(task.id).state == TaskState.FAILED
        assert "TimeoutError" in repo.get_task(task.id).error
        await engine.close()
    asyncio.run(scenario())


def test_concurrency_limit(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        active = 0; peak = 0
        async def handler(task):
            nonlocal active, peak
            active += 1; peak = max(peak, active)
            try:
                await asyncio.sleep(0.02); return {}
            finally:
                active -= 1
        engine = TaskEngine(repo, concurrency=1); engine.register(Operation("test.check", handler))
        for _ in range(3):
            await engine.submit(new_task(a))
        await engine.wait_idle(); assert peak == 1
        await engine.close()
    asyncio.run(scenario())


def test_duplicate_unknown_dependencies_and_cross_scope(repo):
    async def scenario():
        a = assessment(); b = assessment(); repo.save_assessment(a); repo.save_assessment(b)
        engine = TaskEngine(repo); engine.register(Operation("test.check", success))
        first = await engine.submit(new_task(a))
        with pytest.raises(ValueError):
            await engine.submit(repo.get_task(first.id))
        with pytest.raises(KeyError):
            await engine.submit(new_task(a, dependencies=["missing"]))
        with pytest.raises(ValueError):
            await engine.submit(new_task(b, dependencies=[first.id]))
        await engine.close()
    asyncio.run(scenario())


def test_scope_rechecked_after_wait(repo):
    async def scenario():
        a = assessment(expires_at=utcnow() + timedelta(seconds=0.25)); repo.save_assessment(a)
        calls = []
        async def handler(task):
            calls.append(task.id); await asyncio.sleep(0.4); return {}
        engine = TaskEngine(repo, concurrency=1); engine.register(Operation("test.check", handler))
        first = await engine.submit(new_task(a)); second = await engine.submit(new_task(a))
        await engine.wait_idle()
        assert calls == [first.id]
        assert repo.get_task(second.id).state == TaskState.FAILED
        assert "Authorization" in repo.get_task(second.id).error
        await engine.close()
    asyncio.run(scenario())


def test_illegal_transition(repo):
    a = assessment(); repo.save_assessment(a)
    task = new_task(a); repo.save_task(task)
    engine = TaskEngine(repo)
    with pytest.raises(ValueError):
        engine._transition(task, TaskState.SUCCEEDED)


def test_no_handler_for_unimplemented_operation(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        engine = TaskEngine(repo)
        with pytest.raises(KeyError):
            await engine.submit(new_task(a))
        assert repo.counts()["tasks"] == 0
        assert repo.list_audit()[-1].event == "task.rejected"
        await engine.close()
    asyncio.run(scenario())


def test_cancelling_waiter_does_not_cancel_operation(repo):
    async def scenario():
        a = assessment(); repo.save_assessment(a)
        started = asyncio.Event(); release = asyncio.Event()
        async def handler(task):
            started.set(); await release.wait(); return {}
        engine = TaskEngine(repo); engine.register(Operation("test.check", handler))
        task = await engine.submit(new_task(a)); await started.wait()
        waiter = asyncio.create_task(engine.wait_idle()); await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert repo.get_task(task.id).state == TaskState.RUNNING
        release.set(); await engine.wait_idle()
        assert repo.get_task(task.id).state == TaskState.SUCCEEDED
        await engine.close()
    asyncio.run(scenario())
