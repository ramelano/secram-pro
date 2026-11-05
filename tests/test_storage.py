from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from secram.core.models import (
    Assessment,
    Authorization,
    Scope,
    Task,
    TaskState,
    utcnow,
)
from secram.storage.repository import Repository, SchemaVersionError


def make_assessment(identifier: str = "assessment-1") -> Assessment:
    starts_at = utcnow()
    return Assessment(
        id=identifier,
        title="Storage test assessment",
        scope=Scope(
            cidrs=["192.0.2.0/24"],
            allowed_operations={"probe"},
            starts_at=starts_at,
            expires_at=starts_at + timedelta(hours=1),
        ),
        authorization=Authorization(
            approved_by="Test approver",
            evidence_reference="ticket-1",
            statement="Authorized test scope",
        ),
    )


def make_task(
    assessment_id: str,
    identifier: str = "task-1",
    *,
    state: TaskState = TaskState.PENDING,
) -> Task:
    return Task(
        id=identifier,
        assessment_id=assessment_id,
        name="Probe task",
        operation="probe",
        target="192.0.2.10",
        params={"mode": "safe"},
        dependencies=[],
        state=state,
    )


def test_persistence_reopen_and_counts(tmp_path: Path) -> None:
    database = tmp_path / "repo.sqlite3"
    assessment = make_assessment()
    task = make_task(assessment.id)

    repository = Repository(database)
    repository.save_assessment(assessment)
    repository.save_task(task)
    created_audit = repository.audit(
        "assessment.created",
        assessment_id=assessment.id,
        payload={"source": "test"},
    )
    assert repository.counts() == {"assessments": 1, "tasks": 1, "audit": 1}
    repository.close()

    reopened = Repository(database)
    assert reopened.get_assessment(assessment.id) == assessment
    assert reopened.get_task(task.id) == task
    assert reopened.list_assessments() == [assessment]
    assert reopened.list_tasks() == [task]
    assert reopened.list_audit() == [created_audit]
    assert database.stat().st_mode & 0o777 == 0o600
    reopened.close()


def test_missing_assessment_is_rejected_by_foreign_key(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")

    with pytest.raises(IntegrityError):
        repository.save_task(make_task("missing-assessment"))

    assert repository.counts()["tasks"] == 0
    repository.close()


def test_concurrent_audit_writes_are_safe(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")

    def write_event(index: int):
        return repository.audit("concurrent", payload={"index": index})

    with ThreadPoolExecutor(max_workers=8) as executor:
        records = list(executor.map(write_event, range(64)))

    assert len({record.id for record in records}) == 64
    stored = repository.list_audit(limit=100)
    assert len(stored) == 64
    assert [record.event for record in stored] == ["concurrent"] * 64
    assert {record.payload["index"] for record in stored} == set(range(64))
    repository.close()


def test_audit_latest_limit_is_returned_in_chronological_order(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")
    for index in range(5):
        repository.audit("ordered", payload={"index": index})

    latest = repository.list_audit(limit=3)
    assert [record.payload["index"] for record in latest] == [2, 3, 4]
    assert repository.list_audit(limit=0) == []
    repository.close()


def test_unknown_schema_version_is_rejected_before_use(tmp_path: Path) -> None:
    database = tmp_path / "repo.sqlite3"
    repository = Repository(database)
    repository.close()

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE schema_metadata SET version = 99 WHERE id = 1")

    with pytest.raises(SchemaVersionError):
        Repository(database)


def test_recover_interrupted_tasks_and_audit_recovery(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")
    assessment = make_assessment()
    repository.save_assessment(assessment)
    running = make_task(assessment.id, "running", state=TaskState.RUNNING)
    ready = make_task(assessment.id, "ready", state=TaskState.READY)
    succeeded = make_task(assessment.id, "succeeded", state=TaskState.SUCCEEDED)
    for task in (running, ready, succeeded):
        repository.save_task(task)

    assert repository.recover_interrupted() == 2
    for task_id in (running.id, ready.id):
        recovered = repository.get_task(task_id)
        assert recovered.state is TaskState.FAILED
        assert recovered.error == "Interrupted: manual resubmission required"
        assert recovered.finished_at is not None
        assert recovered.finished_at.tzinfo is not None
    assert repository.get_task(succeeded.id) == succeeded

    recovery = repository.list_audit(limit=1)[0]
    assert recovery.event == "recovery"
    assert recovery.payload == {"count": 2, "task_ids": ["ready", "running"]}
    repository.close()


def test_task_save_updates_mutable_fields_only(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")
    assessment = make_assessment()
    original = make_task(assessment.id)
    repository.save_assessment(assessment)
    repository.save_task(original)

    changed = original.model_copy(
        update={
            "state": TaskState.SUCCEEDED,
            "result": {"ok": True},
            "error": None,
        }
    )
    repository.save_task(changed)
    stored = repository.get_task(original.id)
    assert stored.state is TaskState.SUCCEEDED
    assert stored.result == {"ok": True}
    assert stored.assessment_id == original.assessment_id
    assert stored.operation == original.operation
    assert stored.name == original.name
    assert stored.target == original.target
    assert stored.params == original.params
    assert stored.dependencies == original.dependencies
    assert stored.created_at == original.created_at
    repository.close()


def test_conflicting_assessment_is_rejected_without_overwrite(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "repo.sqlite3")
    original = make_assessment()
    repository.save_assessment(original)
    conflicting = original.model_copy(update={"title": "Different contents"})

    with pytest.raises(ValueError):
        repository.save_assessment(conflicting)

    assert repository.get_assessment(original.id) == original
    repository.close()
