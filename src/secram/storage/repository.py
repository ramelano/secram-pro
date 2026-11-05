"""Durable SQLite repository for the Phase 1 domain models.

The repository deliberately stores each domain object as a Pydantic JSON document.
The relational columns are limited to identifiers, the task foreign key, and the
monotonic audit sequence needed for safe ordering and referential integrity.
"""
from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from secram.core.models import (
    Assessment,
    AuditRecord,
    Task,
    TaskState,
    utcnow,
)


SCHEMA_VERSION = 1
_SCHEMA_TABLE = "schema_metadata"
_STORAGE_TABLES = frozenset({"assessments", "tasks", "audit_records"})
_BUSY_TIMEOUT_MS = 10_000


class SchemaVersionError(ValueError):
    """Raised when a database is not a known repository schema."""


class _Base(DeclarativeBase):
    pass


class _SchemaMetadata(_Base):
    __tablename__ = _SCHEMA_TABLE

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class _AssessmentRow(_Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    data: Mapped[str] = mapped_column(Text, nullable=False)


class _TaskRow(_Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )
    data: Mapped[str] = mapped_column(Text, nullable=False)


class _AuditRow(_Base):
    __tablename__ = "audit_records"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)


_SCHEMA_INIT_LOCK = RLock()


class Repository:
    """Thread-safe, synchronous SQLite repository with one Session per call."""

    _TASK_IDENTITY_FIELDS = (
        "assessment_id",
        "operation",
        "name",
        "target",
        "port",
        "params",
        "dependencies",
    )
    _TASK_MUTABLE_FIELDS = (
        "state",
        "result",
        "error",
        "started_at",
        "finished_at",
    )

    def __init__(self, path: Path):
        self._path = Path(path).expanduser().absolute()
        self._lifecycle_lock = RLock()
        self._write_lock = RLock()
        self._closed = False

        self._ensure_private_parent(self._path.parent)
        if self._path.is_symlink():
            raise ValueError("A symlink database path is not accepted")
        if self._path.exists():
            if not self._path.is_file():
                raise IsADirectoryError(self._path)
            os.chmod(self._path, 0o600)

        self._engine: Engine = create_engine(
            f"sqlite:///{self._path.as_posix()}",
            connect_args={"check_same_thread": False},
        )
        event.listen(self._engine, "connect", self._configure_sqlite)
        self._session_factory = sessionmaker(
            bind=self._engine,
            class_=Session,
            expire_on_commit=False,
            autoflush=True,
        )

        try:
            self._initialize_schema()
            # SQLite creates a missing database file on first connect. Secure it
            # after that point without ever changing an existing parent directory.
            os.chmod(self._path, 0o600)
        except Exception:
            self._engine.dispose()
            raise

    @staticmethod
    def _ensure_private_parent(parent: Path) -> None:
        """Create only missing parent components with private permissions."""
        missing: list[Path] = []
        current = parent
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                break
            current = current.parent

        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                # Another creator won the race; never chmod an arbitrary
                # directory that this instance did not create.
                continue
            os.chmod(directory, 0o700)

    @staticmethod
    def _configure_sqlite(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.fetchone()
        finally:
            cursor.close()

    def _initialize_schema(self) -> None:
        """Create a new v1 database, but reject unknown or ambiguous schemas."""
        with _SCHEMA_INIT_LOCK:
            with self._engine.begin() as connection:
                table_names = set(inspect(connection).get_table_names())

                if _SCHEMA_TABLE in table_names:
                    version = connection.execute(
                        text(f"SELECT version FROM {_SCHEMA_TABLE} WHERE id = 1")
                    ).scalar_one_or_none()
                    if version is None:
                        raise SchemaVersionError(
                            "Repository schema metadata is missing its version"
                        )
                    if int(version) != SCHEMA_VERSION:
                        raise SchemaVersionError(
                            f"Unsupported repository schema version: {version}"
                        )
                    _Base.metadata.create_all(connection)
                    return

                if table_names.intersection(_STORAGE_TABLES):
                    raise SchemaVersionError(
                        "Repository schema metadata is missing; refusing implicit migration"
                    )

                _Base.metadata.create_all(connection)
                connection.execute(
                    _SchemaMetadata.__table__.insert().values(
                        id=1,
                        version=SCHEMA_VERSION,
                    )
                )

    def _new_session(self) -> Session:
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("Repository is closed")
            return self._session_factory()

    @staticmethod
    def _decode(model_type: type[BaseModel], payload: str) -> Any:
        return model_type.model_validate_json(payload)

    @staticmethod
    def _audit_row(record: AuditRecord) -> _AuditRow:
        return _AuditRow(record_id=record.id, data=record.model_dump_json())

    def save_assessment(self, assessment: Assessment) -> None:
        payload = assessment.model_dump_json()
        with self._write_lock:
            session = self._new_session()
            try:
                with session.begin():
                    row = session.get(_AssessmentRow, assessment.id)
                    if row is None:
                        session.add(_AssessmentRow(id=assessment.id, data=payload))
                    else:
                        current = self._decode(Assessment, row.data)
                        if current != assessment:
                            raise ValueError(
                                f"Assessment {assessment.id!r} already exists with different contents"
                            )
            finally:
                session.close()

    def get_assessment(self, id: str) -> Assessment:
        session = self._new_session()
        try:
            row = session.get(_AssessmentRow, id)
            if row is None:
                raise KeyError(id)
            return self._decode(Assessment, row.data)
        finally:
            session.close()

    def list_assessments(self) -> list[Assessment]:
        session = self._new_session()
        try:
            rows = session.scalars(select(_AssessmentRow)).all()
            assessments = [self._decode(Assessment, row.data) for row in rows]
            assessments.sort(key=lambda item: (item.created_at, item.id))
            return assessments
        finally:
            session.close()

    def save_task(self, task: Task) -> None:
        payload = task.model_dump_json()
        with self._write_lock:
            session = self._new_session()
            try:
                with session.begin():
                    self._upsert_task(session, task, payload)
            finally:
                session.close()

    def _upsert_task(self, session: Session, task: Task, payload: str) -> None:
        row = session.get(_TaskRow, task.id)
        if row is None:
            session.add(_TaskRow(id=task.id, assessment_id=task.assessment_id, data=payload))
            return
        current = self._decode(Task, row.data)
        if row.assessment_id != current.assessment_id:
            raise ValueError(f"Task {task.id!r} has inconsistent stored identity")
        for field in self._TASK_IDENTITY_FIELDS:
            if getattr(current, field) != getattr(task, field):
                raise ValueError(f"Task {task.id!r} immutable field {field!r} cannot change")
        updated = current.model_copy(update={field: getattr(task, field) for field in self._TASK_MUTABLE_FIELDS})
        row.data = updated.model_dump_json()

    def save_task_and_audit(self, task: Task, event: str, payload: dict[str, Any]) -> AuditRecord:
        record = AuditRecord(event=event, assessment_id=task.assessment_id, task_id=task.id, payload=payload)
        with self._write_lock:
            session = self._new_session()
            try:
                with session.begin():
                    self._upsert_task(session, task, task.model_dump_json())
                    session.add(self._audit_row(record))
            finally:
                session.close()
        return record

    def get_task(self, id: str) -> Task:
        session = self._new_session()
        try:
            row = session.get(_TaskRow, id)
            if row is None:
                raise KeyError(id)
            return self._decode(Task, row.data)
        finally:
            session.close()

    def list_tasks(self) -> list[Task]:
        session = self._new_session()
        try:
            rows = session.scalars(select(_TaskRow)).all()
            tasks = [self._decode(Task, row.data) for row in rows]
            tasks.sort(key=lambda item: (item.created_at, item.id))
            return tasks
        finally:
            session.close()

    def audit(
        self,
        event: str,
        assessment_id: str | None = None,
        task_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecord:
        record = AuditRecord(
            event=event,
            assessment_id=assessment_id,
            task_id=task_id,
            payload={} if payload is None else payload,
        )
        with self._write_lock:
            session = self._new_session()
            try:
                with session.begin():
                    session.add(self._audit_row(record))
            finally:
                session.close()
        return record

    def list_audit(self, limit: int = 200) -> list[AuditRecord]:
        if limit < 0:
            raise ValueError("Audit limit cannot be negative")
        session = self._new_session()
        try:
            rows = session.scalars(
                select(_AuditRow)
                .order_by(_AuditRow.sequence.desc())
                .limit(limit)
            ).all()
            return [self._decode(AuditRecord, row.data) for row in reversed(rows)]
        finally:
            session.close()

    def counts(self) -> dict[str, int]:
        session = self._new_session()
        try:
            return {
                "assessments": int(
                    session.scalar(select(func.count()).select_from(_AssessmentRow)) or 0
                ),
                "tasks": int(
                    session.scalar(select(func.count()).select_from(_TaskRow)) or 0
                ),
                "audit": int(
                    session.scalar(select(func.count()).select_from(_AuditRow)) or 0
                ),
            }
        finally:
            session.close()

    def recover_interrupted(self) -> int:
        """Fail persisted ready/running tasks and append one recovery audit event."""
        with self._write_lock:
            session = self._new_session()
            try:
                with session.begin():
                    rows = session.scalars(select(_TaskRow).order_by(_TaskRow.id)).all()
                    recovered_ids: list[str] = []
                    for row in rows:
                        task = self._decode(Task, row.data)
                        if task.state not in {TaskState.RUNNING, TaskState.READY}:
                            continue
                        task.state = TaskState.FAILED
                        task.error = "Interrupted: manual resubmission required"
                        task.finished_at = utcnow()
                        row.data = task.model_dump_json()
                        recovered_ids.append(task.id)

                    recovery = AuditRecord(
                        event="recovery",
                        payload={
                            "count": len(recovered_ids),
                            "task_ids": recovered_ids,
                        },
                    )
                    session.add(self._audit_row(recovery))
                    return len(recovered_ids)
            finally:
                session.close()

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._engine.dispose()


__all__ = ["Repository", "SCHEMA_VERSION", "SchemaVersionError"]
