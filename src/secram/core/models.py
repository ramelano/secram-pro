"""Phase 1 domain contracts. No scanning or host-monitoring implementation."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_network
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class TaskState(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"


TERMINAL_STATES = {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED}


class Scope(Model):
    cidrs: list[str] = Field(min_length=1, max_length=256)
    allowed_operations: set[str] = Field(min_length=1)
    allowed_ports: set[int] = Field(default_factory=set)
    starts_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime

    @field_validator("cidrs")
    @classmethod
    def networks(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(str(ip_network(value.strip(), strict=True)) for value in values))

    @field_validator("allowed_ports")
    @classmethod
    def ports(cls, values: set[int]) -> set[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("Ports must be between 1 and 65535")
        return values

    @field_validator("starts_at", "expires_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timezone-aware timestamps required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def valid_window(self) -> Scope:
        if self.expires_at <= self.starts_at:
            raise ValueError("Authorization must expire after its start")
        if not all(op.strip() == op and op for op in self.allowed_operations):
            raise ValueError("Operation identifiers cannot be blank")
        return self


class Authorization(Model):
    approved_by: str = Field(min_length=1, max_length=200)
    evidence_reference: str = Field(min_length=1, max_length=1000)
    statement: str = Field(min_length=1, max_length=2000)
    recorded_at: datetime = Field(default_factory=utcnow)

    @field_validator("approved_by", "evidence_reference", "statement")
    @classmethod
    def nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Authorization fields cannot be blank")
        return value


class Assessment(Model):
    id: str = Field(default_factory=new_id)
    title: str = Field(min_length=1, max_length=200)
    scope: Scope
    authorization: Authorization
    created_at: datetime = Field(default_factory=utcnow)


class Task(Model):
    id: str = Field(default_factory=new_id)
    assessment_id: str
    name: str = Field(min_length=1, max_length=200)
    operation: str = Field(min_length=1, max_length=100)
    target: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    params: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list, max_length=128)
    state: TaskState = TaskState.PENDING
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class AuditRecord(Model):
    id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utcnow)
    event: str
    assessment_id: str | None = None
    task_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
