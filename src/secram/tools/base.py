from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from secram.core.models import Assessment


@dataclass(frozen=True)
class ToolStatus:
    name: str
    installed: bool | None
    integrated: bool
    tested: bool
    supported: bool | None
    details: str
    executable: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class ToolRequest:
    operation: str
    timeout: float = 10.0
    target: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    assessment: Assessment | None = None


@dataclass(frozen=True)
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    data: dict[str, Any]


class ToolAdapter(ABC):
    name: str

    @abstractmethod
    def probe(self) -> ToolStatus: ...

    @abstractmethod
    def validate(self, request: ToolRequest) -> None: ...

    @abstractmethod
    async def run(self, request: ToolRequest) -> ToolResult: ...

    @abstractmethod
    def normalize(self, result: ToolResult) -> dict[str, Any]: ...
