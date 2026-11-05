from dataclasses import asdict

from secram.tools.base import ToolAdapter, ToolStatus


class ToolRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._planned: dict[str, str] = {}

    def register(self, adapter: ToolAdapter) -> None:
        if not adapter.name or adapter.name in self._adapters or adapter.name in self._planned:
            raise ValueError("Tool identifier must be unique and non-empty")
        self._adapters[adapter.name] = adapter

    def declare_planned(self, name: str, details: str) -> None:
        if not name or name in self._adapters or name in self._planned:
            raise ValueError("Tool identifier must be unique and non-empty")
        self._planned[name] = details

    def get(self, name: str) -> ToolAdapter:
        if name not in self._adapters:
            raise KeyError(f"No implemented adapter: {name}")
        return self._adapters[name]

    def statuses(self) -> list[dict]:
        result = []
        for adapter in self._adapters.values():
            try:
                result.append(asdict(adapter.probe()))
            except Exception as exc:
                result.append(asdict(ToolStatus(adapter.name, None, True, False, None,
                                                f"Probe failed: {type(exc).__name__}: {exc}")))
        result.extend(asdict(ToolStatus(name, None, False, False, None, details))
                      for name, details in self._planned.items())
        return result
