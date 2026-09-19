"""Stable contracts shared by all specialist engines."""
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any

@dataclass(frozen=True)
class EngineContext:
    client: str
    target: str
    output: str
    scope_file: str | None = None
    mode: str = "assessment"

@dataclass
class EngineResult:
    engine: str
    status: str
    target: str
    artifacts: list[str] = field(default_factory=list)
    handoffs: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.1"
    def to_dict(self) -> dict[str, Any]: return asdict(self)

class EngineContract:
    name = "unknown"
    version = "1.0"
    def describe(self) -> dict[str, Any]: return {"name": self.name, "version": self.version}
