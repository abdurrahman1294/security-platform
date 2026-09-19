"""Specialist-engine registry with deterministic discovery and factories."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Any

@dataclass(frozen=True)
class EngineSpec:
    name: str
    description: str
    factory: Callable[..., Any]
    active: bool = True
    version: str = "1.0"
    capabilities: tuple[str, ...] = ()

_REGISTRY: dict[str, EngineSpec] = {}

def register(spec: EngineSpec) -> None:
    if spec.name in _REGISTRY:
        raise ValueError(f"Engine already registered: {spec.name}")
    _REGISTRY[spec.name] = spec

def get(name: str) -> EngineSpec:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"Unknown engine: {name}") from exc

def all_specs() -> tuple[EngineSpec, ...]:
    return tuple(_REGISTRY[k] for k in sorted(_REGISTRY))
