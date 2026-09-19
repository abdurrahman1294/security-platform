from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from modules.scope import load_scope, is_valid_target_format
from modules.security import in_scope

@dataclass(frozen=True)
class ScopePolicy:
    """Immutable active-testing allowlist. Construction never exits the process."""
    scope_file: Path
    allowed: tuple[str, ...]

    @classmethod
    def from_file(cls, path: str | Path, target: str = "") -> "ScopePolicy":
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise ValueError(f"Scope file does not exist: {p}")
        allowed = tuple(load_scope(str(p)))
        if not allowed:
            raise ValueError("Scope is empty; refusing active operation")
        if target:
            if not is_valid_target_format(target):
                raise ValueError(f"Invalid or dangerous target format: {target}")
            if not in_scope(target, list(allowed)):
                raise ValueError(f"Target '{target}' is out of scope according to '{p}'")
        return cls(p, allowed)

    def contains(self, target: str) -> bool:
        return in_scope(target, list(self.allowed))
