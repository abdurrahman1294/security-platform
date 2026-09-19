"""Fail-closed preflight checks shared by active engines."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from modules.scope import is_valid_target_format, load_scope
from modules.security import in_scope

@dataclass(frozen=True)
class Preflight:
    target_valid: bool
    scope_present: bool
    target_in_scope: bool | None
    ready_for_active: bool
    blockers: tuple[str, ...]

    def to_dict(self):
        return asdict(self)

def check(target: str, scope_file: str | Path | None = None, *, active: bool = True) -> Preflight:
    """Check readiness. Passive/planning modes do not require an allowlist."""
    if not active:
        valid = is_valid_target_format(target)
        blockers = ("invalid-target-format",) if not valid else ()
        return Preflight(valid, bool(scope_file and Path(scope_file).is_file()), None, valid, blockers)

    blockers=[]
    valid=is_valid_target_format(target)
    if not valid: blockers.append("invalid-target-format")
    present=bool(scope_file and Path(scope_file).is_file())
    if not present:
        blockers.append("scope-file-missing")
    allowed=[]
    if present:
        try:
            allowed=load_scope(str(scope_file))
        except (OSError, UnicodeError):
            blockers.append("scope-read-failed")
    if present and not allowed: blockers.append("scope-empty")
    scoped=bool(valid and allowed and in_scope(target, allowed))
    if valid and allowed and not scoped: blockers.append("target-out-of-scope")
    return Preflight(valid,present,scoped,not blockers,tuple(dict.fromkeys(blockers)))
