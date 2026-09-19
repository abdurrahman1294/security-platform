from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from modules.tool_manager_v40 import ToolManager, TOOLS
from modules.tool_adapter_hardening_v162 import executable_path, verify_executable_identity

@dataclass(frozen=True)
class ToolStatus:
    name: str
    status: str
    path: str = ""
    detail: str = ""

def inventory() -> list[ToolStatus]:
    out=[]
    for name in sorted(TOOLS):
        try:
            p=executable_path(name)
            if p is None:
                out.append(ToolStatus(name, "unavailable-or-rejected")); continue
            ok, reason=verify_executable_identity(name, p)
            out.append(ToolStatus(name, "ready" if ok else "identity-failed", str(p), reason))
        except (OSError, RuntimeError, ValueError) as exc:
            out.append(ToolStatus(name, "error", detail=str(exc)))
    return out

def run(root: str | Path, tool: str, argv: list[str], timeout: int = 3600):
    if tool not in TOOLS:
        raise ValueError(f"Unregistered assessment tool: {tool}")
    return ToolManager(Path(root)).run(tool, argv, timeout=timeout)
