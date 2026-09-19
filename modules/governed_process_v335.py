"""Central fixed-argv subprocess boundary for legacy/local specialist tools.

This is not a general command runner. Only named local tools with fixed
argument contracts may use it; callers must construct argv themselves and
shell execution is permanently disabled.
"""
from __future__ import annotations
import os, shutil, subprocess
from pathlib import Path
from typing import Iterable

ALLOWED_TOOLS = {
    "xcrun", "iw", "nmcli", "airmon-ng", "tshark", "apkanalyzer", "aapt", "aapt2",
}
MAX_STDOUT = 200_000
MAX_STDERR = 20_000

def resolve_tool(name: str) -> str | None:
    if name not in ALLOWED_TOOLS: raise ValueError("tool-not-allowlisted")
    path = shutil.which(name)
    if not path: return None
    p = Path(path).resolve()
    if not p.is_file() or not os.access(p, os.X_OK): return None
    try:
        if p.parent.stat().st_mode & 0o022: return None
    except OSError: return None
    return str(p)

def run_fixed(tool: str, argv: Iterable[str], *, timeout: float = 60.0) -> dict:
    resolved = resolve_tool(tool)
    if not resolved: return {"returncode": None, "stdout": "", "stderr": "tool-unavailable"}
    args = [str(x) for x in argv]
    if not args or Path(args[0]).name != Path(resolved).name:
        raise ValueError("argv-executable-mismatch")
    if not 0 < float(timeout) <= 300: raise ValueError("timeout-out-of-range")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=float(timeout), shell=False,
                           env={k:v for k,v in os.environ.items() if k in {"PATH","HOME","LANG","LC_ALL","LC_CTYPE"}})
        return {"returncode":p.returncode,"stdout":(p.stdout or "")[-MAX_STDOUT:],"stderr":(p.stderr or "")[-MAX_STDERR:]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"returncode":None,"stdout":"","stderr":str(exc)}
