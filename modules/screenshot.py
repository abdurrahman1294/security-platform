#!/usr/bin/env python3
"""Scoped screenshot collection through the registered HTTP toolchain."""
from __future__ import annotations
import shutil
from pathlib import Path
from .scope import filter_in_scope, load_scope
from .tool_manager_v40 import ToolManager


def run_screenshots(live_hosts_file: str, output_dir: str, scope_file: str = ""):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    allowed = load_scope(scope_file)
    if not allowed:
        raise PermissionError("scope file is missing or empty")
    src = Path(live_hosts_file)
    if not src.is_file():
        raise FileNotFoundError(live_hosts_file)
    hosts = filter_in_scope([x.strip().split()[0] for x in src.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()], allowed=allowed)
    targets = out / "screenshot-targets.txt"; targets.write_text("\n".join(sorted(set(hosts))) + ("\n" if hosts else ""), encoding="utf-8")
    if not hosts:
        return {"status": "blocked", "reason": "no-in-scope-hosts"}
    result = {"httpx": "not-run", "gowitness": "not-run"}
    try:
        proc = ToolManager(out).run("httpx", ["httpx", "-l", str(targets), "-screenshot", "-screenshot-timeout", "10", "-o", str(out / "httpx-screenshots.txt")])
        result["httpx"] = proc.returncode
    except (OSError, RuntimeError, ValueError) as exc:
        result["httpx"] = f"blocked:{type(exc).__name__}"
    # gowitness is optional and not part of the registered tool boundary; do not
    # execute it automatically. Operators can use the generated target file with
    # their separately managed licensed/approved screenshot workflow.
    if shutil.which("gowitness"):
        result["gowitness"] = "available-but-not-auto-executed"
    return result
