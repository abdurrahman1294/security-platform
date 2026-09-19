#!/usr/bin/env python3
"""Scoped authenticated Nuclei assessment using a temporary header file."""
from __future__ import annotations
import tempfile
from pathlib import Path
from .findings_io import load_findings_file
from .scope import filter_in_scope, load_scope
from .tool_manager_v40 import ToolManager


def run_authenticated_scan(urls_file: str, output_dir: str, auth_type: str = "cookie", auth_value: str = "", scope_file: str = ""):
    if auth_type not in {"cookie", "bearer", "header"}:
        raise ValueError("auth_type must be cookie, bearer, or header")
    if not auth_value:
        return {"status": "skipped", "reason": "no-auth-value"}
    allowed = load_scope(scope_file)
    if not allowed:
        raise PermissionError("scope file is missing or empty")
    src = Path(urls_file)
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    urls = filter_in_scope([x.strip() for x in src.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()], allowed=allowed)
    target_file = out / "authenticated-targets.txt"; target_file.write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""), encoding="utf-8")
    if not urls:
        return {"status": "blocked", "reason": "no-in-scope-targets"}
    header = f"Cookie: {auth_value}" if auth_type == "cookie" else f"Authorization: Bearer {auth_value}" if auth_type == "bearer" else auth_value
    fd, name = tempfile.mkstemp(prefix="auth-header-", suffix=".txt", dir=out); header_file = Path(name)
    header_file.chmod(0o600)
    try:
        with open(fd, "w", encoding="utf-8", closefd=True) as fh: fh.write(header + "\n")
        argv = ["nuclei", "-l", str(target_file), "-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfiguration/", "-t", "exposures/", "-t", "default-logins/", "-severity", "medium,high,critical", "-rate-limit", "100", "-c", "30", "-silent", "-o", str(out / "authenticated-findings.txt"), "-json-export", str(out / "authenticated-findings.json"), "-H", str(header_file)]
        proc = ToolManager(out).run("nuclei", argv)
        return {"status": "completed" if proc.returncode == 0 else "failed", "returncode": proc.returncode, "findings": len(load_findings_file(out / "authenticated-findings.json")) if (out / "authenticated-findings.json").exists() else 0}
    finally:
        try: header_file.unlink(missing_ok=True)
        except OSError: pass
