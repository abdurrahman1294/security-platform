#!/usr/bin/env python3
"""Scoped API vulnerability assessment adapter.

Execution is routed through ToolManager; the module only feeds in-scope URLs to
Nuclei and supports an optional temporary header file for authenticated scans.
"""
from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

from .findings_io import load_findings_file
from .scope import filter_in_scope, load_scope
from .security import redact_text
from .tool_manager_v40 import ToolManager


def _scoped_urls(urls_file: str, output_dir: Path, scope_file: str) -> Path:
    if not scope_file:
        raise PermissionError("scope file is required for API scanning")
    allowed = load_scope(scope_file)
    if not allowed:
        raise PermissionError("scope file is missing or empty")
    src = Path(urls_file)
    if not src.is_file():
        raise FileNotFoundError(urls_file)
    urls = [x.strip() for x in src.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    urls = filter_in_scope(urls, allowed=allowed)
    dest = output_dir / "api-targets.txt"
    dest.write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""), encoding="utf-8")
    return dest


def run_api_scan(urls_file: str, output_dir: str, auth_header: str = "", scope_file: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    targets = _scoped_urls(urls_file, out, scope_file)
    if targets.stat().st_size == 0:
        return {"status": "blocked", "reason": "no-in-scope-api-targets"}

    argv = [
        "nuclei", "-l", str(targets),
        "-t", "http/vulnerabilities/", "-t", "http/misconfiguration/", "-t", "http/exposures/",
        "-t", "cves/", "-tags", "api,graphql,jwt,idor,ssrf,authorization",
        "-severity", "medium,high,critical", "-rate-limit", "100", "-silent",
        "-o", str(out / "api-findings.txt"), "-json-export", str(out / "api-findings.json"),
    ]
    header_file = None
    try:
        if auth_header:
            fd, name = tempfile.mkstemp(prefix="api-header-", suffix=".txt", dir=out)
            header_file = Path(name)
            Path(name).chmod(0o600)
            with open(fd, "w", encoding="utf-8", closefd=True) as fh:
                fh.write(redact_text(auth_header) if "[REDACTED]" in auth_header else auth_header)
                fh.write("\n")
            argv += ["-H", str(header_file)]
        proc = ToolManager(out).run("nuclei", argv)
        return {"status": "completed" if proc.returncode == 0 else "failed", "returncode": proc.returncode,
                "findings": len(load_findings_file(out / "api-findings.json")) if (out / "api-findings.json").exists() else 0}
    finally:
        if header_file:
            try:
                header_file.unlink(missing_ok=True)
            except OSError:
                pass


def generate_api_checklist(output_dir: str, target: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    content = f"""# API Security Testing Checklist\nTarget: {target}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n## Authentication & Authorization\n- [ ] Anonymous versus authenticated access\n- [ ] Horizontal authorization (User A versus User B)\n- [ ] Vertical authorization (user versus privileged functions)\n- [ ] Token expiry, rotation and logout invalidation\n- [ ] Object-level and function-level authorization\n\n## Input & Data Handling\n- [ ] Mass assignment / hidden fields\n- [ ] Excessive data exposure\n- [ ] Injection candidates\n- [ ] SSRF candidates\n- [ ] Rate limiting and abuse controls\n\n## GraphQL / API Documentation\n- [ ] Schema exposure and introspection\n- [ ] Mutation authorization\n- [ ] Query depth / batching controls\n\n## Evidence\nRecord endpoint, method, role, expected result, observed result and evidence ID.\n"""
    path = out / "api-security-checklist.md"
    path.write_text(content, encoding="utf-8")
    return str(path)
