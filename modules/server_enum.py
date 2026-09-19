#!/usr/bin/env python3
"""Scoped external server enumeration through the registered toolchain."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from .scope import load_scope, filter_in_scope
from .tool_manager_v40 import ToolManager


def _require_scope(target: str, scope_file: str):
    allowed = load_scope(scope_file)
    if not allowed or not filter_in_scope([target], allowed=allowed):
        raise PermissionError("target is not in a valid authorized scope")


def run_server_enum(target: str, output_dir: str, scope_file: str = ""):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    _require_scope(target, scope_file)
    tm = ToolManager(out)
    nmap = ["nmap", "-sV", "-sC", "-Pn", "-T4", "--top-ports", "2000", "--open", "-oA", str(out / "nmap-full"), target]
    nuclei = ["nuclei", "-u", target, "-t", "network/", "-t", "network/detection/", "-severity", "medium,high,critical", "-silent", "-o", str(out / "network-findings.txt")]
    r1 = tm.run("nmap", nmap)
    r2 = tm.run("nuclei", nuclei)
    return {"nmap": r1.returncode, "nuclei": r2.returncode}


def generate_server_checklist(output_dir: str, target: str = ""):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    content = f"""# External Server Testing Checklist\nTarget: {target}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n- [ ] Open ports and service versions reviewed\n- [ ] Unnecessary exposed services identified\n- [ ] Management interfaces reviewed\n- [ ] Database / cache exposure reviewed\n- [ ] SSH/RDP/SMB security posture reviewed\n- [ ] Web services on non-standard ports reviewed\n- [ ] Findings correlated with software/version evidence\n- [ ] Remediation and retest evidence recorded\n"""
    path = out / "external-server-checklist.md"; path.write_text(content, encoding="utf-8"); return str(path)
