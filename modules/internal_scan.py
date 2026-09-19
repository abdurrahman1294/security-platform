#!/usr/bin/env python3
"""Scoped internal-network discovery profile."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from .scope import load_scope, filter_in_scope
from .tool_manager_v40 import ToolManager


def run_internal_scan(target: str, output_dir: str, scope_file: str = ""):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    allowed = load_scope(scope_file)
    if not allowed or not filter_in_scope([target], allowed=allowed):
        raise PermissionError("internal target is not in a valid authorized scope")
    tm = ToolManager(out)
    r1 = tm.run("naabu", ["naabu", "-host", target, "-rate", "500", "-top-ports", "1000", "-silent", "-o", str(out / "internal-ports.txt")])
    r2 = tm.run("nmap", ["nmap", "-sV", "-Pn", "-T3", "--top-ports", "1000", "-oA", str(out / "internal-nmap"), target])
    r3 = tm.run("nmap", ["nmap", "-Pn", "-T3", "-p", "445,139,88,389,636,3268,3269,5985,5986,30,22,3389", "--open", "-oA", str(out / "internal-interesting-ports"), target])
    return {"naabu": r1.returncode, "nmap": [r2.returncode, r3.returncode]}


def generate_internal_checklist(output_dir: str):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    content = f"""# Internal Network Testing Checklist\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n- [ ] Live hosts identified\n- [ ] Domain controllers / critical assets identified\n- [ ] Open ports and services mapped\n- [ ] SMB signing / share exposure reviewed\n- [ ] Management interfaces reviewed\n- [ ] Trust and identity relationships documented\n- [ ] Potential lateral-movement paths treated as hypotheses\n- [ ] Evidence and scope recorded for every access path\n"""
    path = out / "internal-network-checklist.md"; path.write_text(content, encoding="utf-8"); return str(path)
