#!/usr/bin/env python3
"""
Main Launcher for Security Platform v1.8
Provides interactive menu + profile support.
"""

import sys
import subprocess
import os
from getpass import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.menu import main_menu, get_target_info, get_auth_info
from modules.smart_report import generate_executive_summary, prioritize_findings
from modules.ad_command_generator import generate_ad_commands
from modules.ad_advanced import generate_advanced_ad_guide

def run_orchestrator(flags, env=None):
    cmd = [sys.executable, str(Path(__file__).with_name("orchestrator.py"))] + [str(x) for x in flags]
    print(f"\n[+] Executing: {' '.join(cmd)}\n")
    subprocess.run(cmd, env=env, check=False, cwd=str(Path(__file__).parent))

def main():
    profile = main_menu()
    client, target = get_target_info()

    if profile == "web-full":
        run_orchestrator(["-c", client, "-t", target, "--full", "--html-report", "--server-enum", "--chain", "--report-pack", "--dashboard", "--control-center", "--analytics", "--next-investigation", "--assessment"])

    elif profile == "web-api":
        run_orchestrator(["-c", client, "-t", target, "--full", "--api", "--html-report", "--chain", "--report-pack", "--dashboard", "--control-center", "--analytics", "--next-investigation", "--assessment"])

    elif profile == "auth-web":
        cookie, bearer = get_auth_info()
        flags = ["-c", client, "-t", target, "--vuln-only", "--html-report", "--chain", "--report-pack", "--dashboard", "--control-center", "--analytics", "--next-investigation", "--assessment"]
        env = os.environ.copy()
        if cookie:
            env["PENTEST_AUTH_COOKIE"] = cookie
        if bearer:
            env["PENTEST_AUTH_BEARER"] = bearer
        run_orchestrator(flags, env=env)

    elif profile == "server":
        run_orchestrator(["-c", client, "-t", target, "--server-enum", "--ports-only"])

    elif profile == "internal":
        run_orchestrator(["-c", client, "-t", target, "--internal"])

    elif profile == "ad":
        domain = input("Domain (e.g. corp.local): ").strip() or target
        dc_ip = input("DC IP: ").strip() or target
        generate_advanced_ad_guide(f"output/{client}-ad", domain=domain, dc_ip=dc_ip)
        generate_ad_commands(f"output/{client}-ad", domain=domain, dc_ip=dc_ip)
        print("\n[+] AD methodology and command generator created in output/")

    elif profile == "web-adaptive":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--web-engine"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "auth-intelligence":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--auth-engine"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "session-intelligence":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--session-engine"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "web-deep":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--web-assessment"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "api-security":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--api-engine"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "business-logic":
        outdir = input("Existing engagement output folder (leave empty for a new one): ").strip()
        flags = ["-c", client, "-t", target, "--business-logic-engine"]
        if outdir:
            flags += ["--output-dir", outdir]
        run_orchestrator(flags)

    elif profile == "assessment":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--assessment", "--chain", "--dashboard", "--next-investigation"])

    elif profile == "validate":
        finding_id = input("Finding ID (e.g. F-abc123): ").strip()
        mode = input("Validation mode [observe/verify/impact] (default verify): ").strip().lower() or "verify"
        if mode not in {"observe", "verify", "impact"}:
            print("[!] Invalid validation mode.")
        else:
            outdir = input("Existing engagement output folder: ").strip()
            scope = input("Scope file [config/scope.example.txt]: ").strip() or "config/scope.example.txt"
            if finding_id and outdir:
                run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--validate-finding", finding_id, "--validation-mode", mode, "--scope-file", scope])

    elif profile == "investigation":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--advanced-investigation", "--knowledge-base", "--operator-workspace", "--control-center"])

    elif profile == "knowledge":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--knowledge-base", "--operator-workspace"])

    elif profile == "workspace":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--operator-workspace", "--control-center", "--dashboard"])

    elif profile == "lab":
        run_orchestrator(["-c", client, "-t", target, "--lab", "--control-center", "--analytics", "--assessment"])

    elif profile == "report":
        outdir = input("Path to existing output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--chain", "--report-pack", "--html-report", "--assessment"])


    elif profile == "case":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--case-management"])

    elif profile == "risk":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--risk-analytics"])

    elif profile == "workflow":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--workflow-status"])

    elif profile == "data-intelligence":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--normalize-findings", "--finding-dedup", "--remediation-intelligence", "--assessment", "--chain"])

    elif profile == "lifecycle":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--remediation-tracking", "--retest-intelligence", "--closure-readiness", "--report-pack"])

    elif profile == "proof-plan":
        outdir = input("Existing engagement output folder: ").strip()
        if outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--proof-plan"])

    elif profile == "controlled-exploit":
        finding_id = input("Finding ID: ").strip()
        outdir = input("Existing engagement output folder: ").strip()
        scope = input("Scope file [config/scope.example.txt]: ").strip() or "config/scope.example.txt"
        if finding_id and outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--controlled-exploit", finding_id, "--scope-file", scope, "--exploit-evidence", "--assessment-decision"])

    elif profile == "pipeline":
        scope = input("Scope file [config/scope.example.txt]: ").strip() or "config/scope.example.txt"
        run_orchestrator(["-c", client, "-t", target, "--scope-file", scope, "--pipeline-all", "--pipeline-max-tasks", "20"])

    elif profile == "proof-v41":
        action = input("Action [execute/analytics]: ").strip().lower() or "analytics"
        outdir = input("Existing engagement output folder: ").strip()
        if action == "execute":
            finding_id = input("Finding ID: ").strip()
            scope = input("Scope file [config/scope.example.txt]: ").strip() or "config/scope.example.txt"
            if finding_id and outdir:
                run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--proof-execute", finding_id, "--scope-file", scope])
        elif action == "analytics" and outdir:
            run_orchestrator(["-c", client, "-t", target, "--output-dir", outdir, "--proof-analytics"])
        else:
            print("[!] Invalid action.")

    elif profile == "custom":
        print("\nEnter the full orchestrator command arguments (e.g. -c client -t target.com --full):")
        extra = input("→ ").strip()
        run_orchestrator(extra.split())

    print("\n[+] Done. Check the output/ directory.")

if __name__ == "__main__":
    main()
