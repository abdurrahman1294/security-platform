#!/usr/bin/env python3
"""
Compatibility Pentest Orchestrator — legacy V242 reference runner
----------------------------------
Strengthened coverage for:
- Web Applications & APIs
- External Servers
- Internal Systems
- Active Directory (guidance + safe enum)
"""

import argparse
import sys
import subprocess
import datetime
import json
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

sys.path.insert(0, str(Path(__file__).parent))

from modules.screenshot import run_screenshots
from modules.html_report import generate_html_report
from modules.exploiter import InteractiveExploiter
from modules.auth_scanner import run_authenticated_scan
from modules.session_tester import generate_session_report
from modules.business_logic import generate_business_logic_checklist
from modules.post_exploit import generate_post_exploit_guide
from modules.coverage_report import generate_coverage_report
from modules.api_scanner import run_api_scan, generate_api_checklist
from modules.server_enum import run_server_enum, generate_server_checklist
from modules.internal_scan import run_internal_scan, generate_internal_checklist
from modules.ad_guidance import generate_ad_enum_guide
from modules.scope import validate_target_or_exit, filter_in_scope, is_valid_target_format, load_scope
from modules.security import require_authorization, safe_client_name
from modules.attack_graph import generate_attack_graph
from modules.resume import load_state, save_state
from modules.finding_tracker import generate_status_report
from modules.report_pack import generate_report_pack
from modules.engagement import init_engagement, update_artifacts
from modules.evidence_manager import build_evidence_index
from modules.asset_inventory import build_asset_inventory
from modules.timeline import build_timeline
from modules.next_investigation import recommend as recommend_next
from modules.dashboard import generate_dashboard
from modules.control_center import generate_control_center
from modules.lab_mode import create_lab
from modules.analytics import build_analytics
from modules.controlled_validation import validate as controlled_validate
from modules.assessment_intelligence import build as build_assessment, set_business_impact
from modules.retest import record as record_retest
from modules.technology_intelligence import build as build_technology_intelligence
from modules.correlation_engine import build as build_correlation
from modules.engagement_governance import audit as audit_event, readiness as build_readiness
from modules.investigation_engine_v18 import build as build_investigation_v18
from modules.knowledge_base import build as build_knowledge_base
from modules.operator_workspace import generate as generate_operator_workspace
from modules.case_management import build as build_cases, record as record_case
from modules.risk_analytics_v22 import build as build_risk_analytics
from modules.workflow_v23 import status as workflow_status, advance as workflow_advance
from modules.data_normalization_v24 import build as build_normalization_v24
from modules.finding_dedup_v25 import build as build_dedup_v25
from modules.remediation_intelligence_v26 import build as build_remediation_v26
from modules.remediation_tracking_v27 import build as build_remediation_tracking_v27, set_record as set_remediation_record
from modules.retest_intelligence_v28 import build as build_retest_intelligence_v28
from modules.closure_engine_v29 import build as build_closure_v29
from modules.controlled_exploitation_v30 import run_proof as run_controlled_exploitation_v30
from modules.exploit_evidence_v31 import build as build_exploit_evidence_v31
from modules.exploit_adapters_v33 import REGISTRY, registry_document
from modules.exploit_policy_v34 import DEFAULT_POLICY
from modules.exploit_planner_v35 import build_plan as build_controlled_proof_plan
from modules.residual_risk_v32 import build as build_residual_risk_v32
from modules.assessment_engine_v39 import build_plan as build_mission_plan_v39, load as load_mission_v39, mark as mark_mission_v39
from modules.tool_manager_v40 import ToolManager, TOOLS, list_tools as list_registered_tools_v40
from modules.adaptive_engine_v41 import decide as decide_adaptive_v41
from modules.pipeline_v42 import build_pipeline as build_pipeline_v42
from modules.pipeline_runner_v44 import PipelineRunner
from modules.web_surface_v45 import build as build_web_surface_v45
from modules.web_endpoint_v46 import build as build_web_endpoints_v46
from modules.web_assessment_v47 import build as build_web_assessment_v47
from modules.web_test_matrix_v48 import build as build_web_test_matrix_v48
from modules.web_probe_v49 import run as run_web_probe_v49
from modules.web_decisions_v50 import build as build_web_decisions_v50
from modules.auth_intelligence_v51 import build as build_auth_intelligence_v51
from modules.authorization_matrix_v52 import build as build_authorization_matrix_v52
from modules.authz_decisions_v53 import build as build_authz_decisions_v53
from modules.session_intelligence_v54 import build as build_session_intelligence_v54
from modules.session_observation_v55 import run as run_session_observation_v55
from modules.identity_transitions_v56 import build as build_identity_transitions_v56
from modules.api_schema_v57 import build as build_api_schema_v57
from modules.api_surface_v58 import build as build_api_surface_v58
from modules.api_decisions_v59 import build as build_api_decisions_v59
from modules.workflow_intelligence_v60 import build as build_workflow_intelligence_v60
from modules.workflow_sequences_v61 import build as build_workflow_sequences_v61
from modules.business_logic_v62 import build as build_business_logic_v62
from modules.complete_assessment_v63_v70 import build as build_complete_v63_v70
from modules.production_layer_v211_v225 import build_all as build_production_v211_v225
from modules.deep_excellence_v226_v231 import (v226_exploitation as build_exploitation_excellence_v226, v227_validation_plan as build_validation_excellence_v227, v227_execute as execute_validation_excellence_v227, v228_ad as build_ad_excellence_v228, v229_aws as build_aws_excellence_v229, v230_web_api as build_web_api_excellence_v230, v231_quality as build_deep_quality_v231)
from modules.intelligence_modes_v76 import build as build_intelligence_mode_v76
from modules.security_brain_v77 import build as build_security_brain_v77
from modules.evidence_memory_v78 import build as build_evidence_memory_v78
from modules.task_router_v79 import build as build_task_router_v79
from modules.operator_loop_v80 import build as build_operator_loop_v80
from modules.unified_assessment_v81 import build as build_unified_assessment_v81
from modules.final_intelligence_v82 import build as build_final_intelligence_v82
from modules.ai_reasoning_v83 import build as build_ai_reasoning_v83
from modules.target_profile_v84 import build as build_target_profile_v84
from modules.web_intelligence_v85 import build as build_web_intelligence_v85
from modules.osint_collection_v86 import build as build_osint_collection_v86
from modules.cross_engagement_memory_v87 import build as build_cross_engagement_memory_v87
from modules.bounty_prioritization_v88 import build as build_bounty_prioritization_v88
from modules.reporting_monitoring_v89 import build as build_reporting_monitoring_v89
from modules.security_training_v90 import build as build_security_training_v90
from modules.master_operator_v91 import build as build_master_operator_v91
from modules.capability_registry_v92 import build as build_capability_registry_v92
from modules.self_verification_v93 import build as build_self_verification_v93
from modules.security_knowledge_graph_v94 import build as build_security_knowledge_graph_v94
from modules.hypothesis_engine_v95 import build as build_hypothesis_engine_v95
from modules.experiment_planner_v96 import build as build_experiment_planner_v96
from modules.capability_reliability_v97 import build as build_capability_reliability_v97
from modules.plugin_architecture_v98 import build as build_plugin_architecture_v98
from modules.operator_dashboard_v99 import build as build_operator_dashboard_v99
from modules.integrated_toolchain_v100 import IntegratedToolchain
from modules.execution_orchestrator_v101 import ExecutionOrchestrator, build_plan as build_execution_plan_v101
from modules.normalization_v102 import build as build_normalization_v102
from modules.qa_verification_v103 import build as build_qa_v103
from modules.smart_tool_selection_v104 import build as build_smart_tools_v104
from modules.role_testing_v105 import build as build_role_testing_v105
from modules.api_intelligence_v106 import build as build_api_intelligence_v106
from modules.correlation_v107 import build as build_correlation_v107
from modules.change_detection_v108 import build as build_change_detection_v108
from modules.evidence_vault_v109 import build as build_evidence_vault_v109
from modules.quality_gate_v110 import build as build_quality_gate_v110
from modules.excellence_v111_v145 import build_all as build_excellence_v111_v145
from modules.osint_engine_v146_v159 import build_osint_engine as build_osint_engine_v146_v159
from modules.tool_catalog_v160 import build as build_tool_catalog_v160
from modules.hardening_v161_v175 import build_hardening as build_hardening_v161_v175, build_osint_source_registry as build_osint_source_registry_v161
from modules.security_hardening_v163_v170 import build_security_audit as build_security_audit_v163, build_runtime_policy as build_runtime_policy_v164
from modules.osint_quality_v165_v170 import build_osint_quality as build_osint_quality_v165

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def log(msg, level="info"):
    prefix = {
        "info": f"{Colors.CYAN}[*]{Colors.RESET}",
        "success": f"{Colors.GREEN}[+]{Colors.RESET}",
        "warn": f"{Colors.YELLOW}[!]{Colors.RESET}",
        "error": f"{Colors.RED}[-]{Colors.RESET}",
        "header": f"{Colors.BOLD}{Colors.CYAN}",
    }.get(level, "[*]")
    if level == "header":
        print(f"\n{prefix}{msg}{Colors.RESET}")
    else:
        print(f"{prefix} {msg}")

def run_cmd(cmd, timeout=3600, root=None):
    """Run a registered assessment tool through the central execution boundary."""
    if isinstance(cmd, str) or not isinstance(cmd, (list, tuple)):
        raise TypeError("run_cmd() requires an argv list; shell commands are not supported")
    if not cmd:
        raise ValueError("run_cmd() requires a non-empty argv list")
    tool_id = str(cmd[0])
    if tool_id not in TOOLS:
        raise ValueError(f"Unregistered assessment tool: {tool_id}")
    if root is None:
        raise ValueError("run_cmd() requires the engagement root")
    log(f"Running registered tool: {' '.join(map(str, cmd))}")
    try:
        from modules.tool_manager_v40 import ToolManager
        result = ToolManager(root).run(tool_id, list(map(str, cmd)), timeout=timeout)
        if result.returncode != 0 and result.stderr:
            log(f"Command warning (exit {result.returncode}): {result.stderr[:300]}", "warn")
        return result.returncode == 0
    except (OSError, RuntimeError, ValueError) as exc:
        log(f"Tool execution blocked/error: {exc}", "error")
        return False

def create_dirs(base: Path):
    base.mkdir(parents=True, exist_ok=True)
    try:
        base.chmod(0o700)
    except OSError:
        pass
    for sub in ["recon", "ports", "web", "vulns", "logs", "evidence", "screenshots", "reports", "api", "servers", "internal", "ad"]:
        path = base / sub
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError:
            pass

def recon(target, outdir, allowed_scope):
    log("PHASE 1: Reconnaissance", "header")
    recon_dir = outdir / "recon"
    run_cmd(["subfinder", "-d", target, "-all", "-silent", "-o", str(recon_dir / "subfinder.txt")], root=outdir)
    # Assetfinder is routed through the same registered-tool boundary.
    try:
        from modules.tool_manager_v40 import ToolManager
        proc = ToolManager(outdir).run("assetfinder", ["assetfinder", "--subs-only", target], timeout=600)
        (recon_dir / "assetfinder.txt").write_text(proc.stdout or "", encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as exc:
        log(f"assetfinder error: {exc}", "error")
    # Merge subdomain results safely
    try:
        subs = set()
        for f in recon_dir.glob("*.txt"):
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip().lstrip("*.")
                if line:
                    subs.add(line)
        in_scope_subs = filter_in_scope(sorted(subs), allowed=allowed_scope)
        (recon_dir / "subdomains.txt").write_text("\n".join(in_scope_subs) + ("\n" if in_scope_subs else ""))
    except Exception as e:
        log(f"subdomain merge error: {e}", "error")
    run_cmd(["httpx", "-l", str(recon_dir / "subdomains.txt"), "-silent", "-status-code", "-title",
             "-tech-detect", "-o", str(recon_dir / "live-hosts.txt")], root=outdir)
    log("Recon complete", "success")

def portscan(target, outdir):
    log("PHASE 2: Port Scanning", "header")
    ports_dir = outdir / "ports"
    run_cmd(["naabu", "-host", target, "-rate", "3000", "-top-ports", "1000", "-silent", "-o", str(ports_dir / "naabu.txt")], root=outdir)
    naabu_file = ports_dir / "naabu.txt"
    if naabu_file.exists() and naabu_file.stat().st_size > 0:
        run_cmd(["nmap", "-sV", "-sC", "-Pn", "-iL", str(naabu_file), "--open", "-oA", str(ports_dir / "nmap-detailed")], root=outdir)
    else:
        run_cmd(["nmap", "-sV", "-sC", "-Pn", "-T4", "--top-ports", "1000", target, "--open", "-oA", str(ports_dir / "nmap-top")], root=outdir)
    log("Port scan complete", "success")

def web_enum(outdir):
    log("PHASE 3: Web Enumeration", "header")
    web_dir = outdir / "web"
    live = outdir / "recon" / "live-hosts.txt"
    if not live.exists() or live.stat().st_size == 0:
        log("No live hosts found", "warn")
        return
    try:
        urls = set()
        for line in live.read_text(errors="ignore").splitlines():
            part = line.strip().split()[0] if line.strip() else ""
            if part:
                urls.add(part)
        (web_dir / "urls.txt").write_text("\n".join(sorted(urls)) + "\n")
    except Exception as e:
        log(f"URL extract error: {e}", "error")
    run_cmd(["katana", "-list", str(web_dir / "urls.txt"), "-d", "2", "-silent", "-o", str(web_dir / "katana.txt")], root=outdir)
    run_cmd(["nuclei", "-l", str(web_dir / "urls.txt"), "-t", "technologies/", "-t", "exposures/", "-silent", "-o", str(web_dir / "tech-exposures.txt")], root=outdir)
    log("Web enumeration complete", "success")

def vuln_scan(outdir, retain_raw_evidence=False):
    log("PHASE 4: Vulnerability Scanning", "header")
    vulns_dir = outdir / "vulns"
    urls = outdir / "web" / "urls.txt"
    live = outdir / "recon" / "live-hosts.txt"
    target_file = urls if urls.exists() and urls.stat().st_size > 0 else live
    if not target_file.exists():
        log("No targets for vuln scan", "warn")
        return
    cmd = ["nuclei", "-l", str(target_file),
           "-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfiguration/",
           "-t", "exposures/", "-t", "default-logins/",
           "-severity", "medium,high,critical",
           "-rate-limit", "150", "-c", "40", "-silent", "-stats"]
    if retain_raw_evidence:
        cmd.append("-include-rr")
    cmd += ["-o", str(vulns_dir / "findings.txt"),
            "-json-export", str(vulns_dir / "findings.json")]
    run_cmd(cmd, root=outdir)
    log("Vulnerability scan complete", "success")

def load_config(config_path):
    if yaml is None:
        print("[!] PyYAML not installed. Run: pip install pyyaml")
        sys.exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f) or {}

def main():
    parser = argparse.ArgumentParser(description="Pentest Automation Orchestrator v240 — Complete Authorized Assessment Platform")
    parser.add_argument("--config", help="Path to engagement YAML config")
    parser.add_argument("-c", "--client", help="Client name")
    parser.add_argument("-t", "--target", help="Target domain / IP / CIDR")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--complete-assessment", action="store_true", help="V63-V70: run the integrated end-to-end assessment and intelligence stack")
    parser.add_argument("--intelligence-mode", choices=["pentest","bugbounty","osint","auto"], help="V76: unified operating mode")
    parser.add_argument("--operator", action="store_true", help="V77-V82: run the unified security operator brain")
    parser.add_argument("--operator-execute", action="store_true", help="V80+: prepare bounded execution; consequential actions still require approval")
    parser.add_argument("--integrated-mission", action="store_true", help="V92-V110: run the real integrated toolchain plus reliability, intelligence and quality gates")
    parser.add_argument("--v101-v110", action="store_true", help="V101-V110: build execution/reliability/intelligence artifacts from an existing engagement")
    parser.add_argument("--baseline-change", action="store_true", help="V108: save the current artifact snapshot as the change-detection baseline")
    parser.add_argument("--osint-collect", action="store_true", help="V86: collect from passive public sources (opt-in)")
    parser.add_argument("--training", action="store_true", help="V90: build a safe cybersecurity learning/lab plan")
    parser.add_argument("--bug-bounty", action="store_true", help="V71-V73: run scope-first bug bounty intelligence and triage")
    parser.add_argument("--osint", action="store_true", help="V74-V75: run passive public-source OSINT intelligence")
    parser.add_argument("--osint-objective", default="general", help="OSINT research objective")
    parser.add_argument("--osint-input", action="append", default=[], help="Existing OSINT tool output file to ingest; repeat for multiple tools")
    parser.add_argument("--tool-catalog", action="store_true", help="V160: build the assessment tool catalog")
    parser.add_argument("--program-policy", default="", help="Bug bounty policy JSON file")
    parser.add_argument("--program-name", default="", help="Bug bounty program name")
    parser.add_argument("--bounty-assets", action="append", default=[], help="Additional in-scope bounty asset; repeat as needed")
    parser.add_argument("--bounty-execute", action="store_true", help="Run the authorized active assessment using the supplied bounty policy as scope")
    parser.add_argument("--recon-only", action="store_true")
    parser.add_argument("--ports-only", action="store_true")
    parser.add_argument("--web-only", action="store_true")
    parser.add_argument("--vuln-only", action="store_true")
    parser.add_argument("--exploit", action="store_true")
    parser.add_argument("--html-report", action="store_true")
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--retain-raw-evidence", action="store_true", help="Retain raw HTTP request/response evidence; may contain secrets/PII")
    parser.add_argument("--app-type", default=None, choices=["general", "ecommerce", "saas", "banking"])
    parser.add_argument("--post-exploit", choices=["shell", "web-admin", "rce", "database"], default="")
    parser.add_argument("--os-type", default=None, choices=["linux", "windows"])
    parser.add_argument("--internal", action="store_true", help="Internal network mode")
    parser.add_argument("--api", action="store_true", help="Run API-focused scanning + checklist")
    parser.add_argument("--server-enum", action="store_true", help="Strengthened external server enumeration")
    parser.add_argument("--ad-guide", action="store_true", help="Generate Active Directory guidance")
    parser.add_argument("--domain", default="", help="Domain name for AD guidance")
    parser.add_argument("--chain", action="store_true", help="Build evidence-aware attack hypothesis graph")
    parser.add_argument("--report-pack", action="store_true", help="Generate the professional report pack")
    parser.add_argument("--resume", action="store_true", help="Resume phases recorded in the engagement state file")
    parser.add_argument("--output-dir", default="", help="Existing engagement output directory for --resume/--chain/report-pack")
    parser.add_argument("--dashboard", action="store_true", help="Generate the local engagement dashboard")
    parser.add_argument("--next-investigation", action="store_true", help="Generate prioritized human investigation recommendations")
    parser.add_argument("--assessment", action="store_true", help="Generate assessment intelligence and validation queue")
    parser.add_argument("--control-center", action="store_true")
    parser.add_argument("--lab", action="store_true", help="Create a synthetic local lab; no real target testing")
    parser.add_argument("--analytics", action="store_true")
    parser.add_argument("--technology-intelligence", action="store_true", help="Build artifact-derived technology intelligence")
    parser.add_argument("--correlation", action="store_true", help="Build normalized finding correlation hypotheses")
    parser.add_argument("--governance", action="store_true", help="Run engagement readiness and audit governance")
    parser.add_argument("--advanced-investigation", action="store_true", help="Build V18 investigation priorities")
    parser.add_argument("--knowledge-base", action="store_true", help="Build V19 engagement knowledge base")
    parser.add_argument("--operator-workspace", action="store_true", help="Build V20 operator workspace")
    parser.add_argument("--case-management", action="store_true", help="Build V21 evidence/case management")
    parser.add_argument("--case-finding", metavar="FINDING_ID", help="Add a controlled analyst case action for a finding")
    parser.add_argument("--case-action", choices=["note","decision","status","evidence-link"], default="note")
    parser.add_argument("--case-text", default="")
    parser.add_argument("--case-evidence", action="append", default=[])
    parser.add_argument("--risk-analytics", action="store_true", help="Build V22 risk and attack-path analytics")
    parser.add_argument("--workflow-status", action="store_true", help="Show V23 engagement lifecycle status")
    parser.add_argument("--workflow-advance", action="store_true", help="Advance V23 lifecycle after gate checks and explicit approval")
    parser.add_argument("--normalize-findings", action="store_true", help="V24: normalize heterogeneous finding artifacts")
    parser.add_argument("--finding-dedup", action="store_true", help="V25: build duplicate hypotheses and finding history")
    parser.add_argument("--remediation-intelligence", action="store_true", help="V26: build remediation and retest guidance")
    parser.add_argument("--remediation-tracking", action="store_true", help="V27: build remediation tracking")
    parser.add_argument("--set-remediation", metavar="FINDING_ID", help="Record remediation tracking metadata for a finding")
    parser.add_argument("--remediation-status", choices=["open","in-progress","blocked","ready-for-retest","closed"], default="open")
    parser.add_argument("--remediation-owner", default="")
    parser.add_argument("--remediation-priority", choices=["critical","high","medium","low"], default="medium")
    parser.add_argument("--remediation-due", default="")
    parser.add_argument("--remediation-note", default="")
    parser.add_argument("--retest-intelligence", action="store_true", help="V28: compare recorded retest and remediation state")
    parser.add_argument("--closure-readiness", action="store_true", help="V29: evaluate engagement closure readiness")
    parser.add_argument("--controlled-exploit", metavar="FINDING_ID", help="V30: run bounded, non-destructive proof for one finding")
    parser.add_argument("--exploit-evidence", action="store_true", help="V31: build sanitized exploit evidence ledger")
    parser.add_argument("--assessment-decision", action="store_true", help="V32: compute residual-risk assessment posture")
    parser.add_argument("--proof-plan", action="store_true", help="V35: build operator-reviewed controlled proof plan")
    parser.add_argument("--list-proof-adapters", action="store_true", help="V33: list installed safe proof adapters")
    parser.add_argument("--proof-execute", metavar="FINDING_ID", help="V37: execute one guarded, approved proof adapter")
    parser.add_argument("--proof-analytics", action="store_true", help="V38: build proof coverage and outcome analytics")
    parser.add_argument("--mission", action="store_true", help="V39-V41: run the unified authorized assessment mission")
    parser.add_argument("--mission-plan", action="store_true", help="V39: create/update the durable mission plan")
    parser.add_argument("--mission-status", action="store_true", help="V39: show durable mission state")
    parser.add_argument("--tool-inventory", action="store_true", help="V40: list registered external assessment tools")
    parser.add_argument("--adaptive-decisions", action="store_true", help="V41: generate next-action decisions from engagement evidence")
    parser.add_argument("--pipeline-plan", action="store_true", help="V42: build unified assessment pipeline")
    parser.add_argument("--pipeline-run", action="store_true", help="V44: execute the next dependency-ready pipeline task")
    parser.add_argument("--pipeline-all", action="store_true", help="V44: execute dependency-ready pipeline tasks until completion or limit")
    parser.add_argument("--pipeline-max-tasks", type=int, default=20, help="V44: maximum pipeline tasks in one run")
    parser.add_argument("--web-surface", action="store_true", help="V45: build structured web/API attack-surface model from existing artifacts")
    parser.add_argument("--web-endpoints", action="store_true", help="V46: build endpoint, parameter, authentication and business-logic intelligence")
    parser.add_argument("--web-assessment-plan", action="store_true", help="V47: build prioritized operator-reviewed web/API assessment plan")
    parser.add_argument("--web-assessment", action="store_true", help="V45-V47: build the complete deep web/API assessment intelligence stack")
    parser.add_argument("--web-test-matrix", action="store_true", help="V48: build a deterministic web/API test matrix")
    parser.add_argument("--web-probe", action="store_true", help="V49: execute bounded, scope-checked HTTP observations")
    parser.add_argument("--web-decisions", action="store_true", help="V50: generate adaptive web/API decision support")
    parser.add_argument("--web-engine", action="store_true", help="V48-V50: build matrix, run approved bounded observations, and generate decisions")
    parser.add_argument("--auth-intelligence", action="store_true", help="V51: map authentication surfaces and trust boundaries without collecting secrets")
    parser.add_argument("--authorization-matrix", action="store_true", help="V52: build operator-reviewed authorization comparison matrix")
    parser.add_argument("--authz-decisions", action="store_true", help="V53: generate authentication/authorization decision support")
    parser.add_argument("--auth-engine", action="store_true", help="V51-V53: build auth intelligence, authorization matrix, and decisions")
    parser.add_argument("--session-intelligence", action="store_true", help="V54: model session lifecycle and identity transitions without collecting secrets")
    parser.add_argument("--session-observe", action="store_true", help="V55: run bounded approved GET observations of session-related surfaces")
    parser.add_argument("--identity-transitions", action="store_true", help="V56: generate identity/session transition decision support")
    parser.add_argument("--session-engine", action="store_true", help="V54-V56: build session intelligence, optional bounded observations, and transition decisions")
    parser.add_argument("--api-schema", action="store_true", help="V57: build API/OpenAPI schema candidate intelligence")
    parser.add_argument("--api-surface", action="store_true", help="V58: model API methods, parameters and authorization candidates")
    parser.add_argument("--api-decisions", action="store_true", help="V59: generate adaptive API testing decision support")
    parser.add_argument("--api-engine", action="store_true", help="V57-V59: build API schema, surface and decision intelligence")
    parser.add_argument("--workflow-intelligence", action="store_true", help="V60: build business workflow/state model")
    parser.add_argument("--workflow-sequences", action="store_true", help="V61: build non-executing workflow sequence hypotheses")
    parser.add_argument("--business-logic-decisions", action="store_true", help="V62: prioritize business-logic review decisions")
    parser.add_argument("--business-logic-engine", action="store_true", help="V60-V62: build workflow intelligence, sequence hypotheses and business-logic decisions")
    parser.add_argument("--set-business-impact", metavar="FINDING_ID", help="Record business context for a finding (metadata only)")
    parser.add_argument("--asset-importance", choices=["critical","high","medium","low"], default="low")
    parser.add_argument("--data-sensitivity", choices=["critical","confidential","internal","public","unknown"], default="unknown")
    parser.add_argument("--business-function", default="")
    parser.add_argument("--impact-note", default="")
    parser.add_argument("--retest-finding", metavar="FINDING_ID", help="Record a manual remediation retest result")
    parser.add_argument("--retest-result", choices=["fixed","partially-fixed","still-present","inconclusive"], default="inconclusive")
    parser.add_argument("--retest-note", default="")
    parser.add_argument("--retest-evidence", action="append", default=[], help="Evidence ID/path to associate with manual retest")
    parser.add_argument("--validate-finding", metavar="FINDING_ID", help="Run controlled, non-destructive validation for one finding")
    parser.add_argument("--validation-mode", choices=["observe", "verify", "impact"], default="verify", help="CVM mode; impact is documentation-only")
    parser.add_argument("--scope-file", default="", help="Engagement scope allowlist (overrides config scope_file)")
    parser.add_argument("--excellence-pretest", action="store_true", help="Build V171-V190 post-test roadmap/excellence readiness stack")
    parser.add_argument("--production-pretest", action="store_true", help="Build V211-V225 production/reality readiness stack")
    parser.add_argument("--deep-excellence", action="store_true", help="Build V226-V231 deep exploitation/validation/AD/AWS/Web quality stack")
    parser.add_argument("--exploitation-intelligence", action="store_true", help="V226: build evidence-driven safe proof eligibility")
    parser.add_argument("--validation-excellence", action="store_true", help="V227: build finding-aware validation plan")
    parser.add_argument("--ad-assessment", action="store_true", help="V228: build read-only AD assessment plan")
    parser.add_argument("--ad-execute", action="store_true", help="V228: execute approved read-only AD enumeration using NXC_USER/NXC_PASSWORD")
    parser.add_argument("--aws-assessment", action="store_true", help="V229: build read-only AWS assessment plan")
    parser.add_argument("--aws-execute", action="store_true", help="V229: execute approved read-only AWS inventory for an allowlisted account")
    parser.add_argument("--aws-account-id", default="", help="V229: AWS account ID; must also be in AWS_ALLOWED_ACCOUNT_IDS for execution")
    parser.add_argument("--final-excellence", action="store_true", help="V241-V242: run research-exhaustion and final reality/readiness gates")
    parser.add_argument("--research-exhaustion", action="store_true", help="V241: build a bounded evidence-driven research exhaustion queue")
    parser.add_argument("--final-readiness", action="store_true", help="V242: build the final execution/evidence readiness gate")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    client = args.client or config.get("client")
    target = args.target or config.get("target")
    if not client or not target:
        parser.error("Client and target are required")

    # Merge options
    complete_requested = bool(args.complete_assessment or args.final_excellence or config.get("complete_assessment", False))
    full = args.full or complete_requested or config.get("full", False)
    exploit = args.exploit or config.get("exploit", False)
    html_report = args.html_report or config.get("html_report", False)
    screenshots = args.screenshots or config.get("screenshots", False)
    retain_raw_evidence = args.retain_raw_evidence or config.get("retain_raw_evidence", False)
    # Secrets come from the environment only; do not expose them in argv/process listings.
    auth_cookie = os.environ.get("PENTEST_AUTH_COOKIE", "")
    auth_bearer = os.environ.get("PENTEST_AUTH_BEARER", "")
    jwt = os.environ.get("PENTEST_JWT", "")
    app_type = args.app_type or config.get("app_type", "general")
    post_exploit = args.post_exploit or config.get("post_exploit") or ""
    os_type = args.os_type or config.get("os_type", "linux")
    internal = args.internal or config.get("internal", False)
    chain = args.chain or config.get("chain", False)
    report_pack = args.report_pack or config.get("report_pack", False)
    dashboard = args.dashboard or config.get("dashboard", False)
    next_investigation = args.next_investigation or config.get("next_investigation", False)
    assessment = args.assessment or config.get("assessment", False)
    control_center = args.control_center or config.get("control_center", False)
    analytics = args.analytics or config.get("analytics", False)
    technology_intelligence = args.technology_intelligence or config.get("technology_intelligence", False)
    correlation = args.correlation or config.get("correlation", False)
    governance = args.governance or config.get("governance", False)
    advanced_investigation = args.advanced_investigation or config.get("advanced_investigation", False)
    knowledge_base = args.knowledge_base or config.get("knowledge_base", False)
    operator_workspace = args.operator_workspace or config.get("operator_workspace", False)
    metadata_requested = bool(args.set_business_impact or args.retest_finding or args.lab or args.case_finding or args.workflow_status or args.workflow_advance)
    controlled_validation = bool(args.validate_finding)
    case_requested = bool(args.case_finding)
    workflow_requested = bool(args.workflow_status or args.workflow_advance)
    v24_requested = bool(args.normalize_findings)
    v25_requested = bool(args.finding_dedup)
    v26_requested = bool(args.remediation_intelligence)
    v27_requested = bool(args.remediation_tracking or args.set_remediation)
    v28_requested = bool(args.retest_intelligence)
    v29_requested = bool(args.closure_readiness)
    v30_requested = bool(args.controlled_exploit)
    v31_requested = bool(args.exploit_evidence)
    v32_requested = bool(args.assessment_decision)
    v33_requested = bool(args.list_proof_adapters)
    v35_requested = bool(args.proof_plan)
    v37_requested = bool(args.proof_execute)
    v38_requested = bool(args.proof_analytics)
    v39_requested = bool(args.mission or args.mission_plan or args.mission_status)
    v40_requested = bool(args.tool_inventory)
    v41_requested = bool(args.adaptive_decisions)
    v42_requested = bool(args.pipeline_plan or args.pipeline_run or args.pipeline_all)
    v45_requested = bool(args.web_surface or args.web_endpoints or args.web_assessment_plan or args.web_assessment)
    v48_requested = bool(args.web_test_matrix or args.web_probe or args.web_decisions or args.web_engine)
    v51_requested = bool(args.auth_intelligence or args.authorization_matrix or args.authz_decisions or args.auth_engine)
    v54_requested = bool(args.session_intelligence or args.session_observe or args.identity_transitions or args.session_engine)
    v57_requested = bool(args.api_schema or args.api_surface or args.api_decisions or args.api_engine)
    v60_requested = bool(args.workflow_intelligence or args.workflow_sequences or args.business_logic_decisions or args.business_logic_engine)
    v76_mode = args.intelligence_mode or ("auto" if (args.bug_bounty and args.osint) else "bugbounty" if args.bug_bounty else "osint" if args.osint else "")
    if args.bounty_execute and not args.bug_bounty:
        parser.error("--bounty-execute requires --bug-bounty")
    if args.bounty_execute:
        full = True
    v76_requested = bool(v76_mode)
    v101_requested = bool(args.v101_v110 or args.baseline_change)
    v241_requested = bool(args.research_exhaustion or args.final_excellence or args.final_readiness)
    operator_requested = bool(args.operator or args.operator_execute)
    if operator_requested and v76_mode in ("pentest", "auto"):
        complete_requested = True
        full = True

    client = safe_client_name(client)
    date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.output_dir:
        outdir = Path(args.output_dir).resolve()
        if not outdir.exists() and (args.resume or args.chain or args.report_pack):
            parser.error("--output-dir does not exist")
    else:
        outdir = Path("output") / f"{client}-{date}"
    create_dirs(outdir)

    # Hard scope + format validation only applies to active testing. Report/correlation
    # workflows can operate on an existing engagement directory without re-targeting it.
    scope_file = args.scope_file or config.get("scope_file") or "config/scope.example.txt"
    if args.bounty_execute:
        if not args.program_policy or not Path(args.program_policy).is_file():
            parser.error("--bounty-execute requires --program-policy with an explicit in-scope asset list")
        try:
            with open(args.program_policy, encoding="utf-8") as fh:
                bounty_policy_data = json.load(fh)
            policy_scope = [str(x).strip() for x in bounty_policy_data.get("scope", []) if str(x).strip()]
            policy_scope.extend(str(x).strip() for x in args.bounty_assets if str(x).strip())
            if target and target not in policy_scope:
                policy_scope.append(target)
            policy_scope = sorted(set(policy_scope))
            if not policy_scope:
                parser.error("Bug-bounty policy contains no in-scope assets; refusing active execution")
            bounty_scope_path = outdir / "bounty-policy-scope.txt"
            bounty_scope_path.write_text("\n".join(policy_scope) + "\n", encoding="utf-8")
            scope_file = str(bounty_scope_path)
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError) as exc:
            parser.error(f"Could not load bounty policy scope: {exc}")
    active_requested = any([full, args.recon_only, args.ports_only, args.web_only, args.vuln_only, args.internal,
                            args.api, args.server_enum, bool(auth_cookie), bool(auth_bearer), screenshots, exploit, args.mission, args.pipeline_run, args.pipeline_all, args.web_probe, args.web_engine, args.auth_engine, args.session_observe, args.session_engine, args.api_schema, args.api_surface, args.api_decisions, args.api_engine, args.workflow_intelligence, args.workflow_sequences, args.business_logic_decisions, args.business_logic_engine, args.bounty_execute, args.integrated_mission, v101_requested, (operator_requested and v76_mode in ("pentest", "auto"))])
    deep_active_requested = bool(args.ad_execute or args.aws_execute)
    validation_requested = controlled_validation or v30_requested or v37_requested or deep_active_requested
    allowed_scope = []
    if active_requested or validation_requested:
        if not Path(scope_file).exists():
            validate_target_or_exit(target, scope_file)
        validate_target_or_exit(target, scope_file)
        allowed_scope = load_scope(scope_file)

    log(f"Client  : {client}")
    log(f"Target  : {target}")
    log(f"Output  : {outdir}")
    log("Written authorization is required; active testing is gated below.", "warn")
    init_engagement(outdir, client, target, scope_file)
    audit_event(outdir, "engagement_initialized", {"client": client, "target": target})

    if args.list_proof_adapters:
        print("\nCONTROLLED PROOF ADAPTERS (V33)")
        for spec in REGISTRY.list():
            print(f"- {spec['adapter_id']}: kinds={spec['finding_kinds']} surfaces={spec['surfaces']}")
        registry_document(outdir / "evidence" / "proof-adapters.json")
        update_artifacts(outdir)
        return

    if args.tool_inventory:
        log("PHASE: Tool Registry (V40)", "header")
        for item in list_registered_tools_v40(): print(f"- {item['tool_id']}: {item['description']} ({item['executable']})")
        update_artifacts(outdir); return

    if args.mission_plan:
        log("PHASE: Mission Planning (V39)", "header")
        p=build_mission_plan_v39(outdir, full=True, include_internal=args.internal, include_ad=bool(args.ad_guide or args.domain))
        log(f"Mission plan → {p}", "success"); update_artifacts(outdir); return

    if args.mission_status:
        log("PHASE: Mission Status (V39)", "header")
        data=load_mission_v39(outdir)
        for t in data.get("tasks",[]): print(f"[{t.get('status','pending'):9}] {t.get('action')} — {t.get('reason','')}")
        update_artifacts(outdir); return

    if args.adaptive_decisions:
        log("PHASE: Adaptive Assessment Decisions (V41)", "header")
        ep,rp=decide_adaptive_v41(outdir); log(f"Decisions → {ep}", "success"); log(f"Report → {rp}", "success"); update_artifacts(outdir); return

    if args.pipeline_plan:
        log("PHASE: Unified Assessment Pipeline (V42)", "header")
        ep,rp=build_pipeline_v42(outdir,target,scope_file=scope_file,profile="full")
        log(f"Pipeline → {ep}", "success"); log(f"Report → {rp}", "success"); update_artifacts(outdir); return

    if args.pipeline_run or args.pipeline_all:
        log("PHASE: Unified Assessment Pipeline Execution (V44)", "header")
        print("Pipeline execution is limited to registered tools and the validated engagement scope.")
        approval=input("Approve pipeline execution? Type YES to continue: ").strip()=="YES"
        if not approval:
            log("Pipeline execution cancelled by operator.","warn"); return
        runner=PipelineRunner(outdir,target,scope_file=scope_file,profile="full")
        if args.pipeline_all:
            rows=runner.run_all(max(1,args.pipeline_max_tasks))
            for row in rows: log(f"Completed: {row['action']} → {row['result']}","success")
            if not rows: log("No dependency-ready pipeline task remains.","info")
        else:
            task,path=runner.run_next()
            if task: log(f"Completed: {task['action']} → {path}","success")
            else: log("No dependency-ready pipeline task remains.","info")
        update_artifacts(outdir); return

    if args.integrated_mission:
        log("PHASE: REAL INTEGRATED SECURITY OPERATOR (V92–V110)", "header")
        print("Only registered tools will execute against the validated target and scope. Missing tools are recorded, never fabricated.")
        approval=input("Approve integrated mission execution? Type YES to continue: ").strip()=="YES"
        if not approval:
            log("Integrated mission cancelled by operator.", "warn"); return
        require_authorization()
        build_execution_plan_v101(outdir, target)
        chain=ExecutionOrchestrator(outdir,target,scope_file,resume=True)
        ep,_=chain.run(); log(f"V101 execution state → {ep}", "success")
        # V92–V100 capability, verification, graph, planning, plugin and dashboard layers.
        build_capability_registry_v92(outdir); build_self_verification_v93(outdir); build_security_knowledge_graph_v94(outdir,target)
        build_hypothesis_engine_v95(outdir); build_experiment_planner_v96(outdir); build_capability_reliability_v97(outdir)
        build_plugin_architecture_v98(outdir); build_operator_dashboard_v99(outdir,target)
        # V101–V110 reliability and quality stack.
        build_normalization_v102(outdir); build_qa_v103(outdir); build_smart_tools_v104(outdir,target); build_role_testing_v105(outdir)
        build_api_intelligence_v106(outdir); build_correlation_v107(outdir); build_change_detection_v108(outdir,save_baseline=False)
        build_evidence_vault_v109(outdir); qpath,qdata=build_quality_gate_v110(outdir,target,scope_file); build_excellence_v111_v145(outdir,target,scope_file); build_osint_engine_v146_v159(outdir,target,"integrated assessment",collect=False); build_tool_catalog_v160(outdir); build_hardening_v161_v175(outdir,target); build_osint_source_registry_v161(outdir); build_security_audit_v163(outdir); build_runtime_policy_v164(outdir); build_osint_quality_v165(outdir)
        log(f"V110 quality gate → {qpath} [{qdata['decision']}]", "success" if qdata['decision']=="READY" else "warn")
        # Rebuild the complete evidence-driven intelligence stack over the newly collected artifacts.
        build_normalization_v24(outdir); build_dedup_v25(outdir); build_correlation(outdir); build_assessment(outdir); build_investigation_v18(outdir)
        build_knowledge_base(outdir); build_risk_analytics(outdir); build_remediation_v26(outdir); build_retest_intelligence_v28(outdir); build_closure_v29(outdir)
        build_target_profile_v84(outdir,target); build_web_surface_v45(outdir,target); build_web_endpoints_v46(outdir); build_web_assessment_v47(outdir); build_web_intelligence_v85(outdir,target)
        build_api_schema_v57(outdir); build_api_surface_v58(outdir); build_api_decisions_v59(outdir); build_auth_intelligence_v51(outdir); build_authorization_matrix_v52(outdir); build_authz_decisions_v53(outdir)
        build_session_intelligence_v54(outdir); build_identity_transitions_v56(outdir); build_workflow_intelligence_v60(outdir); build_workflow_sequences_v61(outdir); build_business_logic_v62(outdir)
        build_unified_assessment_v81(outdir,"pentest",target); build_final_intelligence_v82(outdir,"pentest",target); build_ai_reasoning_v83(outdir,"pentest",target); build_master_operator_v91(outdir,"pentest",target)
        build_change_detection_v108(outdir,save_baseline=args.baseline_change); build_evidence_vault_v109(outdir); qpath,qdata=build_quality_gate_v110(outdir,target,scope_file)
        update_artifacts(outdir); log("Integrated mission completed. Review the V110 quality gate and evidence before any controlled validation or proof.", "success"); return

    if args.tool_catalog:
        build_tool_catalog_v160(outdir); log("V160 tool catalog generated.", "success"); return

    if args.v101_v110:
        log("PHASE: V101–V110 Reliability & Quality Stack", "header")
        build_execution_plan_v101(outdir,target); build_normalization_v102(outdir); build_qa_v103(outdir); build_smart_tools_v104(outdir,target)
        build_role_testing_v105(outdir); build_api_intelligence_v106(outdir); build_correlation_v107(outdir); build_change_detection_v108(outdir,save_baseline=args.baseline_change)
        build_evidence_vault_v109(outdir); ep,data=build_quality_gate_v110(outdir,target,scope_file)
        log(f"V110 quality gate → {ep} [{data['decision']}]", "success" if data['decision']=="READY" else "warn"); update_artifacts(outdir); return

    if args.web_assessment or args.web_surface or args.web_endpoints or args.web_assessment_plan:
        log("PHASE: Deep Web/API Assessment Intelligence (V45–V47)", "header")
        ep, rp = build_web_surface_v45(outdir, target)
        log(f"V45 surface model → {ep}", "success")
        ep2, rp2 = build_web_endpoints_v46(outdir)
        log(f"V46 endpoint intelligence → {ep2}", "success")
        ep3, rp3 = build_web_assessment_v47(outdir)
        log(f"V47 assessment plan → {ep3}", "success")
        update_artifacts(outdir)
        return

    if v48_requested:
        log("PHASE: Adaptive Web/API Assessment Engine (V48–V50)", "header")
        # Ensure the V45–V47 structured model exists before the V48 matrix.
        if not (outdir / "evidence" / "web-assessment-plan-v47.json").exists():
            build_web_surface_v45(outdir, target)
            build_web_endpoints_v46(outdir)
            build_web_assessment_v47(outdir)
        ep,rp=build_web_test_matrix_v48(outdir)
        log(f"V48 test matrix → {ep}", "success")
        if args.web_probe or args.web_engine:
            print("V49 performs only bounded GET observations. No redirects, mutation, payload injection, or secret handling.")
            approval=input("Approve V49 bounded observations? Type YES to continue: ").strip()=="YES"
            if approval:
                ep2,rp2=run_web_probe_v49(outdir, scope_file, approved=True)
                log(f"V49 observations → {ep2}", "success")
            else:
                log("V49 observation execution cancelled.", "warn")
        if args.web_decisions or args.web_engine:
            ep3,rp3=build_web_decisions_v50(outdir)
            log(f"V50 adaptive decisions → {ep3}", "success")
        update_artifacts(outdir)
        return

    if v51_requested:
        log("PHASE: Authentication & Authorization Intelligence (V51–V53)", "header")
        # Build from the structured V46 endpoint model; never collect credentials or tokens.
        if not (outdir / "evidence" / "web-endpoints-v46.json").exists():
            build_web_surface_v45(outdir, target)
            build_web_endpoints_v46(outdir)
        ep, rp = build_auth_intelligence_v51(outdir)
        log(f"V51 authentication intelligence → {ep}", "success")
        ep2, rp2 = build_authorization_matrix_v52(outdir)
        log(f"V52 authorization matrix → {ep2}", "success")
        ep3, rp3 = build_authz_decisions_v53(outdir)
        log(f"V53 authz decisions → {ep3}", "success")
        update_artifacts(outdir)
        return

    if v54_requested:
        log("PHASE: Session & Identity Intelligence (V54–V56)", "header")
        # Build from V51 authentication surfaces. Secrets and credentials are never collected.
        if not (outdir / "evidence" / "auth-intelligence-v51.json").exists():
            build_web_surface_v45(outdir, target)
            build_web_endpoints_v46(outdir)
            build_auth_intelligence_v51(outdir)
        ep, rp = build_session_intelligence_v54(outdir)
        log(f"V54 session intelligence → {ep}", "success")
        if args.session_observe or args.session_engine:
            print("V55 performs only bounded GET observations. No redirects, mutation, payload injection, or credential handling.")
            approval=input("Approve V55 session observations? Type YES to continue: ").strip()=="YES"
            if approval:
                try:
                    ep2,rp2=run_session_observation_v55(outdir, scope_file, approved=True)
                    log(f"V55 observations → {ep2}", "success")
                except Exception as exc:
                    log(f"V55 observation blocked: {exc}", "error")
            else:
                log("V55 observation execution cancelled.", "warn")
        if args.identity_transitions or args.session_engine:
            ep3,rp3=build_identity_transitions_v56(outdir)
            log(f"V56 identity transition decisions → {ep3}", "success")
        update_artifacts(outdir)
        return

    if v57_requested:
        log("PHASE: API Security Intelligence (V57–V59)", "header")
        if not (outdir / "evidence" / "web-endpoints-v46.json").exists():
            build_web_surface_v45(outdir, target)
            build_web_endpoints_v46(outdir)
        ep, rp = build_api_schema_v57(outdir)
        log(f"V57 API schema intelligence → {ep}", "success")
        if not (outdir / "evidence" / "api-schema-intelligence-v57.json").exists():
            build_api_schema_v57(outdir)
        ep2, rp2 = build_api_surface_v58(outdir)
        log(f"V58 API surface intelligence → {ep2}", "success")
        ep3, rp3 = build_api_decisions_v59(outdir)
        log(f"V59 API decisions → {ep3}", "success")
        update_artifacts(outdir)
        return

    if args.business_logic_engine or args.workflow_intelligence or args.workflow_sequences or args.business_logic_decisions:
        if args.business_logic_engine or args.workflow_intelligence:
            build_workflow_intelligence_v60(outdir)
        if args.business_logic_engine or args.workflow_sequences:
            build_workflow_sequences_v61(outdir)
        if args.business_logic_engine or args.business_logic_decisions:
            build_business_logic_v62(outdir)
        log("V60-V62 business logic intelligence complete", "success")

    if args.mission:
        log("PHASE: Pentest Mission Engine (V39–V41)", "header")
        print("This mode coordinates the existing authorized assessment pipeline. Controlled proof/exploitation remains separately approval-gated.")
        approval=input("Start the mission? Type YES to continue: ").strip()=="YES"
        if not approval:
            log("Mission cancelled.", "warn"); return
        build_mission_plan_v39(outdir, full=True, include_internal=args.internal, include_ad=bool(args.ad_guide or args.domain))
        mark_mission_v39(outdir,"verify-authorization","completed","operator reached mission after authorization gate")
        full=True

    if args.proof_plan:
        log("PHASE: Controlled Proof Planning (V35)", "header")
        registry_document(outdir / "evidence" / "proof-adapters.json")
        plan = build_controlled_proof_plan(outdir, approved=False)
        print(f"Policy: {DEFAULT_POLICY}")
        log(f"Controlled proof plan → {plan}", "success")
        update_artifacts(outdir)
        return

    if args.proof_analytics:
        log("PHASE: Proof Coverage & Validation Analytics (V38)", "header")
        p = build_proof_analytics_v38(outdir)
        log(f"Proof analytics → {p}", "success")
        update_artifacts(outdir)
        return

    if args.proof_execute:
        log("PHASE: Guarded Controlled Proof Execution (V37)", "header")
        print("Only a registered, narrow proof adapter may execute. Scope, request budget, and safety policy are enforced.")
        print("No arbitrary commands, persistence, credential access, lateral movement, or exfiltration are supported.")
        print(f"Finding: {args.proof_execute}")
        approval = input("\nApprove this guarded proof? Type YES to continue: ").strip() == "YES"
        if approval:
            try:
                result = execute_controlled_proof_v37(outdir, args.proof_execute, scope_file, approved=True, lab_mode=args.lab)
                audit_event(outdir, "guarded_proof_execution", {"finding_id": args.proof_execute, "adapter_id": result.get("adapter_id"), "result": result.get("result")})
                log(f"Proof {result['execution_id']} → {result['result']}", "success")
            except Exception as exc:
                log(f"Guarded proof blocked: {exc}", "error")
        else:
            log("Guarded proof cancelled by operator.", "warn")
        update_artifacts(outdir)
        return

    if args.deep_excellence or args.exploitation_intelligence or args.validation_excellence or args.ad_assessment or args.ad_execute or args.aws_assessment or args.aws_execute:
        log("PHASE: DEEP OPERATIONAL EXCELLENCE (V226-V231)", "header")
        build_exploitation_excellence_v226(outdir)
        build_validation_excellence_v227(outdir)
        build_ad_excellence_v228(outdir, target=target, scope_file=scope_file, approved=False, execute=False)
        build_aws_excellence_v229(outdir, account_id=args.aws_account_id, approved=False, execute=False)
        build_web_api_excellence_v230(outdir)
        if deep_active_requested:
            # V228/V229 execute real external commands, so they must pass the
            # same global authorization phrase as every other active path.
            require_authorization()
        if args.ad_execute:
            approval=input("Approve READ-ONLY AD enumeration? Type YES to continue: ").strip()=="YES"
            if approval:
                try:
                    build_ad_excellence_v228(outdir, target=target, scope_file=scope_file, approved=True, execute=True)
                    log("V228 AD read-only enumeration completed/recorded.", "success")
                except Exception as exc: log(f"V228 AD execution blocked: {exc}", "error")
            else: log("V228 AD execution cancelled.", "warn")
        if args.aws_execute:
            approval=input("Approve READ-ONLY AWS inventory? Type YES to continue: ").strip()=="YES"
            if approval:
                try:
                    build_aws_excellence_v229(outdir, account_id=args.aws_account_id, approved=True, execute=True)
                    log("V229 AWS read-only inventory completed/recorded.", "success")
                except Exception as exc: log(f"V229 AWS execution blocked: {exc}", "error")
            else: log("V229 AWS execution cancelled.", "warn")
        if args.deep_excellence or args.exploitation_intelligence or args.validation_excellence or args.ad_assessment or args.ad_execute or args.aws_assessment or args.aws_execute:
            p=build_deep_quality_v231(outdir,target)
            log(f"V231 deep quality gate → {p}", "success")
        update_artifacts(outdir)
        return

    if args.lab:
        create_lab(outdir, client=client, target=target); build_assessment(outdir); build_investigation_v18(outdir); build_knowledge_base(outdir); generate_control_center(outdir, client, target); generate_operator_workspace(outdir, client, target); build_analytics(outdir); update_artifacts(outdir); log(f"Synthetic lab created → {outdir}", "success"); return

    if args.set_business_impact:
        set_business_impact(outdir, args.set_business_impact, args.asset_importance, args.data_sensitivity, args.business_function, args.impact_note)
        log(f"Business impact recorded for {args.set_business_impact}", "success")
        build_assessment(outdir)
        update_artifacts(outdir)
        return

    if args.set_remediation:
        print("\nREMEDIATION TRACKING")
        print("This records remediation metadata only; it performs no target changes.")
        approval = input("Approve this remediation record? Type YES to continue: ").strip() == "YES"
        if approval:
            try:
                rec, path = set_remediation_record(outdir, args.set_remediation, args.remediation_status, args.remediation_owner, args.remediation_priority, args.remediation_due, args.remediation_note, approved=True)
                audit_event(outdir, "remediation_recorded", {"finding_id": args.set_remediation, "status": args.remediation_status})
                log(f"Remediation {rec['tracking_id']} recorded → {path}", "success")
            except Exception as exc: log(f"Remediation record blocked: {exc}", "error")
        else: log("Remediation record cancelled.", "warn")
        update_artifacts(outdir); return

    if args.retest_finding:
        print("\nMANUAL RETEST RECORD")
        print("This command records a tester-provided remediation result; it performs no network testing.")
        print(f"Finding: {args.retest_finding} | Result: {args.retest_result}")
        approval = input("Approve this retest record? Type YES to continue: ").strip() == "YES"
        if not approval:
            log("Retest record cancelled by operator.", "warn")
        else:
            entry, path = record_retest(outdir, args.retest_finding, args.retest_result, args.retest_note, args.retest_evidence, approved=True)
            log(f"Retest {entry["retest_id"]} recorded → {path}", "success")
            build_assessment(outdir)
        update_artifacts(outdir)
        return

    if args.case_finding:
        print("\nCASE MANAGEMENT")
        print("This records analyst metadata only; it performs no testing.")
        approval = input("Approve this case action? Type YES to continue: ").strip() == "YES"
        if approval:
            try:
                path=record_case(outdir,args.case_finding,args.case_action,args.case_text,args.case_evidence,approved=True)
                audit_event(outdir,"case_action_recorded",{"finding_id":args.case_finding,"action":args.case_action})
                log(f"Case action recorded → {path}","success")
            except Exception as exc: log(f"Case action blocked: {exc}","error")
        else: log("Case action cancelled.","warn")
        update_artifacts(outdir); return

    if args.workflow_status or args.workflow_advance:
        if args.workflow_advance:
            approval=input("Advance engagement workflow? Type YES to continue: ").strip()=="YES"
            if approval:
                try: workflow_advance(outdir,approved=True); audit_event(outdir,"workflow_advanced",{})
                except Exception as exc: log(f"Workflow advance blocked: {exc}","error")
            else: log("Workflow advance cancelled.","warn")
        p=workflow_status(outdir); log(f"Workflow → {p}","success"); update_artifacts(outdir); return

    # Require authorization before ANY active scan. Report-only/AD-guide generation can be run separately.
    if active_requested or validation_requested:
        require_authorization()

    if controlled_validation:
        log("PHASE: Controlled Validation", "header")
        print("\nCONTROLLED VALIDATION MODE")
        print("This action is limited to bounded, non-destructive observations.")
        print("No exploit payloads, arbitrary commands, persistence, credential access, lateral movement, or exfiltration are performed.")
        print(f"Finding: {args.validate_finding}")
        print(f"Mode: {args.validation_mode}")
        approval = input("\nApprove this controlled validation? Type YES to continue: ").strip() == "YES"
        if not approval:
            log("Controlled validation cancelled by operator.", "warn")
        else:
            try:
                result = controlled_validate(outdir, args.validate_finding, args.validation_mode, scope_file, approved=True)
                log(f"Validation {result['validation_id']} → {result['result']}", "success")
                log(f"Validation ledger → {outdir / 'evidence' / 'validation-ledger.json'}", "success")
                log(f"Validation report → {outdir / 'reports' / 'controlled-validation.md'}", "success")
            except Exception as exc:
                log(f"Controlled validation blocked: {exc}", "error")
        update_artifacts(outdir)
        return

    if v30_requested:
        log("PHASE: Controlled Exploitation & Proof (V30)", "header")
        print("\nCONTROLLED EXPLOITATION & PROOF")
        print("Only bounded, non-destructive HTTP proof checks are available in a real engagement.")
        print("No arbitrary commands, persistence, credential access, lateral movement, or exfiltration are supported.")
        approval = input("\nApprove this controlled proof? Type YES to continue: ").strip() == "YES"
        if approval:
            try:
                result = run_controlled_exploitation_v30(outdir, args.controlled_exploit, scope_file, approved=True)
                audit_event(outdir, "controlled_exploitation_proof", {"finding_id": args.controlled_exploit, "result": result.get("result")})
                log(f"CEP {result['execution_id']} → {result['result']}", "success")
            except Exception as exc:
                log(f"Controlled exploitation blocked: {exc}", "error")
        else:
            log("Controlled exploitation cancelled by operator.", "warn")
        build_exploit_evidence_v31(outdir)
        build_residual_risk_v32(outdir)
        update_artifacts(outdir)
        return

    state = load_state(str(outdir))
    completed = set(state.get("completed", [])) if args.resume else set()

    def should_run(phase, requested):
        return bool(requested) and phase not in completed

    def complete(phase):
        state["status"] = "success"
        state.setdefault("completed", []).append(phase) if phase not in state.setdefault("completed", []) else None
        save_state(str(outdir), state)

    if should_run("recon", full or args.recon_only):
        recon(target, outdir, allowed_scope)
        complete("recon")
    if should_run("ports", full or args.ports_only):
        portscan(target, outdir)
        complete("ports")
    if should_run("web", full or args.web_only):
        web_enum(outdir)
        complete("web")
    if should_run("vuln_scan", full or args.vuln_only):
        vuln_scan(outdir, retain_raw_evidence=retain_raw_evidence)
        complete("vuln_scan")

    # API strengthening
    if full or args.api:
        log("PHASE: API Security Scanning", "header")
        urls = outdir / "web" / "urls.txt"
        live = outdir / "recon" / "live-hosts.txt"
        target_file = str(urls if urls.exists() else live)
        auth_header = f"Cookie: {auth_cookie}" if auth_cookie else (f"Authorization: Bearer {auth_bearer}" if auth_bearer else "")
        run_api_scan(target_file, str(outdir / "api"), auth_header, scope_file)
        generate_api_checklist(str(outdir / "evidence"), target)

    # External server strengthening
    if full or args.server_enum:
        log("PHASE: External Server Enumeration", "header")
        run_server_enum(target, str(outdir / "servers"), scope_file)
        generate_server_checklist(str(outdir / "evidence"), target)

    # Internal mode
    if internal:
        log("PHASE: Internal Network Profile", "header")
        run_internal_scan(target, str(outdir / "internal"), scope_file)
        generate_internal_checklist(str(outdir / "evidence"))

    # Active Directory guidance
    if args.ad_guide or (full and args.domain):
        log("PHASE: Active Directory Guidance", "header")
        generate_ad_enum_guide(str(outdir / "ad"), args.domain or target)

    # Authenticated scanning
    if auth_cookie or auth_bearer:
        log("PHASE: Authenticated Scanning", "header")
        urls = outdir / "web" / "urls.txt"
        live = outdir / "recon" / "live-hosts.txt"
        target_file = str(urls if urls.exists() else live)
        if auth_cookie:
            run_authenticated_scan(target_file, str(outdir / "vulns"), "cookie", auth_cookie, scope_file)
        if auth_bearer:
            run_authenticated_scan(target_file, str(outdir / "vulns"), "bearer", auth_bearer, scope_file)

    if auth_cookie or jwt:
        generate_session_report(str(outdir / "evidence"), cookies=auth_cookie, jwt=jwt)

    if full or app_type:
        generate_business_logic_checklist(app_type, str(outdir / "evidence"), target)

    if full or screenshots:
        live = outdir / "recon" / "live-hosts.txt"
        if live.exists():
            run_screenshots(str(live), str(outdir / "screenshots"))

    if full or html_report:
        findings_json = outdir / "vulns" / "findings.json"
        auth_json = outdir / "vulns" / "authenticated-findings.json"
        report_input = findings_json
        if findings_json.exists() and auth_json.exists():
            report_input = outdir / "vulns" / "report-findings.jsonl"
            with open(report_input, "w", encoding="utf-8") as merged:
                merged.write(findings_json.read_text(encoding="utf-8"))
                merged.write(auth_json.read_text(encoding="utf-8"))
        if report_input.exists():
            generate_html_report(str(report_input), client, target, str(outdir / "reports" / "report.html"))

    if full or exploit:
        findings_json = outdir / "vulns" / "findings.json"
        if findings_json.exists():
            log("PHASE: Interactive Verification", "header")
            eng = InteractiveExploiter(str(findings_json), str(outdir / "evidence"))
            eng.run()

    if post_exploit:
        generate_post_exploit_guide(post_exploit, str(outdir / "evidence"), os_type)

    if getattr(args, "excellence_pretest", False):
        log("PHASE: V171-V190 Excellence Expansion", "info")
        run_excellence_pretest_stack(outdir, target)
        complete("excellence-pretest")
        log("V171-V190 excellence stack generated.", "success")
        return

    intelligence_requested = chain or report_pack or dashboard or control_center or analytics or next_investigation or assessment or technology_intelligence or correlation or governance or advanced_investigation or knowledge_base or operator_workspace or full or html_report or args.case_management or args.risk_analytics or args.workflow_status or args.workflow_advance or v24_requested or v25_requested or v26_requested or v27_requested or v28_requested or v29_requested or v30_requested or v31_requested or v32_requested or v33_requested or v35_requested or v39_requested or v40_requested or v41_requested or v42_requested or v57_requested or v60_requested
    if intelligence_requested:
        log("PHASE: Engagement Intelligence", "header")
        build_asset_inventory(outdir)
        build_evidence_index(outdir)
        build_technology_intelligence(outdir)
        build_correlation(outdir)
        audit_event(outdir, "intelligence_refresh", {"technology_intelligence": True, "correlation": True})
        build_timeline(outdir)
        json_path, md_path = generate_attack_graph(outdir)
        log(f"Attack graph → {json_path}", "success")
        log(f"Attack graph report → {md_path}", "success")
        recommend_next(outdir)
        build_assessment(outdir)
        build_investigation_v18(outdir)
        build_knowledge_base(outdir)
        build_cases(outdir)
        build_risk_analytics(outdir)
        build_normalization_v24(outdir)
        build_dedup_v25(outdir)
        build_remediation_v26(outdir)
        build_remediation_tracking_v27(outdir)
        build_retest_intelligence_v28(outdir)
        build_closure_v29(outdir)
        build_exploit_evidence_v31(outdir)
        build_residual_risk_v32(outdir)
        workflow_status(outdir)
        generate_dashboard(outdir, client, target)
        if control_center or full or dashboard or operator_workspace: generate_control_center(outdir, client, target)
        generate_operator_workspace(outdir, client, target)
        build_mission_plan_v39(outdir, full=True, include_internal=internal, include_ad=bool(args.ad_guide or args.domain))
        decide_adaptive_v41(outdir)
        if analytics or full or assessment: build_analytics(outdir)
        if governance or full: build_readiness(outdir)
        complete("intelligence")

    if report_pack or full or html_report:
        generate_status_report(str(outdir))
        generate_report_pack(str(outdir), client, target)
        build_retest_intelligence_v28(outdir)
        build_closure_v29(outdir)
        build_exploit_evidence_v31(outdir)
        build_residual_risk_v32(outdir)
        complete("reporting")

    if args.production_pretest:
        log("PHASE: PRODUCTION / REALITY LAYER (V211-V225)", "header")
        result = build_production_v211_v225(outdir, target)
        audit_event(outdir, "production_pretest", {"versions": "V211-V225", "decision": result.get("decision"), "human_review_required": True})
        update_artifacts(outdir)
        complete("production-pretest")
        log(f"V211-V225 quality gate → {result.get('decision')}", "success" if result.get("decision")=="PASS" else "warn")

    if v241_requested:
        log("PHASE: FINAL EXCELLENCE (V241-V242)", "header")
        from modules.research_exhaustion_v241 import build as build_research_exhaustion_v241
        from modules.final_readiness_v242 import build as build_final_readiness_v242
        if args.research_exhaustion or args.final_excellence:
            build_research_exhaustion_v241(outdir, target)
        if args.final_readiness or args.final_excellence:
            result = build_final_readiness_v242(outdir, target, require_active_tools=bool(args.integrated_mission or args.bounty_execute))
            audit_event(outdir, "final-readiness", {"decision": result.get("decision"), "versions": "V241-V242", "human_review_required": True})
        update_artifacts(outdir)
        complete("final-excellence")
        log("V241-V242 final excellence artifacts generated.", "success")

    if operator_requested:
        mode = v76_mode or "auto"
        log(f"PHASE: UNIFIED SECURITY OPERATOR (V77–V91) [{mode}]", "header")
        build_security_brain_v77(outdir, mode, target, args.osint_objective)
        build_evidence_memory_v78(outdir)
        build_task_router_v79(outdir, mode, args.osint_objective)
        build_operator_loop_v80(outdir, mode, target, args.osint_objective, execute=args.operator_execute)
        build_unified_assessment_v81(outdir, mode, target, client, args.osint_objective, args.program_name, args.program_policy, complete_requested=(mode in ("pentest","auto")))
        build_final_intelligence_v82(outdir)
        # V83-V90: intelligence/operator expansion. These layers analyze existing
        # evidence, create bounded plans, and never bypass the existing safety gates.
        build_ai_reasoning_v83(outdir, mode, target, args.osint_objective or "general")
        build_target_profile_v84(outdir, target)
        build_web_intelligence_v85(outdir)
        build_osint_collection_v86(outdir, target, collect=args.osint_collect and mode in ("osint", "auto"))
        build_cross_engagement_memory_v87(outdir, target)
        if mode in ("bugbounty", "auto"):
            build_bounty_prioritization_v88(outdir)
        build_reporting_monitoring_v89(outdir, target)
        build_security_training_v90(outdir, args.osint_objective or "general")
        build_master_operator_v91(outdir, mode, target)
        # V92–V110: always materialize the current capability/reliability/quality view;
        # V101 execution is only performed by --integrated-mission.
        build_capability_registry_v92(outdir); build_self_verification_v93(outdir); build_security_knowledge_graph_v94(outdir,target)
        build_hypothesis_engine_v95(outdir); build_experiment_planner_v96(outdir); build_capability_reliability_v97(outdir)
        build_plugin_architecture_v98(outdir); build_operator_dashboard_v99(outdir,target)
        build_execution_plan_v101(outdir,target); build_normalization_v102(outdir); build_qa_v103(outdir); build_smart_tools_v104(outdir,target)
        build_role_testing_v105(outdir); build_api_intelligence_v106(outdir); build_correlation_v107(outdir); build_change_detection_v108(outdir)
        build_evidence_vault_v109(outdir); build_quality_gate_v110(outdir,target,scope_file); build_excellence_v111_v145(outdir,target,scope_file); build_hardening_v161_v175(outdir,target); build_osint_source_registry_v161(outdir); build_security_audit_v163(outdir); build_runtime_policy_v164(outdir); build_osint_quality_v165(outdir)
        audit_event(outdir, "unified_security_operator", {"mode": mode, "versions": "V77-V110", "human_review_required": True})
        update_artifacts(outdir)
        complete("unified-operator")
        log("Unified security operator intelligence stack V77-V91 generated.", "success")

    if v76_requested:
        log(f"PHASE: V71-V76 INTELLIGENCE MODE ({v76_mode})", "header")
        build_intelligence_mode_v76(outdir, v76_mode, target, args.osint_objective, args.program_name, args.program_policy)
        audit_event(outdir, "intelligence_mode", {"mode": v76_mode, "versions": "V71-V76", "human_review_required": True})
        # V233-V240: evidence-driven OSINT and bug-bounty excellence layer.
        if v76_mode in ("osint", "auto"):
            from modules.osint_orchestrator_v233 import build as build_osint_v233
            from modules.osint_ingest_v234 import ingest as ingest_osint_v234
            from modules.osint_correlation_v235 import build as build_osint_corr_v235
            from modules.osint_gap_engine_v236 import build as build_osint_gap_v236
            from modules.osint_intelligence_report_v237 import build as build_osint_report_v237
            build_osint_v233(outdir, target, args.osint_objective, collect=True)
            ingest_paths = list(args.osint_input)
            built_in = outdir / "evidence" / "osint-public-collection-v233.json"
            if built_in.exists():
                ingest_paths.append(str(built_in))
            ingest_osint_v234(outdir, ingest_paths)
            build_osint_corr_v235(outdir); build_osint_gap_v236(outdir); build_osint_report_v237(outdir, target)
        if v76_mode in ("bugbounty", "auto"):
            from modules.bug_bounty_program_v238 import build as build_bb_policy_v238
            from modules.bug_bounty_planner_v239 import build as build_bb_plan_v239
            from modules.bug_bounty_quality_v240 import build as build_bb_quality_v240
            assets = list(args.bounty_assets)
            if target and target not in assets:
                assets.append(target)
            build_bb_policy_v238(outdir, args.program_name, args.program_policy, assets)
            build_bb_plan_v239(outdir, target)
            build_bb_quality_v240(outdir)
        update_artifacts(outdir)
        complete("intelligence-mode")
        log("Bug-bounty / OSINT intelligence stack V233-V240 generated.", "success")

    if complete_requested:
        log("PHASE: COMPLETE ASSESSMENT PLATFORM (V45–V70)", "header")
        # Build every structured intelligence layer in dependency order after the
        # full authorized discovery/vulnerability phases have populated artifacts.
        build_web_surface_v45(outdir, target)
        build_web_endpoints_v46(outdir)
        build_web_assessment_v47(outdir)
        build_web_test_matrix_v48(outdir)
        build_web_decisions_v50(outdir)
        build_auth_intelligence_v51(outdir)
        build_authorization_matrix_v52(outdir)
        build_authz_decisions_v53(outdir)
        build_session_intelligence_v54(outdir)
        build_identity_transitions_v56(outdir)
        build_api_schema_v57(outdir)
        build_api_surface_v58(outdir)
        build_api_decisions_v59(outdir)
        build_workflow_intelligence_v60(outdir)
        build_workflow_sequences_v61(outdir)
        build_business_logic_v62(outdir)
        build_complete_v63_v70(outdir, client, target)
        audit_event(outdir, "complete_assessment_stack", {"versions": "V45-V70", "human_review_required": True})
        update_artifacts(outdir)
        complete("complete-assessment")
        log("Complete assessment intelligence stack generated.", "success")
    generate_coverage_report(str(outdir), client, target)
    audit_event(outdir, "pipeline_finished", {"full": bool(full), "intelligence": bool(intelligence_requested)})
    update_artifacts(outdir)

    log(f"Pipeline finished → {outdir}", "success")
    log(f"Dashboard → {outdir / 'reports' / 'dashboard.html'}", "success") if (outdir / 'reports' / 'dashboard.html').exists() else None
    log(f"Control center → {outdir / 'reports' / 'control-center.html'}", "success") if (outdir / 'reports' / 'control-center.html').exists() else None
    log(f"Analytics → {outdir / 'reports' / 'analytics.md'}", "success") if (outdir / 'reports' / 'analytics.md').exists() else None
    log(f"Next investigation → {outdir / 'reports' / 'next-investigation.md'}", "success") if (outdir / 'reports' / 'next-investigation.md').exists() else None
    log(f"Closure readiness → {outdir / 'reports' / 'closure-readiness.md'}", "success") if (outdir / "reports" / "closure-readiness.md").exists() else None
    log("Review reports/engagement-coverage.md for remaining manual work.")

# V171-V190 excellence expansion: callable from --excellence-pretest.
def run_excellence_pretest_stack(outdir, target=""):
    from modules.platform_observability_v171 import build as v171
    from modules.execution_scheduler_v172 import build as v172
    from modules.config_validation_v173 import build as v173
    from modules.osint_source_quality_v174 import build as v174
    from modules.osint_entity_resolution_v175 import build as v175
    from modules.image_osint_pipeline_v176 import build as v176
    from modules.location_osint_v177 import build as v177
    from modules.attack_surface_baseline_v178 import build as v178
    from modules.change_analysis_v179 import build as v179
    from modules.evidence_chain_v180 import build as v180
    from modules.finding_confidence_v181 import build as v181
    from modules.report_quality_v182 import build as v182
    from modules.compliance_mapping_v183 import build as v183
    from modules.plugin_sdk_v184 import build as v184
    from modules.worker_readiness_v185 import build as v185
    from modules.learning_feedback_v186 import build as v186
    from modules.quality_gate_v188 import build as v188
    from modules.operator_readiness_v189 import build as v189
    from modules.pretest_manifest_v190 import build as v190
    for fn in (v171,v172,v173,v174,v175,v176,v178,v179,v180,v181,v182,v183,v184,v185,v186,v188,v189,v190): fn(outdir)
    v177(outdir,target)

# V196-V210 legitimate location/OSINT excellence expansion.
def run_v196_v210(outdir, target="", platform="other", location_data=None):
    from modules.osint_entity_graph_v201 import build as v201
    from modules.osint_social_sources_v202 import build as v202
    from modules.image_analysis_v203 import build as v203
    from modules.osint_timeline_v204 import build as v204
    from modules.osint_source_corroboration_v205 import build as v205
    v201(outdir); v202(outdir); v203(outdir); v204(outdir); v205(outdir)
    return True

if __name__ == "__main__":
    main()
