#!/usr/bin/env python3
"""V3.56 governed controlled-proof execution fabric.

This layer makes the engine execution-capable only through narrow, bounded,
non-destructive proof adapters. Every execution requires:
- explicit operator approval;
- a request-bound, single-use approval token;
- an in-scope HTTP(S) target;
- a registered adapter;
- strict request/body budgets;
- no redirect following.

It deliberately does not provide arbitrary shell/payload execution, credential
theft, persistence, lateral movement, exfiltration, evasion, or destructive actions.
Lab-only adapters may exercise synthetic canaries under the same guard.
"""
from __future__ import annotations
import json
from pathlib import Path
from modules.approval_queue import ApprovalQueue
from modules.proof_execution_v37 import execute
from modules.exploit_adapter_v33 import REGISTRY
import modules.exploit_adapters_v33
import modules.exploit_adapters_v36

SCHEMA_VERSION="3.56.0"

def request_proof(root: str|Path, finding: dict, adapter_id: str, reason: str,
                  risk: str="R3"):
    root=Path(root)
    adapter=REGISTRY.get(adapter_id)
    if adapter is None:
        raise ValueError("Unknown proof adapter")
    target=str(finding.get("endpoint") or finding.get("url") or finding.get("host") or "").strip()
    if not target:
        raise ValueError("Finding has no target")
    q=ApprovalQueue(root/"evidence")
    req=q.submit(f"controlled-proof:{adapter_id}", target, reason, risk)
    return {"schema_version":SCHEMA_VERSION,"request_id":req.request_id,
            "action":req.action,"target":req.target,"status":req.status,
            "expires_at":req.expires_at,"adapter_id":adapter_id}

def approve_proof(root: str|Path, request_id: str):
    q=ApprovalQueue(Path(root)/"evidence")
    token=q.approve(request_id)
    if not token:
        raise PermissionError("Approval request cannot be approved")
    return {"request_id":request_id,"token":token,"single_use":True}

def execute_approved_proof(root: str|Path, finding_id: str, scope_file: str,
                           approval_request_id: str, approval_token: str,
                           lab_mode: bool=False):
    return execute(root, finding_id, scope_file, approved=True, lab_mode=lab_mode,
                   approval_request_id=approval_request_id, approval_token=approval_token)

def catalog():
    return {"schema_version":SCHEMA_VERSION,
            "adapters":REGISTRY.list(),
            "governance":{"operator_approval":True,"single_use_tokens":True,
                          "scope_required":True,"redirects_followed":False,
                          "arbitrary_commands":False,"credential_access":False,
                          "persistence":False,"lateral_movement":False,
                          "exfiltration":False,"destructive_actions":False}}

def write_catalog(path: str|Path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(catalog(),indent=2),encoding="utf-8")
    return p

def v356_test_matrix():
    scenarios=[
        "approval_required","request_bound_token","single_use_token",
        "token_target_binding","token_action_binding","expired_token_rejected",
        "scope_required","scope_enforced_per_request","http_only",
        "redirects_disabled","request_budget","body_budget","adapter_registry",
        "handler_presence","reflected_xss_guarded","open_redirect_guarded",
        "sqli_guarded","lab_ssrf_requires_lab_mode","no_arbitrary_command",
        "no_credential_access","no_persistence","no_lateral_movement",
        "no_exfiltration","no_destructive_actions","ledger_written",
        "operator_reason_recorded","approval_consumed","evidence_snapshot",
        "catalog_consistency","adapter_count_nonzero","unknown_adapter_rejected"
    ]
    return {"schema_version":SCHEMA_VERSION,"scenario_count":len(scenarios),
            "scenarios":scenarios}
