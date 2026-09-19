"""V3.60 final capability closure and assurance report."""
from __future__ import annotations
from pathlib import Path
import hashlib, json, time
from modules.reliability_execution_integrity_v331 import atomic_write
from modules.autonomous_kernel_v360 import build_final_control_plane, VERSION

def _write(root,name,obj):
    p=Path(root)/"evidence"/name; atomic_write(p,obj); return p

def build_final_closure(root, *, target="127.0.0.1", scope_hash="lab", authorization_epoch="lab", objective="final-engine"):
    cp=build_final_control_plane(root,target=target,scope_hash=scope_hash,authorization_epoch=authorization_epoch,objective=objective)
    closure={
      "schema_version":VERSION,"status":"final-closure",
      "claim_policy":"implemented architecture is not equivalent to universal real-world coverage",
      "closed_gaps":[
        {"id":"GAP-336-01","area":"enterprise-emulation","closure":"ATT&CK-aligned planning, governed specialist delegation, evidence lifecycle, and lab/testbed envelope"},
        {"id":"GAP-336-02","area":"web-api","closure":"central test taxonomy, coverage matrix, bounded validation catalog, evidence/provenance hooks"},
        {"id":"GAP-336-03","area":"identity","closure":"protocol assurance catalog, evidence contracts, specialist delegation and safe validation planning"},
        {"id":"GAP-336-04","area":"mobile-wireless","closure":"canonical specialist adapter lifecycle and centralized evidence/state contracts"},
        {"id":"GAP-336-05","area":"physical-testbeds","closure":"explicit lab/testbed adapter envelope, approval gates and non-autonomous physical-impact boundary"},
        {"id":"GAP-336-06","area":"fuzzing","closure":"campaign identity, budgets, corpus lifecycle metadata, crash fingerprints, repro references and triage contracts"},
        {"id":"GAP-336-07","area":"multi-engagement","closure":"SQLite engagement state plus durable engagement index and analytics metadata"},
        {"id":"GAP-336-08","area":"legacy-subprocess","closure":"legacy boundary inventory plus central ToolManager migration contract and audit visibility"},
        {"id":"AUTONOMY-CONVERGENCE","area":"reasoning","closure":"deterministic task identity, duplicate/branch convergence, single-owner leases and stale recovery"},
        {"id":"AUTONOMY-RECEIPTS","area":"execution-integrity","closure":"scope/authorization-bound exact execution receipts and settlement"},
      ],
      "not_claimed_as_closed":[
        "unrestricted autonomous exploitation",
        "credential theft or spraying",
        "persistence deployment",
        "covert command-and-control",
        "destructive actions",
        "scope bypass",
        "universal endpoint-agent runtime",
        "universal physical/hardware execution",
        "human business-logic judgment"
      ],
      "control_plane":cp,
      "generated_at":time.time()
    }
    _write(root,"final-engine-closure-v360.json",closure)
    return closure

def v360_test_matrix():
    names=["task-idempotency","duplicate-convergence","branch-convergence","single-owner-lease","lease-expiry","stale-recovery","scope-binding","authorization-epoch-binding","approval-gate","exact-receipt","receipt-evidence-lineage","provider-not-canonical","web-api-catalog","identity-catalog","fuzz-corpus-contract","multi-engagement-index","legacy-boundary-audit","no-scope-expansion","no-authority-grant","no-unrestricted-rce","no-credential-theft","no-persistence","no-covert-c2","atomic-final-artifact"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":hashlib.sha256(x.encode()).hexdigest()[:20],"name":x,"expected":"pass"} for x in names]}
