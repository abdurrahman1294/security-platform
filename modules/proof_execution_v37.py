#!/usr/bin/env python3
"""V37 guarded execution of registered controlled-proof adapters."""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from pathlib import Path
from modules.exploit_adapter_v33 import REGISTRY
import modules.exploit_adapters_v33
import modules.exploit_adapters_v36
from modules.exploit_policy_v34 import DEFAULT_POLICY, evaluate
from modules.proof_execution_guard_v37 import ExecutionGuard
from modules.approval_queue import ApprovalQueue
from modules.atomic_io import load_json
from modules.scope import load_scope
from modules.exploit_planner_v35 import load_findings


def _find(root, finding_id):
    for f in load_findings(root):
        if (f.get("finding_id") or f.get("id")) == finding_id:
            return f
    return None


def execute(root, finding_id, scope_file, approved=False, lab_mode=False,
            approval_request_id=None, approval_token=None):
    root = Path(root)
    if not approved:
        raise PermissionError("Explicit operator approval is required")
    allowed = load_scope(scope_file)
    if not allowed:
        raise PermissionError("Missing/empty scope allowlist")
    finding = _find(root, finding_id)
    if not finding:
        raise ValueError(f"Finding not found: {finding_id}")
    choices = REGISTRY.select(finding)
    adapter = next((a for a in choices if not a.lab_only or lab_mode), None)
    if adapter is None:
        raise PermissionError("No supported controlled-proof adapter")
    target = str(finding.get("endpoint") or finding.get("url") or finding.get("host") or "").strip()
    action = f"controlled-proof:{adapter.adapter_id}"
    if not approval_request_id or not approval_token:
        raise PermissionError("Request-bound single-use approval token is required")
    queue = ApprovalQueue(root / "evidence")
    if not queue.consume_token(approval_request_id, approval_token, action, target):
        raise PermissionError("Invalid, mismatched, expired, or already-consumed approval token")
    decision = evaluate(adapter, finding, approved=True, scope_ok=True, lab_mode=lab_mode)
    if not decision["allowed"]:
        raise PermissionError("; ".join(decision["reasons"]))
    guard = ExecutionGuard(list(allowed), DEFAULT_POLICY.max_requests, DEFAULT_POLICY.max_body_bytes)
    handler = REGISTRY.handler(adapter.adapter_id)
    if handler is None:
        raise RuntimeError(f"Adapter handler unavailable: {adapter.adapter_id}")
    result = handler(finding, guard=guard, lab_mode=lab_mode)
    entry = {"schema_version": "37.0", "execution_id": f"PVE-{uuid.uuid4().hex[:12]}",
             "finding_id": finding_id, "adapter_id": adapter.adapter_id,
             "result": result.get("result"), "observation": result.get("observation", {}),
             "request_class": result.get("request_class"), "guard": guard.snapshot(),
             "policy": {"max_requests": DEFAULT_POLICY.max_requests,
                        "max_body_bytes": DEFAULT_POLICY.max_body_bytes,
                        "redirects_followed": False, "state_change": False},
             "approved": True, "lab_mode": bool(lab_mode),
             "timestamp": datetime.now(timezone.utc).isoformat()}
    p = root / "evidence" / "proof-execution-ledger.json"; p.parent.mkdir(parents=True, exist_ok=True)
    rows=[]
    if p.exists():
        rows=load_json(p, [])
    rows = rows if isinstance(rows,list) else []
    rows.append(entry); p.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return entry
