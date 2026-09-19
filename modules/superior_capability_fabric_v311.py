from __future__ import annotations
"""V3.11 superior-capability fabric.

Combines higher-value ideas observed across open-source pentest ecosystems into
one evidence-first layer: agentic task decomposition, source/runtime
correlation, browser-trace evidence, proof lifecycle, continuous assurance,
and benchmark-quality metrics.

This module is orchestration/analysis only. It never generates payloads,
credentials, persistence, evasion, C2, or arbitrary shell commands.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic_io import atomic_write_json, load_json
from .security import redact_mapping

VERSION = "3.11.0"
FORBIDDEN = {
    "credential_theft", "credential_capture", "persistence", "lateral_movement",
    "exfiltration", "evasion", "c2", "payload_generation", "arbitrary_shell",
    "destructive_actions",
}

ROLE_CATALOG = {
    "recon": {"purpose": "asset and attack-surface discovery", "risk": "R0-R2"},
    "web": {"purpose": "web/API surface and workflow analysis", "risk": "R0-R2"},
    "source": {"purpose": "source-aware static evidence analysis", "risk": "R0"},
    "identity": {"purpose": "authentication/authorization/session analysis", "risk": "R0-R2"},
    "cloud": {"purpose": "cloud/Kubernetes configuration and identity analysis", "risk": "R0-R2"},
    "mobile": {"purpose": "mobile static/runtime evidence analysis", "risk": "R0-R2"},
    "network": {"purpose": "network/service exposure analysis", "risk": "R0-R2"},
    "validator": {"purpose": "least-invasive proof/retest planning", "risk": "R2-R3"},
    "correlator": {"purpose": "cross-source finding correlation", "risk": "R0"},
    "reporter": {"purpose": "evidence-backed reporting and remediation", "risk": "R0"},
}

DEFAULT_SKILLS = [
    "owasp-web", "owasp-api", "authentication", "authorization", "business-logic",
    "cloud-identity", "ad-relationships", "mobile-masvs", "network-exposure",
    "source-dataflow", "false-positive-analysis", "proof-and-retest",
]


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:20]


def _json_files(root: Path) -> list[Path]:
    return sorted((root / "evidence").glob("*.json")) if (root / "evidence").exists() else []


def _safe_context(root: Path, limit: int = 80) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in _json_files(root):
        data = load_json(p, None, quarantine_on_error=False)
        if data is None:
            continue
        safe = redact_mapping(data)
        text = json.dumps(safe, sort_keys=True, default=str)
        rows.append({"artifact": p.name, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                     "keys": list(safe.keys())[:40] if isinstance(safe, dict) else [],
                     "size": len(text)})
    return rows[-limit:]


def _artifact_exists(root: Path, *names: str) -> bool:
    return any((root / "evidence" / n).exists() for n in names)



MODEL_PROVIDERS = [
    "openai", "anthropic", "google", "deepseek", "xai", "qwen",
    "moonshot", "ollama", "vllm", "custom-https",
]


def build_model_routing_plan(root: str | Path, objective: str = "general") -> dict[str, Any]:
    """Create a provider-agnostic model routing policy without storing secrets."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    policy = {
        "reasoning": {"preferred": ["openai", "anthropic", "google", "ollama"], "fallback": "heuristic"},
        "code_analysis": {"preferred": ["anthropic", "openai", "ollama"], "fallback": "heuristic"},
        "summarization": {"preferred": ["google", "qwen", "ollama"], "fallback": "heuristic"},
        "offline": {"preferred": ["ollama", "vllm"], "fallback": "disabled"},
    }
    out = {"schema_version": VERSION, "objective": objective, "providers": MODEL_PROVIDERS,
           "routing": policy, "secret_storage": "none",
           "selection_rule": "provider availability and engagement policy decide the final route"}
    atomic_write_json(evidence / "model-routing-v311.json", out)
    return out


def import_attack_emulation_catalog(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Import ATT&CK/Atomic-style technique metadata for planning and detection validation.

    Only metadata is imported. The fabric does not execute emulation payloads.
    """
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    src = Path(source); raw = json.loads(src.read_text(encoding="utf-8"))
    objects = raw.get("objects", []) if isinstance(raw, dict) else []
    techniques = []
    for obj in objects:
        if not isinstance(obj, dict): continue
        typ = obj.get("type", "")
        if typ not in {"attack-pattern", "technique", "test"}: continue
        tid = ""
        for ref in obj.get("external_references", []) or []:
            if isinstance(ref, dict) and str(ref.get("external_id", "")).startswith("T"):
                tid = ref.get("external_id"); break
        techniques.append({"id": tid or obj.get("id"), "name": obj.get("name", ""),
                           "description": str(obj.get("description", ""))[:600],
                           "execution": "metadata-only", "approval_required": True})
    out = {"schema_version": VERSION, "source": src.name, "techniques": techniques,
           "count": len(techniques), "use": ["coverage mapping", "emulation planning", "detection validation"],
           "execution_boundary": "No payloads, C2, persistence or remote execution are produced by this importer."}
    atomic_write_json(evidence / "attack-emulation-catalog-v311.json", out)
    return out


def build_agentic_plan(root: str | Path, target: str, objective: str = "general", *, max_parallel: int = 4) -> dict[str, Any]:
    """Create a resumable, dependency-aware multi-role assessment plan."""
    root = Path(root)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    ctx = _safe_context(root)

    tasks = [
        ("recon", "surface_inventory", [], 90),
        ("source", "source_evidence", [], 88),
        ("web", "web_api_model", ["surface_inventory"], 86),
        ("identity", "identity_and_session_model", ["surface_inventory"], 84),
        ("cloud", "cloud_identity_configuration", ["surface_inventory"], 78),
        ("mobile", "mobile_static_runtime_model", ["surface_inventory"], 72),
        ("network", "network_service_model", ["surface_inventory"], 80),
        ("correlator", "cross_source_correlation", ["source_evidence", "web_api_model", "identity_and_session_model"], 94),
        ("validator", "proof_and_retest_queue", ["cross_source_correlation"], 96),
        ("reporter", "evidence_report_and_remediation", ["proof_and_retest_queue"], 70),
    ]

    rows = []
    for role, task, deps, score in tasks:
        present = {
            "surface_inventory": _artifact_exists(root, "asset-inventory.json", "capability-matrix-v300.json"),
            "source_evidence": _artifact_exists(root, "source-analysis-v311.json", "sarif-import-v311.json"),
            "web_api_model": _artifact_exists(root, "web-surface-v45.json", "api-surface-v58.json"),
            "identity_and_session_model": _artifact_exists(root, "auth-intelligence-v51.json", "session-intelligence-v54.json"),
            "cloud_identity_configuration": _artifact_exists(root, "cloud-intelligence-v64.json", "cloud-multiplatform-v32.json"),
            "mobile_static_runtime_model": _artifact_exists(root, "mobsf-import-v39.json", "ios-dynamic-v33.json"),
            "network_service_model": _artifact_exists(root, "infrastructure-intelligence-v63.json", "network-surface-v27.json"),
            "cross_source_correlation": _artifact_exists(root, "correlation-v107.json", "cross-domain-plan-v310.json"),
            "proof_and_retest_queue": _artifact_exists(root, "proof-analytics-v38.json", "retest-intelligence-v28.json"),
            "evidence_report_and_remediation": _artifact_exists(root, "final-report-v69.json", "report-pack.json"),
        }.get(task, False)
        rows.append({"id": task, "role": role, "dependencies": deps, "priority": score,
                     "status": "materialized" if present else "ready",
                     "requires_approval": role == "validator",
                     "objective": objective})

    data = {
        "schema_version": VERSION,
        "target": target,
        "objective": objective,
        "architecture": "multi-role agentic fabric with deterministic policy/evidence gates",
        "max_parallel": max(1, min(int(max_parallel), 8)),
        "roles": ROLE_CATALOG,
        "skills": DEFAULT_SKILLS,
        "tasks": rows,
        "context_manifest": ctx,
        "resume_key": _hash({"target": target, "objective": objective, "tasks": rows}),
        "safety": {"human_approval_for_consequential_actions": True,
                   "forbidden_autonomy": sorted(FORBIDDEN),
                   "scope_is_never_expanded_by_imported_evidence": True},
    }
    atomic_write_json(evidence / "superior-agentic-plan-v311.json", data)
    return data


def import_sarif(root: str | Path, source: str | Path, source_name: str = "SARIF") -> dict[str, Any]:
    """Normalize SARIF from Semgrep/CodeQL-like tools into evidence candidates."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    src = Path(source)
    raw = json.loads(src.read_text(encoding="utf-8"))
    runs = raw.get("runs", []) if isinstance(raw, dict) else []
    findings = []
    for run in runs:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name", source_name)
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules", [])
        rule_map = {str(r.get("id")): r for r in rules if isinstance(r, dict)}
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            loc = ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            artifact = ((loc.get("artifactLocation") or {}).get("uri") or "")
            region = loc.get("region") or {}
            rid = str(result.get("ruleId", "unknown"))
            rule = rule_map.get(rid, {})
            msg = ((result.get("message") or {}).get("text") or "").strip()
            findings.append({
                "id": "SRC-" + _hash({"tool": tool, "rid": rid, "artifact": artifact, "line": region.get("startLine"), "msg": msg}),
                "source": tool, "rule_id": rid, "rule": rule.get("name", rid), "message": msg,
                "location": {"file": artifact, "line": region.get("startLine"), "column": region.get("startColumn")},
                "level": result.get("level", "warning"), "state": "candidate", "provenance": "SARIF",
            })
    out = {"schema_version": VERSION, "source_name": source_name, "source_file": src.name,
           "findings": findings, "count": len(findings),
           "rule": "static analysis is evidence candidate, not proof"}
    atomic_write_json(evidence / "sarif-import-v311.json", out)
    return out


def correlate_source_runtime(root: str | Path, *, runtime_artifact: str = "") -> dict[str, Any]:
    """Fuse source findings with runtime/web evidence without executing exploits."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    src = load_json(evidence / "sarif-import-v311.json", {}) or {}
    source_findings = src.get("findings", []) if isinstance(src, dict) else []
    runtime = load_json(evidence / runtime_artifact, {}) if runtime_artifact else {}
    if not isinstance(runtime, dict): runtime = {}
    runtime_text = json.dumps(runtime, default=str).lower()
    rows = []
    for f in source_findings:
        file_name = str((f.get("location") or {}).get("file", ""))
        msg = str(f.get("message", ""))
        tokens = [x.lower() for x in (file_name, msg) if x]
        matched = [t for t in tokens if len(t) > 4 and t in runtime_text]
        confidence = "high" if len(matched) >= 2 else "medium" if matched else "candidate"
        rows.append({"source_id": f.get("id"), "confidence": confidence,
                     "runtime_correlated": bool(matched), "matched_tokens": matched[:5],
                     "validation_required": True})
    out = {"schema_version": VERSION, "source_count": len(source_findings),
           "runtime_artifact": runtime_artifact, "correlations": rows,
           "principle": "source evidence narrows hypotheses; runtime evidence validates behavior"}
    atomic_write_json(evidence / "source-runtime-correlation-v311.json", out)
    return out


def import_browser_trace(root: str | Path, source: str | Path) -> dict[str, Any]:
    """Normalize HAR-like browser/proxy traces into request/flow evidence."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    src = Path(source); raw = json.loads(src.read_text(encoding="utf-8"))
    entries = (((raw.get("log") or {}).get("entries")) if isinstance(raw, dict) else None) or raw.get("entries", []) if isinstance(raw, dict) else []
    flows = []
    for e in entries:
        req = e.get("request", {}) if isinstance(e, dict) else {}
        resp = e.get("response", {}) if isinstance(e, dict) else {}
        url = str(req.get("url", "")); method = str(req.get("method", "GET"))
        flows.append({"id": "FLOW-" + _hash({"m": method, "u": url}), "method": method,
                      "url": url, "status": resp.get("status"),
                      "mime": ((resp.get("content") or {}).get("mimeType")),
                      "timing_ms": e.get("time"), "state": "observed"})
    out = {"schema_version": VERSION, "source": src.name, "flows": flows,
           "count": len(flows), "supports": ["authenticated-flow-mapping", "API-discovery", "business-workflow-candidates", "regression-baselines"],
           "no_credentials_retained": True}
    atomic_write_json(evidence / "browser-trace-v311.json", out)
    return out


def build_continuous_assurance(root: str | Path, *, baseline: str = "") -> dict[str, Any]:
    """Turn changes/baselines into a bounded continuous-assurance plan."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    current = []
    for p in _json_files(root):
        if p.name in {"continuous-assurance-v311.json", "benchmark-metrics-v311.json"}:
            continue
        data = load_json(p, None, quarantine_on_error=False)
        if data is None: continue
        current.append({"artifact": p.name, "fingerprint": _hash(redact_mapping(data))})
    old = load_json(evidence / baseline, {}) if baseline else {}
    old_map = {x.get("artifact"): x.get("fingerprint") for x in (old.get("artifacts", []) if isinstance(old, dict) else [])}
    changed = [x for x in current if old_map.get(x["artifact"]) not in {None, x["fingerprint"]}]
    plan = []
    for x in changed:
        plan.append({"artifact": x["artifact"], "action": "re-assess impacted capability and retest linked findings",
                     "approval_required": True})
    out = {"schema_version": VERSION, "baseline": baseline, "artifacts": current,
           "changed": changed, "regression_plan": plan,
           "ci_safe": True, "execution": "plan-only unless existing policy grants a bounded action"}
    atomic_write_json(evidence / "continuous-assurance-v311.json", out)
    return out


def build_benchmark_metrics(root: str | Path) -> dict[str, Any]:
    """Measure quality like modern agentic pentest benchmarks do."""
    root = Path(root); evidence = root / "evidence"; evidence.mkdir(parents=True, exist_ok=True)
    ledger = load_json(evidence / "tool-execution-ledger-v40.json", []) or []
    proof = load_json(evidence / "proof-analytics-v38.json", {}) or {}
    quality = load_json(evidence / "qa-verification-v103.json", {}) or {}
    rows = ledger if isinstance(ledger, list) else []
    completed = [r for r in rows if r.get("status") == "completed"]
    failed = [r for r in rows if r.get("status") in {"failed", "error", "timeout"}]
    total = len(rows)
    out = {
        "schema_version": VERSION,
        "metrics": {
            "tool_steps": total, "successful_steps": len(completed), "failed_steps": len(failed),
            "execution_success_rate": round(len(completed) / total, 4) if total else 0.0,
            "qa_pass_rate": quality.get("quality_pass_rate", 0.0),
            "proof_metrics": proof.get("metrics", proof) if isinstance(proof, dict) else {},
        },
        "recommended_benchmark_dimensions": ["coverage", "proof_rate", "false_positive_rate", "time_to_validated_finding", "resume_reliability", "scope-violation_rate", "evidence-completeness"],
        "benchmark_rule": "Never treat a module count or clean run as proof of capability.",
    }
    atomic_write_json(evidence / "benchmark-metrics-v311.json", out)
    return out
