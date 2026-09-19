"""V3.49 end-to-end range assurance gate.

Combines the disposable validation campaigns into one auditable gate. The gate
measures fixture/range effectiveness, resilience, governance, artifact
integrity, and tool readiness without claiming universal real-world coverage.
No new offensive execution path is introduced.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, json, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.49.0"
REQUIRED_DOMAINS = (
    "web-api","network","identity","cloud","endpoint","mobile","wireless",
    "firmware-iot","ot-ics","automotive","containers","source-supply-chain",
    "reverse-engineering","data","ai-ml","telecom",
)

def _id(*p):
    return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]

def _write(root: Path, name: str, obj):
    p = root / "evidence" / name
    atomic_write(p, redact(obj))
    return p

def _tool_readiness(repo_root: Path) -> dict:
    try:
        from security_platform.core.tools import inventory
        rows = [x.__dict__ for x in inventory()]
    except Exception as exc:
        rows = []
        error = type(exc).__name__
    else:
        error = ""
    ready = sum(1 for x in rows if x.get("status") == "ready")
    return {"tool_count": len(rows), "ready": ready, "unavailable_or_rejected": sum(1 for x in rows if x.get("status") == "unavailable-or-rejected"), "identity_failed": sum(1 for x in rows if x.get("status") == "identity-failed"), "errors": sum(1 for x in rows if x.get("status") == "error"), "inventory_error": error}

def build_gate(root: str | Path, *, repo_root: str | Path | None = None, multi_report: dict | None = None, resilience: dict | None = None) -> dict:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    if multi_report is None:
        from modules.multi_target_integration_v348 import run_multi_target_campaign
        multi_report = run_multi_target_campaign(root / "multi-target")
    if resilience is None:
        from modules.campaign_resilience_v347 import run_resilience_checks
        resilience = run_resilience_checks(root / "resilience")

    summary = multi_report.get("summary", {})
    total = int(summary.get("total", 0)); tp = int(summary.get("true_positives", 0)); misses = int(summary.get("misses", 0)); fps = int(summary.get("false_positives", 0))
    domain_rows = multi_report.get("targets", {})
    covered = sum(1 for d in REQUIRED_DOMAINS if int(domain_rows.get(d, {}).get("total", 0)) > 0)
    domain_coverage = covered / len(REQUIRED_DOMAINS)
    detection = tp / total if total else 0.0
    false_positive_control = 1.0 if fps == 0 else 0.0
    resilience_ok = bool(resilience.get("properties", {}).get("no_silent_success") and resilience.get("properties", {}).get("preserve_partial_evidence"))
    governance = 1.0 if all(multi_report.get("safety", {}).get(k) for k in ("loopback_only","synthetic_data_only")) else 0.0
    resilience_score = 1.0 if resilience_ok else 0.0
    score = round(100 * (0.45*detection + 0.20*domain_coverage + 0.15*false_positive_control + 0.10*resilience_score + 0.10*governance), 2)
    result = {
        "schema_version": VERSION,
        "gate": "end-to-end-local-range-assurance",
        "status": "PASS" if (total > 0 and misses == 0 and fps == 0 and resilience_ok and governance == 1.0) else "FAIL",
        "score": score,
        "components": {"detection": round(detection,4), "domain_coverage": round(domain_coverage,4), "false_positive_control": false_positive_control, "resilience": resilience_score, "governance": governance},
        "range_summary": {"total": total, "true_positives": tp, "misses": misses, "false_positives": fps, "targets": len(domain_rows)},
        "required_domains": list(REQUIRED_DOMAINS),
        "covered_domains": sorted(d for d in REQUIRED_DOMAINS if int(domain_rows.get(d, {}).get("total", 0)) > 0),
        "missing_domains": sorted(d for d in REQUIRED_DOMAINS if int(domain_rows.get(d, {}).get("total", 0)) == 0),
        "tool_readiness": _tool_readiness(Path(repo_root) if repo_root else Path.cwd()),
        "regression_baseline": {"v343_capabilities": 116, "v344_realistic_scenarios": 14, "v348_multi_target_scenarios": 36, "required_misses": 0, "required_false_positives": 0},
        "safety": {"loopback_only": True, "external_targets": False, "synthetic_data_only": True, "no_unrestricted_offensive_runtime": True},
        "limitations": ["This is a local validation gate, not a universal real-world detection benchmark.", "Tool readiness is inventory-only; unavailable specialist tools are reported rather than replaced by unsafe generic execution.", "Representative synthetic targets do not replace real Windows/AD, wireless, OT, automotive, device, cloud-provider, or mobile ranges."],
        "created_at": time.time(),
    }
    _write(root, "range-assurance-gate-v349.json", result)
    return result

def v349_test_matrix():
    names = ["end-to-end-gate","detection-component","domain-coverage","false-positive-control","resilience-component","governance-component","tool-readiness","regression-baseline","missing-domain-reporting","target-accounting","loopback-safety","synthetic-data-boundary","no-unrestricted-runtime","machine-readable","atomic-artifact","secret-redaction","pass-fail-gate","zero-total-safe","reproducible-schema","limitations-explicit"]
    return {"schema_version": VERSION, "scenario_count": len(names), "scenarios": [{"id": _id("v349", n), "name": n, "expected": "pass"} for n in names]}
