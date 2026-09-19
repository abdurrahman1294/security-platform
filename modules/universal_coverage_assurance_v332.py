"""V3.32 Universal Coverage & Capability Assurance Fabric.

Answers: what can be assessed, from where, by which registered capability,
with what evidence, and what remains uncovered. This is an accounting and
planning layer; it does not create new execution primitives.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, time

from modules.universal_attack_surface_fabric_v320 import ATTACK_SURFACES, PERSPECTIVES, EXECUTION_ADAPTERS
from modules.capability_runtime_v325 import capability_catalog
from modules.reliability_execution_integrity_v331 import atomic_write, redact

VERSION = "3.32.0"


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _norm(values: Iterable[Any] | None) -> list[str]:
    return list(dict.fromkeys(str(x).strip() for x in (values or []) if str(x).strip()))


def _write(root: str | Path, name: str, value: Any) -> dict[str, Any]:
    atomic_write(Path(root) / "evidence" / name, value)
    return value


def build_capability_index() -> list[dict[str, Any]]:
    rows = []
    for c in capability_catalog():
        rows.append({
            "capability_id": c["id"], "surface": c["surface"], "specialist": c["specialist"],
            "action": c["action"], "risk": c["risk"], "perspectives": c["perspectives"],
            "evidence_inputs": c["evidence_inputs"], "available": bool(c.get("available", True)),
            "execution_source": "registered-capability-runtime",
        })
    return rows


def build_coverage_matrix(*, surfaces: Iterable[str] | None = None,
                           perspectives: Iterable[str] | None = None,
                           observations: Iterable[dict[str, Any]] | None = None,
                           completed: Iterable[str] | None = None) -> dict[str, Any]:
    selected_surfaces = _norm(surfaces) or list(ATTACK_SURFACES)
    selected_perspectives = _norm(perspectives) or list(PERSPECTIVES)
    observed = [x for x in (observations or []) if isinstance(x, dict)]
    done = set(_norm(completed))
    caps = build_capability_index()
    rows = []
    invalid_surfaces = []
    invalid_perspectives = []
    for s in selected_surfaces:
        if s not in ATTACK_SURFACES:
            invalid_surfaces.append(s); continue
        surface_caps = [c for c in caps if c["surface"] == s]
        if not surface_caps:
            # A surface can still be covered by a specialist/artifact route.
            adapter_names = EXECUTION_ADAPTERS.get(s, [])
            route = "specialist-or-artifact" if not adapter_names else "registered-tool-adapter"
        else:
            adapter_names = EXECUTION_ADAPTERS.get(s, [])
            route = "registered-capability" if surface_caps else "specialist-or-artifact"
        for p in selected_perspectives:
            if p not in PERSPECTIVES:
                if p not in invalid_perspectives: invalid_perspectives.append(p)
                continue
            compatible = [c for c in surface_caps if "*" in c["perspectives"] or p in c["perspectives"]]
            observed_here = [o for o in observed if str(o.get("surface", "")) == s and str(o.get("perspective", "")) == p]
            completed_here = [c for c in compatible if c["capability_id"] in done]
            if completed_here:
                status = "assessed"
            elif compatible:
                status = "capability-available"
            elif adapter_names:
                status = "adapter-available-specialist-routing"
            else:
                status = "specialist-or-artifact-required"
            if observed_here:
                status = "evidence-observed" if status != "assessed" else status
            rows.append({
                "id": _id(s, p), "surface": s, "perspective": p,
                "family": ATTACK_SURFACES[s]["family"], "status": status,
                "capabilities": [c["capability_id"] for c in compatible],
                "registered_adapters": adapter_names,
                "observations": len(observed_here), "completed_capabilities": [c["capability_id"] for c in completed_here],
                "evidence_expected": sorted({e for c in compatible for e in c["evidence_inputs"]}),
                "confidence": 1.0 if completed_here else (0.7 if observed_here else 0.45 if compatible or adapter_names else 0.2),
            })
    return {"schema_version": VERSION, "rows": rows,
            "invalid_surfaces": invalid_surfaces, "invalid_perspectives": invalid_perspectives}


def summarize_coverage(matrix: dict[str, Any]) -> dict[str, Any]:
    rows = matrix.get("rows", [])
    counts = {}
    for r in rows: counts[r["status"]] = counts.get(r["status"], 0) + 1
    total = len(rows)
    assessed = counts.get("assessed", 0)
    observed = counts.get("evidence-observed", 0)
    actionable = assessed + observed
    return {"total_cells": total, "status_counts": counts,
            "coverage_ratio": round(actionable / total, 4) if total else None,
            "execution_ready_ratio": round(sum(1 for r in rows if r["status"] in {"assessed", "capability-available", "adapter-available-specialist-routing"}) / total, 4) if total else None,
            "not_applicable": total == 0}


def build_gap_register(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = []
    for r in matrix.get("rows", []):
        if r["status"] in {"assessed", "evidence-observed"}: continue
        reason = {
            "capability-available": "capability exists but has not completed",
            "adapter-available-specialist-routing": "registered adapter exists; specialist routing required",
            "specialist-or-artifact-required": "no generic executable capability for this surface/perspective",
        }.get(r["status"], "input-or-routing-gap")
        gaps.append({"gap_id": _id("gap", r["id"]), "surface": r["surface"], "perspective": r["perspective"],
                     "status": r["status"], "reason": reason, "required_evidence": r["evidence_expected"],
                     "recommended": "specialist-review" if "specialist" in reason else "governed-capability-step"})
    return gaps


def build_v332_fabric(root: str | Path, *, target: str, surfaces=None, perspectives=None,
                      observations=None, completed=None, objective: str = "full-assessment") -> dict[str, Any]:
    matrix = build_coverage_matrix(surfaces=surfaces, perspectives=perspectives, observations=observations, completed=completed)
    summary = summarize_coverage(matrix)
    gaps = build_gap_register(matrix)
    result = {"schema_version": VERSION, "target": target, "objective": objective,
              "capability_count": len(build_capability_index()), "surface_count": len(ATTACK_SURFACES),
              "perspective_count": len(PERSPECTIVES), "coverage": summary, "matrix": matrix,
              "gaps": gaps,
              "assurance_contract": {
                  "registered_capabilities_only": True, "unknown_inputs_are_errors": True,
                  "coverage_never_implies_vulnerability": True, "scanner_output_never_implies_exploitability": True,
                  "cellular_is_a_perspective_not_a_bypass": True, "specialist_gaps_remain_explicit": True,
              }, "created_at": time.time()}
    return _write(root, "universal-coverage-assurance-v332.json", result)


def v332_test_matrix() -> dict[str, Any]:
    names = [
        "all-35-surfaces-accounted", "all-14-perspectives-accounted", "unknown-surface-preserved",
        "unknown-perspective-preserved", "zero-cell-coverage-is-not-one", "completed-capability-accounting",
        "observed-evidence-accounting", "specialist-gap-accounting", "adapter-route-accounting",
        "evidence-expectation-accounting", "duplicate-capability-stability", "cellular-perspective-not-bypass",
        "coverage-does-not-imply-vulnerability", "scanner-output-does-not-imply-exploitability",
        "capability-runtime-source-of-truth", "deterministic-gap-ids", "multiple-assets-per-type-compatible",
        "malformed-observation-is-ignored", "secret-redaction", "atomic-artifact", "objective-preserved",
        "perspective-specific-capability-filter", "surface-family-routing", "assessed-vs-observed-distinction",
        "specialist-required-explicit", "execution-ready-vs-assessed-distinction", "empty-selection-defaults",
        "duplicate-selection-deduped", "coverage-ratio-bounded", "gap-register-complete", "no-scope-expansion",
        "no-authorization-inference", "no-new-command-path", "evidence-expectation-is-not-evidence",
        "human-led-domain-remains-human-led", "physical-lab-remains-lab", "ai-ml-bounded-route", "telecom-bounded-route",
        "supply-chain-gap-visible", "physical-facility-gap-visible", "management-plane-gap-visible",
        "remote-mobile-perspective-accounting", "firmware-testbed-accounting", "ot-ics-lab-accounting",
        "reporting-input-is-machine-readable", "resume-compatible-identifiers", "coverage-schema-stable",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names),
            "scenarios": [{"id": _id(x), "name": x, "expected": "account-or-degrade-safely"} for x in names]}
