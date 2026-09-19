"""Shared evidence-driven policy evaluation helpers for the V171-V210 layer.

These helpers keep policy catalogs honest: a policy artifact records both the
static rules and the observed engagement context used to evaluate them.
"""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from .atomic_io import atomic_write_json, load_json
from .findings_io import load_findings_file


def context(root: str | Path) -> dict:
    root = Path(root)
    ev = root / "evidence"
    artifacts = [p for p in ev.rglob("*") if p.is_file()] if ev.exists() else []
    findings = []
    for p in (root / "vulns" / "findings.json", ev / "normalized-findings.json", root / "api" / "api-findings.json"):
        findings.extend(load_findings_file(p))
    return {
        "artifact_count": len(artifacts),
        "evidence_json_count": sum(p.suffix == ".json" for p in artifacts),
        "finding_count": len(findings),
        "has_scope": any(p.name in {"scope.csv", "scope.txt", "scope.example.txt"} for p in artifacts),
        "has_execution_state": (ev / "execution-state-v101.json").exists(),
        "has_tool_ledger": (ev / "tool-execution-ledger-v40.json").exists(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_policy(root: str | Path, filename: str, version: str, purpose: str, rules: list[str], *, evaluation=None) -> dict:
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    ctx = context(root)
    result = evaluation(ctx) if evaluation else {"decision": "POLICY_ONLY"}
    data = {"schema_version": version, "purpose": purpose, "rules": rules, "context": ctx, "evaluation": result}
    atomic_write_json(ev / filename, data)
    return data


def load_artifact(root: str | Path, filename: str, default=None):
    return load_json(Path(root) / "evidence" / filename, default)
