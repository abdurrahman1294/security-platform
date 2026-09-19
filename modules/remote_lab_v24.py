"""Controlled remote-assessment proof layer for the disposable adversarial lab.

This module never accepts arbitrary commands/payloads. It only invokes fixed,
benign proof fixtures exposed by the local lab and records evidence.
"""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urljoin
from .lab_http import base, request

SCENARIOS = (
    "rce", "credential-exposure", "command-injection", "ssrf",
    "privilege-escalation", "persistence", "lateral-auth", "objective-access",
    "destructive-boundary",
)


def _write(out: Path, name: str, data: dict):
    p = out / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return p


def assess(out: Path, target: str, *, scenarios=(), authorized=False, execute=False,
           roe_permitted=False, internal_target="") -> dict:
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    evidence = {"schema_version": "remote-lab-24.1", "target": target,
                "authorized": bool(authorized), "execute": bool(execute), "results": []}
    try:
        b = base(target)
    except ValueError as exc:
        evidence["status"] = "blocked"; evidence["reason"] = str(exc)
        _write(out, "remote-assessment.json", evidence); return evidence
    chosen = tuple(scenarios) or SCENARIOS
    unknown = [s for s in chosen if s not in SCENARIOS]
    if unknown:
        evidence["status"] = "blocked"; evidence["reason"] = f"unknown scenarios: {unknown}"
        _write(out, "remote-assessment.json", evidence); return evidence
    if execute and (not authorized or not roe_permitted):
        evidence["status"] = "blocked"; evidence["reason"] = "execution requires authorization and ROE permission"
        _write(out, "remote-assessment.json", evidence); return evidence
    if not execute:
        evidence["status"] = "dry_run"
        evidence["results"] = [{"scenario": s, "status": "planned"} for s in chosen]
        _write(out, "remote-assessment.json", evidence); return evidence

    paths = {
        "rce": ("/lab/proof/rce", "RCE_CONFIRMED"),
        "credential-exposure": ("/lab/proof/credentials", "CREDENTIAL_EXPOSURE_CONFIRMED"),
        "command-injection": ("/lab/proof/command-injection", "COMMAND_INJECTION_CONFIRMED"),
        "ssrf": ("/lab/proof/ssrf", "SSRF_CONFIRMED"),
        "privilege-escalation": ("/lab/proof/privilege", "PRIVESC_CONFIRMED"),
        "persistence": ("/lab/proof/persistence", "PERSISTENCE_CONFIRMED"),
        "lateral-auth": ("/lab/proof/lateral", "LATERAL_AUTH_CONFIRMED"),
        "objective-access": ("/lab/proof/objective", "OBJECTIVE_ACCESS_CONFIRMED"),
        "destructive-boundary": ("/lab/proof/destructive", "DESTRUCTIVE_ACTION_BLOCKED"),
    }
    for scenario in chosen:
        path, marker = paths[scenario]
        r = request(urljoin(b + "/", path), method="GET", timeout=5, max_body=16384)
        body = r.get("body", "")
        evidence["results"].append({
            "scenario": scenario, "status": "confirmed" if marker in body else "not_confirmed",
            "http_status": r.get("status"), "marker": marker if marker in body else "",
            "response_excerpt": body[:512],
        })
    evidence["status"] = "completed"
    if internal_target:
        try:
            ib = base(internal_target)
            evidence["internal_target"] = ib
        except ValueError:
            evidence["internal_target"] = "rejected"
    _write(out, "remote-assessment.json", evidence)
    return evidence
