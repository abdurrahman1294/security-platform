from __future__ import annotations
"""Adaptive, evidence-driven assessment planning.

This layer does not invent exploitation. It turns observed artifacts into
bounded hypotheses and low-risk experiments, then escalates unsupported or
high-impact work to a human operator.
"""
import json, re
from pathlib import Path
from typing import Any
from .atomic_io import atomic_write_json

VERSION = "2.8"

SECRET_RE = re.compile(r"(password|passwd|secret|token|cookie|authorization|api[_-]?key|private[_-]?key)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b|\b(?:127\.0\.0\.1|localhost)\b", re.I)

RULES = [
    ("auth-state", re.compile(r"\b(login|signin|logout|session|oauth|sso|jwt|bearer|cookie)\b", re.I),
     "authentication or session state detected", "map authentication states and review session transitions"),
    ("api-surface", re.compile(r"\b(openapi|swagger|graphql|/api/|api/v\d+)\b", re.I),
     "API surface indicator detected", "inventory endpoints and review object/function authorization boundaries"),
    ("custom-protocol", re.compile(r"\b(?:unknown protocol|custom protocol|tcp/\d+|udp/\d+)\b", re.I),
     "non-standard protocol indicator detected", "perform bounded banner/protocol characterization"),
    ("workflow-state", re.compile(r"\b(workflow|state transition|checkout|approval|reset|invite|transfer)\b", re.I),
     "stateful workflow indicator detected", "model state transitions and test authorization/invariant boundaries"),
    ("cloud-trust", re.compile(r"\b(aws|azure|gcp|iam|role|security group|s3|bucket|vpc)\b", re.I),
     "cloud identity/resource indicator detected", "build identity-to-resource trust graph using read-only inventory"),
    ("mobile", re.compile(r"\b(android|apk|manifest|webview|adb|ios|mobile)\b", re.I),
     "mobile artifact indicator detected", "select platform-specific static/read-only dynamic analysis"),
    ("wireless", re.compile(r"\b(wifi|wi-fi|pcap|bssid|ssid|802\.11|bluetooth|ble)\b", re.I),
     "wireless artifact indicator detected", "perform passive interface/PCAP characterization"),
    ("binary", re.compile(r"\b(elf|pe32|mach-o|binary|executable|\.so|\.dll|\.exe)\b", re.I),
     "binary artifact indicator detected", "perform bounded static triage and identify dynamic-analysis needs"),
]

EXPERIMENTS = {
    "auth-state": ("state-model", "Review observed authentication artifacts and enumerate states; no credential guessing.", "low"),
    "api-surface": ("api-inventory", "Normalize discovered API endpoints/schemas and identify authorization review points.", "low"),
    "custom-protocol": ("protocol-characterization", "Collect only bounded service metadata already authorized by scope; no payload fuzzing.", "low"),
    "workflow-state": ("workflow-model", "Construct a state-transition model from observed application behavior.", "low"),
    "cloud-trust": ("cloud-readonly-graph", "Correlate read-only identity/resource observations without changing cloud state.", "low"),
    "mobile": ("mobile-triage", "Run available static/read-only mobile analysis and record tool gaps.", "low"),
    "wireless": ("passive-radio-analysis", "Analyze interface capabilities or supplied captures only.", "low"),
    "binary": ("binary-static-triage", "Inventory architecture, strings/import indicators and metadata without executing the binary.", "low"),
}


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if SECRET_RE.search(str(k)) else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def _read_artifacts(root: Path, limit_files: int = 300, max_bytes: int = 512_000) -> list[dict[str, Any]]:
    observations = []
    count = 0
    for p in sorted(root.rglob("*")):
        if count >= limit_files or not p.is_file() or p.name.startswith("adaptive-assessment"):
            continue
        if any(x in p.parts for x in (".git", ".pytest_cache")):
            continue
        try:
            size = p.stat().st_size
            if size > max_bytes:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        observations.append({"path": str(p.relative_to(root)), "text": text[:max_bytes]})
        count += 1
    return observations


def _classify(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: dict[str, dict[str, Any]] = {}
    for obs in observations:
        text = obs["text"]
        for kind, pattern, rationale, recommendation in RULES:
            if pattern.search(text):
                item = hits.setdefault(kind, {"kind": kind, "rationale": rationale, "recommendation": recommendation, "sources": []})
                if len(item["sources"]) < 20:
                    item["sources"].append(obs["path"])
    return sorted(hits.values(), key=lambda x: x["kind"])


def _hypotheses(classes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i, c in enumerate(classes, 1):
        exp = EXPERIMENTS.get(c["kind"])
        if not exp:
            continue
        out.append({
            "hypothesis_id": f"AH-{i:03d}",
            "kind": c["kind"],
            "statement": f"Observed evidence may indicate a {c['kind']} assessment path worth investigating.",
            "confidence": "candidate",
            "sources": c["sources"],
            "status": "hypothesis",
            "not_a_finding": True,
            "recommended_experiment": exp[0],
        })
    return out


def _plan(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    plans = []
    for h in hypotheses:
        name, action, risk = EXPERIMENTS[h["kind"]]
        plans.append({
            "hypothesis_id": h["hypothesis_id"],
            "experiment": name,
            "action": action,
            "risk": risk,
            "authorization": "existing scope/ROE still required",
            "auto_execute": False,
            "human_approval_required": True,
            "fallback": "collect more passive evidence or escalate to operator",
        })
    return plans


def build(root: str | Path, *, target: str = "", scope: str = "", authorized: bool = False) -> dict:
    root = Path(root)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    observations = _read_artifacts(root)
    classes = _classify(observations)
    hypotheses = _hypotheses(classes)
    plans = _plan(hypotheses)
    urls = sorted({u.rstrip(".,)") for o in observations for u in URL_RE.findall(o["text"])})[:1000]
    hosts = sorted({h for o in observations for h in HOST_RE.findall(o["text"])})[:1000]
    unsupported = []
    if not classes:
        unsupported.append("No recognizable behavioral indicators were found; manual characterization is required.")
    if any(c["kind"] == "custom-protocol" for c in classes):
        unsupported.append("Unknown/custom protocol requires operator-guided characterization beyond generic heuristics.")
    if any(c["kind"] == "binary" for c in classes):
        unsupported.append("Deep reverse engineering is outside this adaptive layer; static triage is bounded and non-executing.")
    data = {
        "schema_version": VERSION,
        "target": target,
        "scope": scope,
        "authorized_context": bool(authorized),
        "observation_count": len(observations),
        "environment": {"hosts": hosts, "urls": urls},
        "classifications": classes,
        "hypotheses": hypotheses,
        "experiment_plan": plans,
        "escalations": unsupported,
        "decision_policy": {
            "principle": "Observe -> classify -> hypothesize -> select bounded experiment -> re-evaluate.",
            "unknown_defaults_to_human": True,
            "no_arbitrary_payloads": True,
            "no_credential_guessing": True,
            "no_scope_expansion": True,
            "no_high_impact_auto_execution": True,
        },
        "privacy": "Only bounded artifact text is analyzed and common secret-key fields are redacted in generated output.",
    }
    atomic_write_json(evidence / "adaptive-assessment-v28.json", _redact(data))
    return data
