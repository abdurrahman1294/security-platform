#!/usr/bin/env python3
"""False-positive reduction and finding state normalization."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


VALID_STATES = {"observed", "suspected", "confirmed", "false_positive", "inconclusive"}


def normalize_state(value: str | None) -> str:
    v = (value or "observed").strip().lower().replace("-", "_")
    if v in VALID_STATES:
        return v
    if v in {"fp", "falsepositive"}:
        return "false_positive"
    return "observed"


def _finding_key(f: dict[str, Any]) -> str:
    info = f.get("info") if isinstance(f.get("info"), dict) else {}
    name = str(info.get("name") or f.get("name") or f.get("template-id") or "unknown")
    host = str(f.get("matched-at") or f.get("host") or "")
    return f"{name}|{host}".lower()


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for f in findings:
        k = _finding_key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def score_confidence(f: dict[str, Any]) -> float:
    """Heuristic confidence 0..1 before human validation."""
    score = 0.4
    info = f.get("info") if isinstance(f.get("info"), dict) else {}
    sev = str(info.get("severity") or "").lower()
    if sev in {"critical", "high"}:
        score += 0.2
    if f.get("matched-at") or f.get("host"):
        score += 0.1
    if f.get("evidence") or f.get("request") or f.get("response"):
        score += 0.2
    name = str(info.get("name") or "")
    if re.search(r"detect|tech|wordpress|nginx|apache", name, re.I):
        score -= 0.1  # informational detections are weaker as vulns
    return max(0.0, min(1.0, score))


def classify_finding(f: dict[str, Any]) -> dict[str, Any]:
    item = dict(f)
    conf = score_confidence(item)
    item["_confidence"] = conf
    if conf >= 0.75:
        item["_state"] = "suspected"
    elif conf <= 0.25:
        item["_state"] = "inconclusive"
    else:
        item["_state"] = "observed"
    # never auto-confirm
    if item.get("_state") == "confirmed":
        item["_state"] = "suspected"
    return item


def process_findings_file(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    cleaned = dedupe_findings([classify_finding(x) for x in data if isinstance(x, dict)])
    return cleaned


def reduce_outdir(outdir: str | Path) -> dict[str, Any]:
    root = Path(outdir)
    results = {}
    total = []
    for rel in [
        "vulns/findings.json",
        "api/api-findings.json",
        "vulns/authenticated-findings.json",
    ]:
        p = root / rel
        items = process_findings_file(p)
        if items:
            outp = p.with_name(p.stem + ".normalized.json")
            outp.write_text(json.dumps(items, indent=2), encoding="utf-8")
            results[rel] = {"count": len(items), "normalized": str(outp)}
            total.extend(items)
    return {
        "files": results,
        "total_findings": len(total),
        "states": {
            st: sum(1 for x in total if x.get("_state") == st)
            for st in sorted({x.get("_state", "observed") for x in total})
        },
    }
