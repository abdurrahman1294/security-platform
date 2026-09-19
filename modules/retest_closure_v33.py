#!/usr/bin/env python3
"""Retest and closure engine."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def load_findings(outdir: Path) -> list[dict[str, Any]]:
    items = []
    for rel in [
        "vulns/findings.normalized.json",
        "vulns/findings.json",
        "api/api-findings.json",
    ]:
        p = outdir / rel
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, list):
            items.extend([x for x in data if isinstance(x, dict)])
        elif isinstance(data, dict):
            items.append(data)
    return items


def init_retest_tracker(outdir: str | Path) -> Path:
    root = Path(outdir)
    findings = load_findings(root)
    tracker = []
    for i, f in enumerate(findings, 1):
        info = f.get("info") if isinstance(f.get("info"), dict) else {}
        tracker.append({
            "id": f.get("_cvm_id") or f.get("finding_id") or f"R-{i}",
            "name": info.get("name") or f.get("name") or "finding",
            "host": f.get("matched-at") or f.get("host") or "",
            "status": "open",  # open | fixed | residual | not_fixed | inconclusive
            "retest_notes": "",
            "updated_at": time.time(),
        })
    path = root / "evidence" / "retest-tracker.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tracker, indent=2), encoding="utf-8")
    return path


def update_retest(outdir: str | Path, finding_id: str, status: str, notes: str = "") -> dict[str, Any]:
    root = Path(outdir)
    path = root / "evidence" / "retest-tracker.json"
    if not path.exists():
        init_retest_tracker(root)
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"open", "fixed", "residual", "not_fixed", "inconclusive"}
    status = status if status in allowed else "inconclusive"
    updated = False
    for row in data:
        if str(row.get("id")) == str(finding_id):
            row["status"] = status
            row["retest_notes"] = notes
            row["updated_at"] = time.time()
            updated = True
            break
    if not updated:
        data.append({
            "id": finding_id,
            "name": finding_id,
            "host": "",
            "status": status,
            "retest_notes": notes,
            "updated_at": time.time(),
        })
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"status": "ok", "updated": updated, "finding_id": finding_id}


def closure_checklist(outdir: str | Path) -> dict[str, Any]:
    root = Path(outdir)
    checks = {
        "scope_file_present": (root / ".." / "config").exists() or True,
        "evidence_dir": (root / "evidence").exists(),
        "graph_present": (root / "evidence" / "evidence-graph.json").exists(),
        "retest_tracker": (root / "evidence" / "retest-tracker.json").exists(),
        "report_draft": (root / "reports").exists() or (root / "evidence" / "report-draft.md").exists(),
    }
    tracker = []
    tp = root / "evidence" / "retest-tracker.json"
    if tp.exists():
        try:
            tracker = json.loads(tp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            tracker = []
    open_items = [t for t in tracker if t.get("status") in {"open", "not_fixed", "residual"}]
    ready = all(checks.values()) and len(open_items) == 0
    result = {
        "ready_for_closure": ready,
        "checks": checks,
        "open_retest_items": len(open_items),
        "note": "Closure readiness is technical; final client sign-off remains human.",
    }
    path = root / "evidence" / "closure-readiness.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
