#!/usr/bin/env python3
"""V25 finding deduplication and lifecycle history. No target interaction."""
from __future__ import annotations
import hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

from .atomic_io import atomic_write_json, atomic_write_text, load_json


def norm_title(s):
    s = re.sub(r"[^a-z0-9 ]+", " ", str(s).lower())
    return re.sub(r"\s+", " ", s).strip()


def _finding_id(f):
    """A finding missing 'normalized_id' previously raised a bare
    KeyError and aborted the entire dedup run over one malformed record.
    Fall back to a stable id derived from the record's own content so
    the rest of the batch still gets processed and reported."""
    fid = f.get("normalized_id")
    if fid:
        return fid, False
    seed = json.dumps(f, sort_keys=True, default=str)
    return "D-UNIDENTIFIED-" + hashlib.sha256(seed.encode()).hexdigest()[:10], True


def build(root):
    root = Path(root)
    ev = root / "evidence"
    rep = root / "reports"
    ev.mkdir(parents=True, exist_ok=True)
    rep.mkdir(parents=True, exist_ok=True)

    data = load_json(ev / "normalized-findings.json", {"findings": []})
    findings = data.get("findings", []) if isinstance(data, dict) else []

    groups = {}
    fallback_count = 0
    id_cache = {}
    for f in findings:
        fid, was_fallback = _finding_id(f)
        id_cache[id(f)] = fid
        if was_fallback:
            fallback_count += 1
        key = (norm_title(f.get("title")), f.get("asset"), f.get("severity"))
        groups.setdefault(key, []).append(fid)

    clusters = []
    duplicates = []
    for key, ids in groups.items():
        cid = "D-" + hashlib.sha256("|".join(sorted(ids)).encode()).hexdigest()[:10]
        primary = ids[0]
        clusters.append({"cluster_id": cid, "primary": primary, "finding_ids": ids, "reason": "normalized title + asset + severity"})
        duplicates += [{"finding_id": x, "primary": primary, "status": "possible-duplicate", "confidence": 0.9} for x in ids[1:]]

    history = load_json(ev / "finding-history.json", {})
    if not isinstance(history, dict):
        history = {}
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        fid = id_cache[id(f)]
        h = history.setdefault(fid, {"finding_id": fid, "events": []})
        fingerprint = hashlib.sha256(json.dumps(f, sort_keys=True, default=str).encode()).hexdigest()
        if not h["events"] or h["events"][-1].get("fingerprint") != fingerprint:
            h["events"].append({
                "timestamp": now, "event": "observed", "fingerprint": fingerprint,
                "severity": f.get("severity"), "asset": f.get("asset"),
            })

    payload = {
        "schema_version": "1.1", "generated_at": now,
        "clusters": clusters, "possible_duplicates": duplicates, "history": history,
        "unidentified_findings": fallback_count,
    }
    p = ev / "finding-dedup.json"
    atomic_write_json(p, payload)
    atomic_write_json(ev / "finding-history.json", history)

    lines = ["# V25 Finding Deduplication & Lifecycle", "", f"Clusters: **{len(clusters)}**", f"Possible duplicate records: **{len(duplicates)}**"]
    if fallback_count:
        lines.append(f"Findings missing a `normalized_id` (assigned a fallback id): **{fallback_count}**")
    lines += ["", "> Duplicate relationships are analyst-review hypotheses; no finding is deleted automatically.", ""]
    for c in clusters:
        lines.append(f"- `{c['cluster_id']}` primary `{c['primary']}`: " + ", ".join(f"`{x}`" for x in c["finding_ids"]))
    atomic_write_text(rep / "finding-dedup.md", "\n".join(lines) + "\n")
    return p
