"""V235 cross-source OSINT correlation and confidence scoring."""
from __future__ import annotations
import json
from pathlib import Path
from collections import defaultdict
from .atomic_io import atomic_write_json, load_json

def build(root):
    root = Path(root); ev = root / "evidence"; data = load_json(ev / "osint-ingest-v234.json", {})
    groups = defaultdict(list)
    for r in data.get("records", []): groups[str(r.get("value", "")).strip().lower()].append(r)
    entities=[]
    for value, rows in groups.items():
        if not value: continue
        sources=sorted({str(r.get("source")) for r in rows})
        confidence="high" if len(sources)>=2 else "medium" if rows else "low"
        entities.append({"value":value,"sources":sources,"evidence_count":len(rows),"confidence":confidence})
    out={"schema_version":"235.0","entity_count":len(entities),"entities":entities,"confidence_policy":"high requires independent sources; single-source claims remain provisional"}
    atomic_write_json(ev / "osint-correlation-v235.json", out); return out
