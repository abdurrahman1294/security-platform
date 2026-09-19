"""V234 universal OSINT result ingestion and normalization.
Accepts tool outputs produced by operator-selected tools without executing arbitrary commands.
"""
from __future__ import annotations
import csv, hashlib, json, re
from pathlib import Path
from datetime import datetime, timezone
from .atomic_io import atomic_write_json

SUPPORTED = {".json", ".jsonl", ".ndjson", ".csv", ".txt", ".tsv"}
MAX_INPUT_BYTES = 25 * 1024 * 1024
SECRET_PATTERNS = [re.compile(r"(?i)(api[_-]?key|secret|token|password|authorization)\s*[:=]\s*[^\s,}]{8,}")]

def _rows(path):
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input exceeds 25 MiB safety limit")
    text = path.read_text(errors="replace")
    if path.suffix == ".json":
        obj = json.loads(text)
        return obj if isinstance(obj, list) else [obj]
    if path.suffix in (".jsonl", ".ndjson"):
        return [json.loads(x) for x in text.splitlines() if x.strip()]
    if path.suffix in (".csv", ".tsv"):
        return list(csv.DictReader(text.splitlines(), delimiter="\t" if path.suffix == ".tsv" else ","))
    return [{"value": x.strip()} for x in text.splitlines() if x.strip()]

def _canonical(row):
    if isinstance(row, dict):
        value = row.get("url") or row.get("host") or row.get("domain") or row.get("name") or row.get("value") or row
        source = row.get("source") or row.get("tool") or "operator-tool"
    else:
        value, source = row, "operator-tool"
    canonical = str(value).strip().lower()
    raw_text = json.dumps(row, sort_keys=True) if isinstance(row, dict) else str(row)
    secret_like = any(p.search(raw_text) for p in SECRET_PATTERNS)
    safe_value = "[REDACTED-SENSITIVE-INDICATOR]" if secret_like else value
    return {"id": hashlib.sha256(canonical.encode()).hexdigest()[:20], "value": safe_value, "source": source, "raw_type": type(row).__name__, "sensitive_indicator": secret_like}

def ingest(root, paths):
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    records, errors, sources = [], [], []
    for raw in paths or []:
        p = Path(raw)
        if not p.is_file() or p.suffix.lower() not in SUPPORTED:
            errors.append({"path": str(p), "error": "unsupported_or_missing"}); continue
        try:
            rows = _rows(p); sources.append(str(p))
            records.extend(_canonical(r) for r in rows)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"path": str(p), "error": f"{type(exc).__name__}: {exc}"})
    dedup = {(r["id"], str(r.get("source"))): r for r in records}
    data = {"schema_version":"234.0","source_files":sources,"record_count":len(records),"unique_count":len({r["id"] for r in records}),"records":list(dedup.values()),"errors":errors,"ingested_at":datetime.now(timezone.utc).isoformat()}
    atomic_write_json(ev / "osint-ingest-v234.json", data)
    return data
