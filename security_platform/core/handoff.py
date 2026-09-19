from __future__ import annotations
from pathlib import Path
import hashlib, hmac, re
from .artifacts import write_json, read_json

SCHEMA_VERSION="1.2"
PRODUCER_RE=re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

def _canonical(payload):
    import json
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _producer(value: str) -> str:
    if not isinstance(value, str) or not PRODUCER_RE.fullmatch(value):
        raise ValueError("invalid handoff producer")
    return value

def publish(root, producer: str, payload: dict) -> Path:
    producer=_producer(producer)
    if not isinstance(payload, dict):
        raise TypeError("handoff payload must be an object")
    canonical = _canonical(payload)
    if len(canonical) > 4 * 1024 * 1024:
        raise ValueError("handoff payload exceeds 4 MiB limit")
    digest=hashlib.sha256(canonical).hexdigest()
    data={"schema_version":SCHEMA_VERSION,"producer":producer,"payload":payload,"payload_sha256":digest}
    return write_json(root, f"handoff-{producer}.json", data)

def load(root, producer: str) -> dict:
    try:
        producer=_producer(producer)
    except ValueError:
        return {}
    data=read_json(root, f"handoff-{producer}.json", {})
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION or data.get("producer") != producer:
        return {}
    payload=data.get("payload")
    expected=data.get("payload_sha256")
    if not isinstance(payload, dict) or not isinstance(expected, str):
        return {}
    actual=hashlib.sha256(_canonical(payload)).hexdigest()
    if not hmac.compare_digest(expected, actual):
        return {}
    return data
