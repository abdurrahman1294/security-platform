"""Operational privacy and safety hygiene for authorized security engagements.

This module is deliberately NOT an anonymity or anti-forensics system. It helps
operators minimize accidental disclosure of personal identity, secrets and
machine metadata while preserving accountability and evidence integrity.
It never changes network routing, hides traffic, evades logging, or deletes
forensic records.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|cookie)")
PERSONAL_KEY_RE = re.compile(r"(?i)(email|phone|telephone|username|operator_name|real_name|home_address|personal_address)")
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]{12,}|(?:sk|ak|api|token|secret)[_-]?[A-Za-z0-9._-]{12,})")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def sanitize_for_export(value: Any, *, operator_alias: str = "operator") -> Any:
    """Return a JSON-safe copy with common secrets/personal fields redacted."""
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            k = str(key)
            if SECRET_KEY_RE.search(k):
                out[k] = "[REDACTED_SECRET]"
            elif PERSONAL_KEY_RE.search(k):
                out[k] = "[REDACTED_PERSONAL_DATA]"
            else:
                out[k] = sanitize_for_export(val, operator_alias=operator_alias)
        return out
    if isinstance(value, list):
        return [sanitize_for_export(x, operator_alias=operator_alias) for x in value]
    if isinstance(value, str):
        s = value
        if operator_alias and operator_alias != "operator":
            s = s.replace(operator_alias, "operator")
        s = SECRET_VALUE_RE.sub("[REDACTED_SECRET]", s)
        return s
    return value


def audit_artifacts(root: str | Path) -> dict[str, Any]:
    """Audit an engagement output tree for accidental disclosure indicators.

    Evidence is never modified. Findings are metadata-only and include hashes,
    not the sensitive values themselves.
    """
    root = Path(root).resolve()
    result: dict[str, Any] = {
        "schema_version": "opsec-25.1",
        "root": str(root),
        "status": "completed",
        "files_scanned": 0,
        "findings": [],
        "principles": [
            "minimize personal data in exported artifacts",
            "keep secrets out of logs and reports",
            "preserve original evidence and accountability records",
            "do not attempt anti-forensics or traffic-evasion",
        ],
    }
    if not root.is_dir():
        result.update(status="blocked", reason="engagement output directory does not exist")
        return result
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        result["files_scanned"] += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = []
        for i, line in enumerate(text.splitlines(), 1):
            if SECRET_KEY_RE.search(line) or SECRET_VALUE_RE.search(line):
                hits.append({"line": i, "type": "secret-indicator", "fingerprint": _digest(line)})
            if PERSONAL_KEY_RE.search(line):
                hits.append({"line": i, "type": "personal-data-indicator", "fingerprint": _digest(line)})
        if hits:
            result["findings"].append({"path": str(path.relative_to(root)), "hits": hits[:20]})
    if result["findings"]:
        result["status"] = "attention"
    return result


def build_posture(output: str | Path, *, operator_alias: str = "operator", export_path: str | Path | None = None) -> dict[str, Any]:
    """Create a privacy/OPSEC posture report without collecting personal identity."""
    output = Path(output).resolve()
    audit = audit_artifacts(output)
    posture = {
        "schema_version": "opsec-25.1",
        "mode": "privacy-hygiene",
        "operator_alias": "operator" if not operator_alias else operator_alias[:64],
        "absolute_anonymity": False,
        "accountability_required": True,
        "network_anonymization": "not provided",
        "anti_forensics": False,
        "artifact_audit": audit,
        "recommended_controls": [
            "use dedicated authorized assessment accounts and infrastructure",
            "store credentials only in approved secret stores or environment variables",
            "review exported reports for personal metadata before sharing",
            "keep engagement evidence immutable and auditable",
            "separate personal accounts from operational accounts",
            "use an emergency stop and revoke operational credentials after suspected compromise",
        ],
    }
    destination = Path(export_path) if export_path else output / "evidence" / "opsec-posture-v25.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(posture, indent=2, sort_keys=True), encoding="utf-8")
    return posture
