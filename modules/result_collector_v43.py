#!/usr/bin/env python3
"""V43 result collector/normalizer for external assessment tools."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from datetime import datetime, timezone

SECRET_PATTERNS=[re.compile(r'(?i)(authorization\s*:\s*bearer\s+)[^\s]+'), re.compile(r'(?i)(cookie\s*[:=]\s*)[^\s]+')]
def sanitize(text: str)->str:
    out=text
    for p in SECRET_PATTERNS: out=p.sub(r'\1[REDACTED]',out)
    return out

def collect(root: str|Path, task: dict, stdout: str, stderr: str, returncode: int|None, *, command: list[str]):
    root=Path(root); (root/"evidence"/"pipeline-results").mkdir(parents=True,exist_ok=True)
    safe_out=sanitize(stdout or ""); safe_err=sanitize(stderr or "")
    record={"schema_version":"43.0","task_id":task["task_id"],"action":task["action"],"tool":task["tool"],
            "command":[str(x) for x in command],"returncode":returncode,"status":"completed" if returncode==0 else "failed",
            "collected":datetime.now(timezone.utc).isoformat(),"stdout_sha256":hashlib.sha256(safe_out.encode()).hexdigest(),
            "stderr_sha256":hashlib.sha256(safe_err.encode()).hexdigest(),"stdout":safe_out,"stderr":safe_err}
    path=root/"evidence"/"pipeline-results"/(task["task_id"]+".json")
    path.write_text(json.dumps(record,indent=2),encoding="utf-8")
    return path

def load_results(root: str|Path):
    d=Path(root)/"evidence"/"pipeline-results"
    rows=[]
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try: rows.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError): pass
    return rows
