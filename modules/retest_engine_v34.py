"""V3.4 deterministic finding retest comparison.

Compares normalized findings from two snapshots; it does not re-run attack
techniques and therefore cannot manufacture a remediation result.
"""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json

def _load(p):
    try:
        x=json.loads(Path(p).read_text(encoding="utf-8")); return x if isinstance(x,list) else []
    except (OSError,json.JSONDecodeError,UnicodeDecodeError): return []

def _key(x): return str(x.get("finding_id") or x.get("id") or x.get("title") or x.get("name") or "unknown").lower()

def compare(root: str|Path, baseline: str|Path, current: str|Path)->dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    old={_key(x):x for x in _load(baseline)}; new={_key(x):x for x in _load(current)}
    fixed=sorted(set(old)-set(new)); introduced=sorted(set(new)-set(old)); unchanged=sorted(set(old)&set(new))
    data={"schema_version":"3.4","status":"completed","fixed":fixed,"introduced":introduced,"unchanged":unchanged,"counts":{"fixed":len(fixed),"introduced":len(introduced),"unchanged":len(unchanged)},"limitations":["Absence from the current snapshot is not proof of remediation; verify with the appropriate authorized test."]}
    atomic_write_json(ev/"retest-comparison-v34.json",data); return data
