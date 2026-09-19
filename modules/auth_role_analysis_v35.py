"""V3.5 authenticated multi-role evidence analysis.

Consumes operator-produced role test results and highlights inconsistent
authorization behavior. It does not generate or execute attack requests.
"""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json

def build(root: str|Path, input_path: str|Path|None=None) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    p=Path(input_path) if input_path else ev/"role-test-results.json"
    try: doc=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError): doc={"tests":[]}
    tests=doc if isinstance(doc,list) else doc.get("tests",[]) if isinstance(doc,dict) else []
    findings=[]
    for t in tests:
        if not isinstance(t,dict): continue
        expected=str(t.get("expected") or "deny").lower(); observed=str(t.get("observed") or "").lower()
        if expected in {"deny","forbidden","unauthorized"} and observed in {"allow","allowed","success","200","201","204"}:
            findings.append({"id":"AUTHZ-ROLE-MISMATCH","severity":"high","role":str(t.get("role") or "unknown"),"test":str(t.get("id") or "unknown"),"evidence":str(t.get("evidence_ref") or "")[:300]})
    out={"schema_version":"3.5","status":"completed","test_count":len(tests),"finding_count":len(findings),"findings":findings,"limitations":["Input is operator-produced evidence; the engine does not issue authorization-bypass requests"]}
    atomic_write_json(ev/"auth-role-analysis-v35.json",out); return out
