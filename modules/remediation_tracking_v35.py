"""V3.5 remediation lifecycle tracker with severity-aware target dates."""
from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from modules.atomic_io import atomic_write_json

WINDOWS={"critical":7,"high":14,"medium":30,"low":60,"info":90}

def build(root: str|Path)->dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    src=ev/"normalized-findings.json"
    try: doc=json.loads(src.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError): doc={"findings":[]}
    findings=doc.get("findings",[]) if isinstance(doc,dict) else []
    now=datetime.now(timezone.utc)
    rows=[]
    for f in findings:
        sev=str(f.get("severity") or "info").lower(); days=WINDOWS.get(sev,90)
        rows.append({"finding_id":f.get("normalized_id") or f.get("finding_id") or f.get("title"),"severity":sev,"state":"open","target_date":(now+timedelta(days=days)).date().isoformat(),"owner":"unassigned","retest_required":True})
    out={"schema_version":"3.5","generated_at":now.isoformat(),"items":rows,"states":["open","in-progress","ready-for-retest","fixed","partially-fixed","accepted-risk","false-positive","inconclusive"]}
    atomic_write_json(ev/"remediation-tracker-v35.json",out); return out
