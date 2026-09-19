#!/usr/bin/env python3
"""V27 remediation tracking: metadata-only, no target modification."""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from pathlib import Path

STATUSES={"open","in-progress","blocked","ready-for-retest","closed"}
PRIORITIES={"critical","high","medium","low"}

def _load(p, default):
    try: return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except (OSError,json.JSONDecodeError): return default

def set_record(root, finding_id, status="open", owner="", priority="medium", due_date="", note="", approved=False):
    if not approved: raise PermissionError("Explicit operator approval is required")
    if status not in STATUSES: raise ValueError("Invalid remediation status")
    if priority not in PRIORITIES: raise ValueError("Invalid remediation priority")
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    p=ev/"remediation-tracking.json"; data=_load(p,{"schema_version":"1.0","records":[]})
    records=data.get("records",[])
    now=datetime.now(timezone.utc).isoformat()
    rec={"tracking_id":"RM-"+uuid.uuid4().hex[:10].upper(),"finding_id":finding_id,"status":status,"owner":owner.strip(),"priority":priority,"due_date":due_date.strip(),"note":note.strip(),"updated_at":now}
    records.append(rec); data["records"]=records; data["updated_at"]=now
    p.write_text(json.dumps(data,indent=2),encoding="utf-8")
    _report(rep,records)
    return rec,p

def build(root):
    root=Path(root); p=root/"evidence"/"remediation-tracking.json"; data=_load(p,{"schema_version":"1.0","records":[]}); _report(root/"reports",data.get("records",[])); return p

def _report(rep, records):
    rep.mkdir(parents=True,exist_ok=True)
    lines=["# V27 Remediation Tracking","","> Metadata-only tracking. The framework does not modify target systems.","","| Finding | Status | Priority | Owner | Due |","|---|---|---|---|---|"]
    latest={}
    for r in records: latest[r["finding_id"]]=r
    for r in latest.values(): lines.append(f"| `{r['finding_id']}` | `{r['status']}` | `{r['priority']}` | {r.get('owner') or '-'} | {r.get('due_date') or '-'} |" )
    (rep/"remediation-tracking.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
