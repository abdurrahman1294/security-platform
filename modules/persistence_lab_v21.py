"""Multiple benign persistence simulations for the disposable lab."""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json
from modules.lab_http import base, request

MECHANISMS = ("startup_marker", "scheduled_task_marker", "service_marker", "application_marker")

def run(root: str | Path, target: str, mechanisms=MECHANISMS) -> dict:
    try:
        target = base(target)
    except ValueError:
        return {"status": "blocked", "reason": "loopback-only"}
    results=[]
    for mechanism in mechanisms:
        if mechanism not in MECHANISMS:
            results.append({"mechanism": mechanism, "status": "BLOCKED"}); continue
        r=request(target+"/lab/persistence-proof", method="POST", data={"mechanism": mechanism}, headers={"Content-Type":"application/json", "X-Lab-Proof":"PERSIST-LAB-OK"})
        try: body=json.loads(r.get("body", "{}"))
        except Exception: body={}
        confirmed=body.get("status")=="confirmed" and body.get("mechanism")==mechanism and body.get("state_change")=="disposable-marker-only"
        results.append({"mechanism": mechanism, "status": "CONFIRMED" if confirmed else "FAILED", "proof": body.get("mechanism"), "state_change": body.get("state_change")})
    out={"schema_version":"22.0","lab_only":True,"results":results,"confirmed":sum(x["status"]=="CONFIRMED" for x in results)}
    ev=Path(root)/"evidence"; ev.mkdir(parents=True,exist_ok=True); atomic_write_json(ev/"persistence-validation-v21.json",out); return out
