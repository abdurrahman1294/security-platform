"""Multiple bounded lateral-access validations for the disposable lab.

No remote command execution is performed. Each method proves only network
reachability plus authentication to a second disposable host.
"""
from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json
from modules.lab_http import base, request

METHODS=("http_basic", "lab_token", "credential_auth")

def _post(url, payload, headers):
    return request(url, method="POST", data=payload, headers=headers)

def run(root: str | Path, target: str, internal: str, username: str="labuser", password: str="labpass123") -> dict:
    try:
        target, internal = base(target), base(internal)
    except ValueError:
        return {"status":"blocked","reason":"loopback-only"}
    if target == internal: return {"status":"blocked","reason":"targets must be distinct"}
    results=[]
    for method in METHODS:
        headers={"X-Lab-Lateral-Method":method}
        payload={"username":username,"password":password,"method":method}
        r=_post(internal+"/lab/lateral-auth",payload,headers)
        try: body=json.loads(r.get("body", "{}"))
        except Exception: body={}
        confirmed=body.get("status")=="confirmed" and body.get("method")==method and body.get("host_role")=="internal"
        results.append({"method":method,"status":"CONFIRMED" if confirmed else "FAILED","principal":body.get("principal","")})
    out={"schema_version":"22.0","lab_only":True,"target":internal,"results":results,"confirmed":sum(x["status"]=="CONFIRMED" for x in results)}
    ev=Path(root)/"evidence"; ev.mkdir(parents=True,exist_ok=True); atomic_write_json(ev/"lateral-validation-v21.json",out); return out
