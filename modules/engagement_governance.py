#!/usr/bin/env python3
"""V17 engagement governance: immutable-ish audit events and readiness checks."""
from __future__ import annotations
import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path

def _load(p,default):
    if not p.exists(): return default
    try: return json.loads(p.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return default

def audit(root: str|Path, event: str, details: dict|None=None):
    root=Path(root); p=root/"evidence"/"audit-log.json"; p.parent.mkdir(parents=True,exist_ok=True)
    rows=_load(p,[]); prev=rows[-1].get("hash","") if rows else ""
    entry={"event_id":f"AUD-{len(rows)+1:05d}","timestamp":datetime.now(timezone.utc).isoformat(),"event":event,"details":details or {},"previous_hash":prev}
    canonical=json.dumps(entry,sort_keys=True,separators=(",",":")); entry["hash"]=hashlib.sha256(canonical.encode()).hexdigest()
    rows.append(entry); p.write_text(json.dumps(rows,indent=2),encoding="utf-8"); return entry

def readiness(root: str|Path):
    root=Path(root); checks=[]
    scope= root/"config"/"scope.example.txt"
    checks.append({"check":"scope-artifact","ok":any((root/x).exists() for x in ["scope.txt","scope.json"]) or scope.exists(),"note":"An engagement-specific scope artifact should exist."})
    checks.append({"check":"engagement-manifest","ok":(root/"evidence"/"engagement.json").exists(),"note":"Engagement manifest present."})
    checks.append({"check":"evidence-index","ok":(root/"evidence"/"evidence-index.json").exists(),"note":"Evidence index present."})
    checks.append({"check":"attack-graph","ok":(root/"evidence"/"attack-graph.json").exists(),"note":"Attack graph present."})
    checks.append({"check":"audit-log","ok":(root/"evidence"/"audit-log.json").exists(),"note":"Audit trail initialized."})
    ready=all(x["ok"] for x in checks)
    payload={"schema_version":"1.0","ready":ready,"checks":checks,"generated_at":datetime.now(timezone.utc).isoformat()}
    p=root/"evidence"/"engagement-readiness.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Engagement Readiness","",f"**Ready:** {'YES' if ready else 'NO'}","", "| Check | Status |", "|---|---|", *[f"| {x['check']} | {'PASS' if x['ok'] else 'REVIEW'} |" for x in checks]]
    (root/"reports"/"engagement-readiness.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p
