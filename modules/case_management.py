#!/usr/bin/env python3
"""V21 case/evidence management. Metadata and analyst decisions only; no testing."""
from __future__ import annotations
import json, hashlib
from datetime import datetime, timezone
from pathlib import Path

ACTIONS={"note","decision","status","evidence-link"}

def _load(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except (OSError,json.JSONDecodeError): return default

def _save(p, data):
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _case_id(fid): return "CASE-" + hashlib.sha256(fid.encode()).hexdigest()[:10].upper()

def build(root: str|Path) -> Path:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"
    graph=_load(ev/"attack-graph.json", {"nodes":[]}); existing=_load(ev/"case-ledger.json", {"cases":[]})
    cases={c["case_id"]:c for c in existing.get("cases",[]) if isinstance(c,dict) and c.get("case_id")}
    for n in graph.get("nodes",[]):
        if n.get("type")!="finding": continue
        fid=str(n.get("finding_id") or n.get("id")); cid=_case_id(fid)
        cases.setdefault(cid,{"case_id":cid,"finding_id":fid,"title":n.get("label"),"status":"open","notes":[],"decisions":[],"evidence_links":[],"created_at":datetime.now(timezone.utc).isoformat()})
    payload={"schema_version":"1.0","updated_at":datetime.now(timezone.utc).isoformat(),"cases":list(cases.values())}
    p=ev/"case-ledger.json"; _save(p,payload)
    lines=["# Evidence & Case Management","",f"Cases: **{len(cases)}**","","Each case links a finding to analyst notes, decisions, evidence references and disposition history.",""]
    for c in cases.values():
        lines += [f"## {c['case_id']} — `{c['finding_id']}`",f"- **Status:** `{c.get('status','open')}`",f"- **Title:** {c.get('title','')}",f"- Notes: {len(c.get('notes',[]))} | Decisions: {len(c.get('decisions',[]))} | Evidence links: {len(c.get('evidence_links',[]))}",""]
    rep.mkdir(parents=True,exist_ok=True); (rep/"case-management.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return p

def record(root: str|Path, finding_id: str, action: str, text: str="", evidence: list[str]|None=None, approved: bool=False) -> Path:
    if not approved: raise PermissionError("Explicit operator approval is required")
    action=action.strip().lower()
    if action not in ACTIONS: raise ValueError("action must be note, decision, status, or evidence-link")
    root=Path(root); p=build(root); data=_load(p,{"cases":[]}); cid=_case_id(finding_id)
    case=next((c for c in data["cases"] if c["case_id"]==cid),None)
    if not case: raise KeyError(finding_id)
    now=datetime.now(timezone.utc).isoformat(); entry={"timestamp":now,"action":action,"text":text.strip(),"evidence":list(evidence or [])}
    if action=="note": case["notes"].append(entry)
    elif action=="decision": case["decisions"].append(entry)
    elif action=="evidence-link": case["evidence_links"].extend(list(evidence or []))
    elif action=="status": case["status"]=text.strip().lower() or case.get("status","open"); case.setdefault("decisions",[]).append(entry)
    case["updated_at"]=now; data["updated_at"]=now; _save(p,data); build(root); return p
