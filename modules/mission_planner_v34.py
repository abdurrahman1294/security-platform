"""V3.4 evidence-driven mission planner.

Builds a bounded assessment plan from scope, available evidence, capability
catalogue and tool readiness. Planning never grants authority or executes tools.
"""
from __future__ import annotations
import json, shutil
from pathlib import Path
from modules.atomic_io import atomic_write_json

PHASES=[
 ("preflight","Validate authorization, scope and ROE",[]),
 ("surface","Normalize assets, services and existing evidence",[]),
 ("recon","Run only the approved discovery toolchain",["nmap","subfinder","httpx","naabu","katana"]),
 ("web_api","Assess web/API surfaces using approved passive/active checks",["nuclei"]),
 ("identity","Analyze AD/cloud identity and authorization relationships",["nxc","aws","az","gcloud","kubectl"]),
 ("specialist","Run mobile, wireless, container and database specialist analysis",[]),
 ("correlation","Build evidence graph and rank attack paths",[]),
 ("verification","Queue bounded proof actions for explicit operator approval",[]),
 ("retest","Compare findings against the baseline and track closure",[]),
 ("report","Generate evidence-backed technical and executive reports",[]),
]

def build(root: str|Path,target: str="",authorized: bool=False)->dict:
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    rows=[]
    for ident,desc,tools in PHASES:
        available={t:bool(shutil.which(t)) for t in tools}
        decision="READY"
        reasons=[]
        if ident=="preflight" and not authorized:
            decision="BLOCKED"; reasons.append("explicit authorization assertion required")
        missing=[t for t,v in available.items() if not v]
        if missing and ident not in {"preflight","surface","specialist","correlation","verification","retest","report"}:
            decision="DEFERRED"; reasons.append("missing optional external tools: "+", ".join(missing))
        rows.append({"phase":ident,"description":desc,"decision":decision,"tools":available,"reasons":reasons})
    data={"schema_version":"3.4","target":target,"authorized":authorized,"phases":rows,"principle":"Planning never expands scope or authority and never executes consequential actions."}
    atomic_write_json(ev/"mission-plan-v34.json",data)
    lines=["# Assessment Mission Plan (V3.4)","",f"Target: `{target}`","", "The planner is advisory. Every consequential action is independently scope- and approval-gated.",""]
    for r in rows: lines.append(f"- **{r['phase']}** — **{r['decision']}** — {r['description']}" + (f" ({'; '.join(r['reasons'])})" if r['reasons'] else ""))
    (rep/"mission-plan-v34.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return data
