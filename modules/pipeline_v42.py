#!/usr/bin/env python3
"""V42 unified assessment pipeline planner.

Builds a dependency-aware execution graph from the V39 mission plan. It is
intentionally declarative: no command is executed here.
"""
from __future__ import annotations
import json, uuid
from pathlib import Path
from datetime import datetime, timezone

PIPELINE_ACTIONS = {
    "external-recon": {"tool":"subfinder", "phase":"recon", "description":"Discover subdomains in the authorized domain."},
    "http-probe": {"tool":"httpx", "phase":"enumeration", "description":"Probe discovered web assets."},
    "port-discovery": {"tool":"naabu", "phase":"enumeration", "description":"Discover exposed TCP ports on approved assets."},
    "service-enumeration": {"tool":"nmap", "phase":"enumeration", "description":"Identify services on approved hosts."},
    "web-crawl": {"tool":"katana", "phase":"web", "description":"Crawl approved live web applications."},
    "vulnerability-discovery": {"tool":"nuclei", "phase":"vuln_scan", "description":"Run vulnerability templates against discovered web targets."},
}

def build_pipeline(root: str | Path, target: str, *, scope_file: str = "", profile: str = "full"):
    root=Path(root); (root/"evidence").mkdir(parents=True,exist_ok=True); (root/"reports").mkdir(parents=True,exist_ok=True)
    actions=["external-recon","http-probe","port-discovery","service-enumeration","web-crawl","vulnerability-discovery"]
    deps={"external-recon":[],"http-probe":["external-recon"],"port-discovery":["external-recon"],
          "service-enumeration":["port-discovery"],"web-crawl":["http-probe"],"vulnerability-discovery":["http-probe","web-crawl"]}
    if profile=="web": actions=["external-recon","http-probe","web-crawl","vulnerability-discovery"]
    tasks=[]
    for i,a in enumerate(actions,1):
        spec=PIPELINE_ACTIONS[a]
        tasks.append({"task_id":f"P42-{uuid.uuid4().hex[:8]}","order":i,"action":a,"tool":spec["tool"],"phase":spec["phase"],
                      "description":spec["description"],"depends_on":deps[a],"status":"pending"})
    doc={"schema_version":"42.0","generated":datetime.now(timezone.utc).isoformat(),"target":target,
         "scope_file":scope_file,"profile":profile,"execution_policy":"authorized-scope-only","tasks":tasks}
    ep=root/"evidence"/"assessment-pipeline-v42.json"; rp=root/"reports"/"assessment-pipeline-v42.md"
    ep.write_text(json.dumps(doc,indent=2),encoding="utf-8")
    lines=["# Assessment Pipeline (V42)","",f"Target: `{target}`",f"Profile: `{profile}`","","| Order | Action | Tool | Depends on |","|---:|---|---|---|"]
    for t in tasks: lines.append(f"| {t['order']} | **{t['action']}** | `{t['tool']}` | {', '.join(t['depends_on']) or '—'} |")
    lines += ["","Execution is blocked unless authorization and scope gates pass."]
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return ep,rp
