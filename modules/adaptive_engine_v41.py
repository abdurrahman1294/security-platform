#!/usr/bin/env python3
"""V41 adaptive decision engine.

Reads engagement artifacts and selects the next *authorized assessment task*.
It never chooses arbitrary exploits or bypasses the existing proof controls.
"""
from __future__ import annotations
import json
from modules.atomic_io import load_json
from pathlib import Path
from datetime import datetime, timezone
from modules.findings_io import load_findings_file


def _json(path, default):
    return load_json(path, default)

def _finding_count(root):
    total=0
    for rel in ["vulns/findings.json","vulns/authenticated-findings.json","api/api-findings.json","servers/server-findings.json","internal/internal-findings.json"]:
        total += len(load_findings_file(root/rel))
    return total

def decide(root: str | Path):
    root=Path(root); mission=_json(root/"evidence"/"mission-state-v39.json",{"tasks":[]})
    findings=_finding_count(root)
    assets=_json(root/"evidence"/"assets.json",{"asset_count":0})
    queue=_json(root/"evidence"/"validation-queue.json",{"queue":[]})
    graph=_json(root/"evidence"/"attack-graph.json",{"nodes":[]})
    proof=_json(root/"evidence"/"proof-analytics-v38.json",{"executions":0,"results":{}})
    recommendations=[]
    completed={t.get("action") for t in mission.get("tasks",[]) if t.get("status")=="completed"}
    pending=[t for t in mission.get("tasks",[]) if t.get("status")=="pending"]
    if "external-recon" not in completed: recommendations.append((100,"external-recon","Complete asset discovery first."))
    elif "port-and-service-enumeration" not in completed: recommendations.append((92,"port-and-service-enumeration","Map exposed services on discovered assets."))
    elif "web-enumeration" not in completed: recommendations.append((90,"web-enumeration","Map web applications and endpoints."))
    elif findings and queue.get("queue"):
        recommendations.append((88,"controlled-proof-review","Review the highest-value validation candidates; execution requires separate operator approval."))
    elif "vulnerability-discovery" not in completed: recommendations.append((86,"vulnerability-discovery","Run vulnerability discovery against the mapped surface."))
    elif "correlate-and-prioritize" not in completed: recommendations.append((82,"correlate-and-prioritize","Refresh normalized findings, attack paths and priorities."))
    else: recommendations.append((60,"report-pack","Generate/update the professional report pack."))
    recommendations.sort(reverse=True)
    decision={"schema_version":"41.0","generated":datetime.now(timezone.utc).isoformat(),
              "engagement_snapshot":{"assets":assets.get("asset_count",0),"findings":findings,
                                     "validation_candidates":len(queue.get("queue",[])),
                                     "attack_graph_nodes":len(graph.get("nodes",[])),"proof_executions":proof.get("executions",0)},
              "next_actions":[{"rank":i+1,"priority":p,"action":a,"reason":r} for i,(p,a,r) in enumerate(recommendations[:5])],
              "human_control_required":True}
    ep=root/"evidence"/"adaptive-decisions-v41.json"; rp=root/"reports"/"adaptive-decisions-v41.md"
    ep.parent.mkdir(parents=True,exist_ok=True); rp.parent.mkdir(parents=True,exist_ok=True)
    ep.write_text(json.dumps(decision,indent=2),encoding="utf-8")
    rp.write_text("# Adaptive Assessment Decisions (V41)\n\n"+"\n".join(f"{x['rank']}. **{x['action']}** — priority {x['priority']}. {x['reason']}" for x in decision["next_actions"])+"\n\nHuman operator approval remains required for consequential actions.\n",encoding="utf-8")
    return ep, rp
