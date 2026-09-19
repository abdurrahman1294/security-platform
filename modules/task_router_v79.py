"""V79 task router: converts mode + evidence into a safe prioritized work queue."""
from pathlib import Path
import json

def build(outdir, mode, objective="general"):
    outdir=Path(outdir); evidence=outdir/"evidence"; evidence.mkdir(parents=True,exist_ok=True)
    queues={
      "pentest":[("recon",90), ("web_api",88), ("authz",86), ("api",84), ("business_logic",82), ("infrastructure",80), ("cloud_ad",75), ("evidence",70), ("reporting",65)],
      "bugbounty":[("program_policy",100),("passive_discovery",92),("safe_assessment",88),("triage",82),("evidence",78),("reporting",72)],
      "osint":[("public_sources",95),("search_pivots",92),("entity_graph",86),("correlation",82),("confidence_review",78)],
      "auto":[("program_policy",90),("recon",90),("public_sources",88),("web_api",87),("authz",85),("correlation",84),("evidence",80),("reporting",75)]}
    rows=[{"task":t,"priority":p,"status":"ready","requires_operator_approval":t in {"safe_assessment","recon","web_api","authz","api","business_logic","infrastructure","cloud_ad"}} for t,p in queues.get(mode,queues["auto"])]
    data={"version":"V79","mode":mode,"objective":objective,"queue":rows,"ordering":"priority-descending","arbitrary_shell":False}
    ep=evidence/"task-router-v79.json"; ep.write_text(json.dumps(data,indent=2)); (outdir/"reports"/"task-router-v79.md").write_text("# Task Router\n\n"+"\n".join(f"- **{r['priority']}** {r['task']} — {r['status']}" for r in rows)); return ep
