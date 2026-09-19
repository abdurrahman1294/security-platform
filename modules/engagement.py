#!/usr/bin/env python3
"""Unified engagement manifest."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

def init_engagement(outdir: str | Path, client: str, target: str, scope_file: str = "") -> Path:
    root=Path(outdir); p=root/"evidence"/"engagement.json"; p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists(): return p
    data={"schema_version":"1.0","engagement_id":root.name,"client":client,"target":target,"scope_file":scope_file,"started":datetime.now(timezone.utc).isoformat(),"artifacts":{}}
    p.write_text(json.dumps(data,indent=2),encoding="utf-8"); return p

def update_artifacts(outdir: str | Path) -> Path:
    root=Path(outdir); p=root/"evidence"/"engagement.json"
    if not p.exists(): return p
    data=json.loads(p.read_text()); artifacts={}
    for rel in ["evidence/assets.json","evidence/attack-graph.json","evidence/evidence-index.json","evidence/timeline.json","evidence/next-investigation.json", "evidence/investigation-priorities-v18.json", "evidence/knowledge-base.json","reports/report-pack.md","reports/dashboard.html", "evidence/validation-ledger.json", "reports/controlled-validation.md", "evidence/assessment-priorities.json", "evidence/validation-queue.json", "evidence/business-impact.json", "evidence/retest-ledger.json", "reports/assessment-intelligence.md", "reports/validation-queue.md", "reports/investigation-priorities-v18.md", "reports/knowledge-base.md", "reports/operator-workspace.html", "evidence/case-ledger.json", "reports/case-management.md", "evidence/risk-analytics-v22.json", "reports/risk-analytics-v22.md", "evidence/workflow.json", "reports/engagement-workflow.md", "evidence/remediation-tracking.json", "reports/remediation-tracking.md", "evidence/retest-intelligence.json", "reports/retest-intelligence.md", "evidence/closure-readiness.json", "reports/closure-readiness.md", "evidence/controlled-exploitation.json", "reports/controlled-exploitation.md", "evidence/exploit-evidence-ledger.json", "reports/exploit-evidence.md", "evidence/assessment-decision.json", "reports/assessment-decision.md", "evidence/proof-adapters.json", "evidence/controlled-proof-plan.json", "reports/controlled-proof-plan.md", "evidence/proof-execution-ledger.json", "evidence/proof-analytics-v38.json", "reports/proof-analytics-v38.md", "evidence/mission-state-v39.json", "evidence/tool-execution-ledger-v40.json", "evidence/adaptive-decisions-v41.json", "reports/adaptive-decisions-v41.md", "evidence/assessment-pipeline-v42.json", "reports/assessment-pipeline-v42.md", "evidence/pipeline-results", "evidence/web-surface-v45.json", "reports/web-surface-v45.md", "evidence/web-endpoints-v46.json", "reports/web-endpoints-v46.md", "evidence/web-assessment-plan-v47.json", "reports/web-assessment-plan-v47.md", "evidence/web-test-matrix-v48.json", "reports/web-test-matrix-v48.md", "evidence/web-probe-v49.json", "reports/web-probe-v49.md", "evidence/web-decisions-v50.json", "reports/web-decisions-v50.md", "evidence/auth-intelligence-v51.json", "reports/auth-intelligence-v51.md", "evidence/authorization-matrix-v52.json", "reports/authorization-matrix-v52.md", "evidence/authz-decisions-v53.json", "reports/authz-decisions-v53.md", "evidence/session-intelligence-v54.json", "reports/session-intelligence-v54.md", "evidence/session-observations-v55.json", "reports/session-observations-v55.md", "evidence/identity-transitions-v56.json", "reports/identity-transitions-v56.md"]:
        artifacts[rel]= (root/rel).exists()
    data["artifacts"]=artifacts; data["updated"]=datetime.now(timezone.utc).isoformat(); p.write_text(json.dumps(data,indent=2),encoding="utf-8"); return p
