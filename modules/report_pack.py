#!/usr/bin/env python3
"""Generate the professional engagement report pack."""
from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
import json
from modules.findings_io import load_findings_file

def _read_findings(out: Path):
    findings=[]
    for rel in ("vulns/findings.json","vulns/authenticated-findings.json","api/api-findings.json","servers/server-findings.json","internal/internal-findings.json"):
        findings.extend(load_findings_file(out/rel))
    return findings

def _read_json(path, default):
    if not path.exists(): return default
    try:
        x=json.loads(path.read_text(encoding="utf-8")); return x
    except (OSError,json.JSONDecodeError): return default

def generate_report_pack(outdir: str, client: str, target: str):
    out=Path(outdir); reports=out/"reports"; reports.mkdir(parents=True,exist_ok=True)
    findings=_read_findings(out)
    statuses=_read_json(out/"evidence"/"finding-status.json", {})
    graph=_read_json(out/"evidence"/"attack-graph.json", {"nodes":[]})
    assets=_read_json(out/"evidence"/"assets.json", {"asset_count":0})
    rec=_read_json(out/"evidence"/"next-investigation.json", {"recommendations":[]})
    priorities=_read_json(out/"evidence"/"assessment-priorities.json", {"recommendations":[]})
    queue=_read_json(out/"evidence"/"validation-queue.json", {"queue":[]})
    counts={}
    for f in findings:
        sev=str((f.get("info") or {}).get("severity") or "info").lower(); counts[sev]=counts.get(sev,0)+1
    confirmed=sum(1 for n in graph.get("nodes",[]) if n.get("type")=="finding" and n.get("status")=="confirmed")

    priority_lines="\n".join(f"{i}. **{r.get('title')}** (`{r.get('finding_id')}`) — score {r.get('rank_score')}/100. {r.get('reason')}" for i,r in enumerate(priorities.get("recommendations",[])[:5],1))
    (reports/"executive-summary.md").write_text(f'''# Executive Summary\n\n**Client:** {client}\n\n**Target:** {target}\n\n**Generated:** {datetime.now(timezone.utc).isoformat()}\n\n## Assessment Snapshot\n\n- Assets inventoried: **{assets.get("asset_count",0)}**\n- Structured findings: **{len(findings)}**\n- Confirmed findings: **{confirmed}**\n- Critical: **{counts.get("critical",0)}**\n- High: **{counts.get("high",0)}**\n- Medium: **{counts.get("medium",0)}**\n- Low: **{counts.get("low",0)}**\n\n## Interpretation\n\nAutomated findings are leads until manually validated. Attack-path relationships labelled as hypotheses are not proof of exploitability, access, trust, or impact.\n\n## Immediate Investigation Priorities\n\n{priority_lines}\n''',encoding="utf-8")

    lines=["# Technical Findings","",f"Client: {client}",f"Target: {target}",""]
    if not findings: lines.append("No structured findings were available.")
    for i,f in enumerate(findings,1):
        info=f.get("info") or {}; fid=f.get("finding_id") or f.get("template-id") or f.get("id") or f"finding-{i}"
        status=statuses.get(fid,{}).get("status","unreviewed") if isinstance(statuses,dict) else "unreviewed"
        lines += [f"## {i}. {info.get('name',fid)}",f"- ID: `{fid}`",f"- Severity: `{str(info.get('severity','info')).lower()}`",f"- Asset: `{f.get('host') or f.get('matched-at') or 'N/A'}`",f"- Status: `{status}`","",str(info.get("description","")).strip()[:3000],""]
    (reports/"technical-findings.md").write_text("\n".join(lines),encoding="utf-8")

    evidence_files=sorted(str(p.relative_to(out)) for p in (out/"evidence").rglob("*") if p.is_file()) if (out/"evidence").exists() else []
    (reports/"evidence-appendix.md").write_text("# Evidence Appendix\n\nSensitive values should remain redacted. This appendix indexes artifacts and hashes rather than embedding secrets.\n\n"+"\n".join(f"- `{p}`" for p in evidence_files),encoding="utf-8")

    (reports/"assessment-intelligence.md").write_text("# Assessment Intelligence\n\nDecision support only; no recommendation authorizes testing.\n\n"+"\n".join(f"- **{r.get('finding_id')}** — score **{r.get('rank_score')}** — {r.get('reason')}" for r in priorities.get("recommendations",[])[:20])+"\n",encoding="utf-8")
    (reports/"validation-queue.md").write_text("# Controlled Validation Queue\n\nEach item requires separate authorization, scope verification, and explicit operator approval.\n\n"+"\n".join(f"- `{r.get('finding_id')}` — {r.get('title')} — **{r.get('queue_status','ready')}**" for r in queue.get("queue",[])[:50])+"\n",encoding="utf-8")

    if not (reports/"retest-report.md").exists():
        (reports/"retest-report.md").write_text("# Retest Report\n\nManual retest results are recorded in `evidence/retest-ledger.json`.\n",encoding="utf-8")
    entries=["executive-summary.md","technical-findings.md","evidence-appendix.md","attack-graph.md","next-investigation.md","assessment-intelligence.md","validation-queue.md","timeline.md","finding-status-report.md","engagement-coverage.md","dashboard.html","controlled-validation.md","controlled-exploitation.md","exploit-evidence.md","assessment-decision.md","controlled-proof-plan.md","proof-analytics-v38.md","adaptive-decisions-v41.md","assessment-pipeline-v42.md","web-surface-v45.md","web-endpoints-v46.md","web-assessment-plan-v47.md","web-test-matrix-v48.md","web-probe-v49.md","web-decisions-v50.md","auth-intelligence-v51.md","authorization-matrix-v52.md","authz-decisions-v53.md","retest-report.md"]
    idx=["# Professional Report Pack","",f"Client: {client}",f"Target: {target}","","## Deliverables",""]+[f"- [{'x' if (reports/n).exists() else ' '}] `{n}`" for n in entries]+["","## Lifecycle","","Discover → Correlate → Prioritize → Validate → Evidence → Impact → Remediate → Retest → Report"]
    path=reports/"report-pack.md"; path.write_text("\n".join(idx)+"\n",encoding="utf-8"); return path
