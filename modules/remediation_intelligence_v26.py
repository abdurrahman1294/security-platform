#!/usr/bin/env python3
"""V26 remediation intelligence derived from findings and metadata."""
from __future__ import annotations
import json,re
from datetime import datetime,timezone
from pathlib import Path
from .atomic_io import load_json

RULES=[
 ("authentication",["auth bypass","authentication bypass","weak password","default credential","default login"],"Review authentication controls, enforce strong authentication, and verify authorization boundaries."),
 ("authorization",["idor","broken access control","authorization","privilege escalation","access control"],"Review server-side authorization on every sensitive operation and test least-privilege boundaries."),
 ("injection",["sql injection","command injection","xss","cross site scripting","ldap injection"],"Use context-appropriate parameterization/encoding and validate untrusted input at security boundaries."),
 ("exposure",["information disclosure","exposed","directory listing","sensitive data"],"Remove unnecessary exposure, restrict access, and minimize sensitive information returned or published."),
 ("configuration",["misconfiguration","debug","default configuration","security header"],"Harden configuration, disable unnecessary features, and apply secure baseline controls."),
 ("dependency",["outdated","vulnerable component","cve-","dependency"],"Update or replace affected dependencies and establish dependency/version monitoring."),
]

def load(p,d):
    return load_json(p,d)

def classify(title,desc):
    text=(str(title)+" "+str(desc)).lower()
    for cat,needles,action in RULES:
        if any(n in text for n in needles): return cat,action
    return "general","Review root cause, apply least privilege/secure defaults, and verify the remediation with a controlled retest."

def build(root):
    root=Path(root); ev=root/"evidence"; rep=root/"reports"; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    data=load(ev/"normalized-findings.json",{"findings":[]}); impacts=load(ev/"business-impact.json",{})
    rows=[]
    for f in data.get("findings",[]):
        cat,action=classify(f.get("title"),f.get("description")); imp=impacts.get(f["normalized_id"],impacts.get(f.get("title"),{})) if isinstance(impacts,dict) else {}
        rows.append({"finding_id":f["normalized_id"],"title":f["title"],"asset":f["asset"],"severity":f["severity"],"root_cause_category":cat,"recommended_action":action,"affected_assets":[f["asset"]],"retest_requirements":["Reproduce the original condition with the same scope and validation constraints","Capture new evidence and compare against the original finding","Record fixed/partially-fixed/still-present/inconclusive"],"business_context":imp})
    payload={"schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),"recommendations":rows}
    p=ev/"remediation-intelligence.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# V26 Remediation Intelligence","","> Recommendations are decision support. They do not perform remediation.",""]
    for r in rows: lines += [f"## {r['finding_id']} — {r['title']}",f"- Severity: `{r['severity']}` | Asset: `{r['asset']}`",f"- Root-cause category: **{r['root_cause_category']}**",f"- Recommendation: {r['recommended_action']}","- Retest: "+"; ".join(r['retest_requirements']),""]
    (rep/"remediation-intelligence.md").write_text("\n".join(lines),encoding="utf-8")
    return p
