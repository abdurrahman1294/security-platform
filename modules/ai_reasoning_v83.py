"""V83 AI reasoning interface: sanitized context, pluggable provider, bounded actions."""
from pathlib import Path
import json, os, re, urllib.request, urllib.error
from urllib.parse import urlparse
from .security import redact_mapping
from .atomic_io import load_json

FORBIDDEN = {"credential_theft","persistence","lateral_movement","exfiltration","destructive_actions","unrestricted_exploitation"}

def _load_context(outdir):
    rows=[]
    for p in sorted((Path(outdir)/"evidence").glob("*.json")):
        d=load_json(p, None, quarantine_on_error=False)
        if d is not None:
            safe = redact_mapping(d)
            rows.append({"artifact":p.name,"data":safe if len(json.dumps(safe))<6000 else {"keys":list(safe)[:30] if isinstance(safe,dict) else []}})
    return rows[-40:]

def _heuristic(mode, objective, context):
    text=json.dumps(context).lower()
    actions=[]
    if mode in ("pentest","auto"):
        actions += ["target_profile","web_api_analysis","authentication_review","business_logic_review"]
        if "cloud" in text or "aws" in text or "azure" in text: actions.append("cloud_review")
    if mode in ("bugbounty","auto"):
        actions += ["program_policy_check","duplicate_review","reportability_review"]
    if mode in ("osint","auto"):
        actions += ["passive_source_collection","entity_correlation","confidence_review"]
    return {"provider":"heuristic","reasoning":"evidence-aware rule synthesis","recommended_actions":list(dict.fromkeys(actions)),"objective":objective}

def _remote(url, model, payload):
    parsed=urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("AI provider URL must use HTTPS")
    body=json.dumps({"model":model,"messages":[{"role":"system","content":"You are a defensive security analysis assistant. Return JSON only. Never propose credential theft, persistence, lateral movement, exfiltration, destructive actions, unrestricted exploitation, or arbitrary shell execution."},{"role":"user","content":json.dumps(payload)}]}).encode()
    req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=20) as r: return json.loads(r.read().decode())

def build(outdir, mode, target, objective="general"):
    outdir=Path(outdir); (outdir/"evidence").mkdir(parents=True,exist_ok=True); (outdir/"reports").mkdir(parents=True,exist_ok=True)
    context=_load_context(outdir); provider=os.getenv("SECURITY_AI_PROVIDER","heuristic").lower(); result=None
    if provider not in {"heuristic","disabled"} and os.getenv("SECURITY_AI_URL"):
        try: result=_remote(os.environ["SECURITY_AI_URL"],os.getenv("SECURITY_AI_MODEL","security-analyst"),{"mode":mode,"target":target,"objective":objective,"context":context})
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e: result={"provider":"fallback","error":type(e).__name__}
    if result is None or provider in {"heuristic","disabled"}: result=_heuristic(mode,objective,context)
    result["version"]="V83"; result["mode"]=mode; result["target"]=target; result["human_approval_required"]=True; result["forbidden_autonomy"]=sorted(FORBIDDEN)
    p=outdir/"evidence"/"ai-reasoning-v83.json"; p.write_text(json.dumps(result,indent=2))
    (outdir/"reports"/"ai-reasoning-v83.md").write_text("# AI Reasoning\n\nProvider: `%s`\n\nRecommended work is decision support only. Consequential actions remain operator-approved.\n"%result.get("provider","unknown"))
    return p
