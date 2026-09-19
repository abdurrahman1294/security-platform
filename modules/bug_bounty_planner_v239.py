"""V239 adaptive bug-bounty assessment planner."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json, load_json
from modules.security import in_scope

TEST_DOMAINS={
"recon":["asset discovery","technology fingerprinting","URL/endpoint discovery"],
"identity":["identity management","authentication","session management","password/reset flows","MFA"],
"authorization":["horizontal authorization","vertical authorization","object-level authorization","function-level authorization"],
"input":["injection","XSS","file/path handling","error handling"],
"api":["API reconnaissance","BOLA","BFLA","excessive data exposure","GraphQL"],
"logic":["workflow bypass","integrity checks","process timing","rate/usage limits","payment/business logic"],
"client":["client-side storage","DOM/client-side behavior","WebSocket/client communication"],
"deployment":["configuration/deployment","security headers","CORS","TLS/cryptography"],
"cloud":["cloud exposure indicators","storage exposure","identity/configuration review"],
}

def build(root, target=""):
    root=Path(root); ev=root/'evidence'; policy=load_json(ev/'bug-bounty-program-v238.json',{}); rules=policy.get('rules',{}) if isinstance(policy,dict) else {}; scope=rules.get('scope',[]) if isinstance(rules,dict) else []; exclusions=rules.get('exclusions',[]) if isinstance(rules,dict) else []; assets=[x for x in scope if not in_scope(x, exclusions)]
    plan=[]
    for category, tests in TEST_DOMAINS.items():
        plan.append({"category":category,"tests":tests,"status":"planned","priority":"high" if category in ('authorization','identity','api','logic') else 'medium'})
    out={"schema_version":"239.0","target":target,"assets":assets,"plan":plan,"methodology_basis":"OWASP WSTG plus API/business-logic coverage","adaptive_inputs":["discovered technologies","authentication model","API schemas","roles/accounts","workflow sequences","prior findings"],"safety":"only authorized, in-scope testing; consequential validation remains operator-approved"}
    atomic_write_json(ev/'bug-bounty-plan-v239.json',out); return out
