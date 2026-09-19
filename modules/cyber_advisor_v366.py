"""V3.66 Cybersecurity Advisor.

Decision-support layer for questions such as "is this hackable?", "which
approach is better?", and "how should I test this?". It can use an external
reasoning provider when configured, otherwise it provides deterministic
structured guidance. It does not execute actions or grant authorization.
"""
from __future__ import annotations
import json, os, re, time, urllib.error, urllib.request
from pathlib import Path
from typing import Any

VERSION = "3.66.0"


def _classify(q: str) -> list[str]:
    t=q.lower()
    groups=[]
    rules={
        "feasibility": ["hackable", "possible", "doable", "can i", "is it possible"],
        "approach": ["how should", "how can i", "best way", "which way", "approach", "method"],
        "web": ["web", "api", "http", "xss", "sqli", "idor", "jwt", "graphql", "ssrf"],
        "network": ["network", "port", "firewall", "router", "dns", "smb"],
        "cloud": ["aws", "azure", "gcp", "cloud", "iam", "bucket"],
        "mobile": ["android", "ios", "apk", "mobile app"],
        "osint": ["osint", "username", "domain", "social media", "public information"],
        "bug-bounty": ["bug bounty", "bounty", "scope", "program"],
        "defensive": ["secure", "fix", "defend", "mitigate", "hardening"],
    }
    for name, words in rules.items():
        if any(w in t for w in words): groups.append(name)
    return groups or ["general-cybersecurity"]


def _heuristic(question: str, context: dict[str, Any]) -> dict[str, Any]:
    topics=_classify(question)
    q=question.strip()
    feasibility = any(x in q.lower() for x in ("hackable", "possible", "doable", "can i"))
    if feasibility:
        opening = "Yes, it may be technically feasible in an authorized environment, but feasibility depends on the target, trust boundaries, access level, and evidence available."
    else:
        opening = "A good way to approach this is to define the objective, identify the attack surface, and choose the least invasive test that can answer the key question."
    plan=[
        "Clarify the objective and success condition.",
        "Confirm written authorization and exact scope before active testing.",
        "Map the relevant assets, trust boundaries, inputs, identities, and dependencies.",
        "Start with passive/read-only evidence, then choose the highest-information test.",
        "Validate promising results with reproducible evidence and an independent check.",
        "Record failed hypotheses as well as successful findings so the next decision improves.",
    ]
    if "web" in topics or "bug-bounty" in topics:
        plan.insert(3,"For web/API work, compare unauthenticated and authorized-user behavior, input handling, routing, session state, and object-level authorization where relevant.")
    if "network" in topics:
        plan.insert(3,"For network work, establish reachable services and versions first, then prioritize exposed trust boundaries and configuration weaknesses.")
    if "cloud" in topics:
        plan.insert(3,"For cloud work, map identities, roles, resources, network paths, and trust relationships before testing permissions.")
    if "mobile" in topics:
        plan.insert(3,"For mobile work, combine static application inspection with controlled runtime observations and API analysis.")
    if "osint" in topics:
        plan.insert(3,"For OSINT, separate confirmed public facts from assumptions and record source/provenance for every important claim.")
    return {
        "provider":"heuristic-v366", "question":q, "topics":topics,
        "answer":opening,
        "recommendation":plan,
        "decision_framework": [
            {"question":"What am I trying to prove?","why":"Prevents unfocused testing."},
            {"question":"What evidence would change my mind?","why":"Reduces confirmation bias."},
            {"question":"What is the safest high-information test?","why":"Maximizes learning while limiting unintended impact."},
            {"question":"What should I do if it fails?","why":"Turns failure into the next hypothesis rather than a dead end."},
        ],
        "warnings":["Technical feasibility does not establish authorization.","Do not treat an unverified hypothesis as a vulnerability.","Do not expose secrets or personal data in advice requests."],
        "next_questions":["What is the target type?","What access do you already have?","What is explicitly in scope?","What evidence have you collected?"],
        "context_used": {"target":context.get("target",""),"engagement":context.get("engagement","")},
    }


def _remote(url: str, model: str, question: str, context: dict[str, Any]) -> dict[str, Any]:
    from urllib.parse import urlparse
    p=urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise ValueError("SECURITY_AI_URL must be an HTTPS endpoint")
    system=("You are a cybersecurity decision-support advisor inside an authorized security platform. "
            "Answer feasibility, approach, architecture, testing, and security questions clearly and practically. "
            "Reason broadly about defensive and authorized offensive security. Distinguish feasibility from authorization, "
            "state assumptions, compare alternatives, identify risks and evidence needed, and suggest a staged test plan. "
            "Never claim an action was performed. Do not execute tools. Do not invent observations, credentials, or scope. "
            "For high-impact actions, keep execution behind the platform's authorization and approval controls. Return JSON "
            "with answer, recommendation (array), decision_framework (array), warnings (array), next_questions (array).")
    body=json.dumps({"model":model,"messages":[{"role":"system","content":system},{"role":"user","content":json.dumps({"question":question,"context":context},ensure_ascii=False)}],"temperature":0.2}).encode()
    req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=45) as r:
        return json.loads(r.read().decode())


def advise(*, question: str, target: str = "", engagement: str = "", context: dict[str, Any] | None = None,
           root: str | Path | None = None) -> dict[str, Any]:
    if not question or not question.strip():
        raise ValueError("question is required")
    ctx={"target":target,"engagement":engagement,**(context or {})}
    provider=os.getenv("SECURITY_AI_PROVIDER","heuristic-v366").lower()
    error=None; raw=None
    if provider not in {"heuristic","disabled","heuristic-v366"} and os.getenv("SECURITY_AI_URL"):
        try: raw=_remote(os.environ["SECURITY_AI_URL"],os.getenv("SECURITY_AI_MODEL","security-advisor"),question[:30000],ctx)
        except (OSError,urllib.error.URLError,TimeoutError,ValueError,json.JSONDecodeError) as exc:
            error=f"{type(exc).__name__}:{str(exc)[:240]}"
    if raw is None: raw=_heuristic(question,ctx)
    result={"schema_version":VERSION,"created_at":time.time(),"provider":raw.get("provider",provider),"question":question[:30000],"result":raw,"provider_error":error,
            "execution_contract":{"advice_only":True,"no_tool_execution":True,"no_authorization_grant":True,"no_scope_expansion":True}}
    if root:
        p=Path(root)/"evidence"; p.mkdir(parents=True,exist_ok=True)
        stamp=str(int(time.time()*1000))
        (p/f"cyber-advice-v366-{stamp}.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf-8")
    return result
