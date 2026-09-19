"""V3.63 Offensive AI Reasoning & Agent Loop.

The model is the adaptive reasoning layer: it can form attacker-style hypotheses,
select registered security tools, interpret observations, revise hypotheses and
build multi-step proof plans. Deterministic code remains the authority for
scope, authorization, tool registration, approvals, evidence and state.

This deliberately removes *reasoning* restrictions while retaining execution
contracts. The model can suggest a high-risk test class, but it cannot turn a
natural-language response into an unregistered arbitrary command or silently
expand the engagement.
"""
from __future__ import annotations
import hashlib, json, os, re, time, urllib.error, urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

VERSION = "3.63.0"

@dataclass(frozen=True)
class AgentAction:
    action_id: str
    tool: str
    target: str
    args: tuple[str, ...]
    objective: str
    expected_evidence: tuple[str, ...]
    risk: str = "medium"
    requires_approval: bool = False
    rationale: str = ""


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _safe_json(value: Any, limit: int = 18000) -> Any:
    raw = json.dumps(value, ensure_ascii=False, default=str)
    if len(raw) <= limit:
        return value
    return {"truncated": True, "sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "preview": raw[:limit]}


def _redact(value: Any) -> Any:
    """Remove secret *values* while preserving attack-relevant structure."""
    secret_names = {"password", "passwd", "secret", "token", "access_token",
                    "refresh_token", "private_key", "cookie", "session_cookie"}
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in secret_names:
                out[k] = "<redacted>"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(x) for x in value[:500]]
    return value


def build_context(*, target: str, objective: str, operator_story: str = "", observations: Iterable[Any] = (),
                  findings: Iterable[Any] = (), source_analysis: Any = None,
                  completed_actions: Iterable[Any] = ()) -> dict[str, Any]:
    return _safe_json(_redact({
        "target": target,
        "objective": objective,
        "operator_story": operator_story[:30000],
        "observations": list(observations)[-80:],
        "findings": list(findings)[-120:],
        "source_analysis": source_analysis,
        "completed_actions": list(completed_actions)[-100:],
    }))


def _heuristic(context: dict[str, Any]) -> dict[str, Any]:
    """Useful offline planner; deliberately attacker-oriented, not a toy checklist."""
    text = json.dumps(context).lower()
    actions = []
    if any(x in text for x in ("xss", "script", "reflect")):
        actions.append({"tool":"httpx","target":context["target"],"args":(),"objective":"reconfirm reachable web surface and response behavior","expected_evidence":["status","headers","body-differential"]})
    if any(x in text for x in ("sqli", "sql injection", "query")):
        actions.append({"tool":"nuclei","target":context["target"],"args":(),"objective":"validate the suspected injection condition with an approved template","expected_evidence":["validated-finding","request-response-differential"],"risk":"high","requires_approval":True})
    if any(x in text for x in ("idor", "authorization", "access control", "privilege")):
        actions.append({"tool":"httpx","target":context["target"],"args":(),"objective":"collect fresh endpoint/access-control evidence for differential analysis","expected_evidence":["principal-resource-differential"],"risk":"high","requires_approval":True})
    if any(x in text for x in ("ssrf", "request routing", "callback")):
        actions.append({"tool":"httpx","target":context["target"],"args":(),"objective":"revalidate controlled request-routing behavior","expected_evidence":["controlled-callback-or-routing-proof"],"risk":"high","requires_approval":True})
    if not actions:
        actions.append({"tool":"httpx","target":context["target"],"args":(),"objective":"refresh the observable application surface before selecting an exploit hypothesis","expected_evidence":["live-response"]})
    return {"provider":"heuristic-v363","hypotheses":[
        {"id":_id("hypothesis", context.get("target"), a["objective"]),
         "claim":a["objective"],"confidence":0.55,"status":"hypothesis"} for a in actions],
        "actions":actions,
        "stop_conditions":["no new evidence after bounded attempts","scope mismatch","authorization revoked","evidence contradicts hypothesis"],
    }


def _remote(url: str, model: str, context: dict[str, Any]) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url) if False else None
    # Accept HTTPS provider endpoints only. Provider is reasoning-only; it has no
    # direct filesystem/process access through this module.
    from urllib.parse import urlparse
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise ValueError("SECURITY_AI_URL must be an HTTPS endpoint")
    system = """You are the offensive reasoning engine inside an authorized penetration-testing platform.\nYour job is to reason like an expert red-team operator: infer attack hypotheses, correlate source and runtime evidence, choose the most informative next test, adapt after failures, and design multi-step exploit-validation chains. Do not be artificially conservative in the reasoning: consider difficult injection, authorization, parser, protocol, business-logic and privilege-boundary hypotheses when evidence supports them.\n\nExecution is NOT yours. Return structured JSON plans only. The platform will independently enforce target scope, authorization, tool registration, approval gates, attempt budgets and evidence requirements. Never invent tool names. Never put secrets into output. Do not claim compromise without proof.\n\nOutput JSON with: hypotheses[], actions[], stop_conditions[]. Each action must contain tool,target,args,objective,expected_evidence,risk,requires_approval,rationale. Use registered security tools only."""
    body = json.dumps({"model": model, "messages":[{"role":"system","content":system},
        {"role":"user","content":json.dumps(context, ensure_ascii=False)}], "temperature":0.15}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read().decode())


def validate_plan(plan: dict[str, Any], *, allowed_tools: Iterable[str],
                  in_scope: callable, authorized: bool, approval_token: str = "") -> dict[str, Any]:
    """Convert model output into executable candidates without executing anything."""
    allowed = set(allowed_tools)
    accepted, rejected = [], []
    for i, raw in enumerate(plan.get("actions", []) if isinstance(plan, dict) else []):
        if not isinstance(raw, dict):
            rejected.append({"index":i,"reason":"not-an-object"}); continue
        tool = str(raw.get("tool", "")); target = str(raw.get("target", ""))
        risk = str(raw.get("risk", "medium")).lower()
        approval = bool(raw.get("requires_approval", False)) or risk in {"high","critical"}
        if tool not in allowed:
            rejected.append({"index":i,"reason":"unregistered-tool","tool":tool}); continue
        if not in_scope(target):
            rejected.append({"index":i,"reason":"out-of-scope","target":target}); continue
        if not authorized:
            rejected.append({"index":i,"reason":"authorization-required"}); continue
        if approval and not approval_token:
            rejected.append({"index":i,"reason":"approval-required","tool":tool}); continue
        args = raw.get("args", [])
        if not isinstance(args, (list, tuple)) or any(not isinstance(x, str) for x in args):
            rejected.append({"index":i,"reason":"invalid-args"}); continue
        aid = str(raw.get("action_id") or _id(tool,target,tuple(args),raw.get("objective", "")))
        accepted.append(asdict(AgentAction(aid,tool,target,tuple(args),str(raw.get("objective","")),
            tuple(str(x) for x in raw.get("expected_evidence",[]) if isinstance(x,(str,int,float))),
            risk,approval,str(raw.get("rationale","")))))
    return {"schema_version":VERSION,"accepted":accepted,"rejected":rejected,
            "governance":{"scope_checked":True,"authorization_checked":True,"registered_tools_only":True,
                           "arbitrary_command_translation":False,"secret_values_in_plan":False}}


def run_reasoning(*, root: str | Path, target: str, objective: str, operator_story: str = "",
                   observations: Iterable[Any] = (), findings: Iterable[Any] = (),
                   source_analysis: Any = None, completed_actions: Iterable[Any] = (),
                   allowed_tools: Iterable[str] = (), in_scope=lambda x: True,
                   authorized: bool = False, approval_token: str = "") -> dict[str, Any]:
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    context = build_context(target=target, objective=objective, operator_story=operator_story, observations=observations,
                            findings=findings, source_analysis=source_analysis,
                            completed_actions=completed_actions)
    provider = os.getenv("SECURITY_AI_PROVIDER", "heuristic-v363").lower()
    raw = None
    error = None
    if provider not in {"heuristic", "disabled"} and os.getenv("SECURITY_AI_URL"):
        try:
            raw = _remote(os.environ["SECURITY_AI_URL"], os.getenv("SECURITY_AI_MODEL", "security-reasoner"), context)
        except (OSError, urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            error = f"{type(exc).__name__}:{str(exc)[:240]}"
    if raw is None:
        raw = _heuristic(context)
    validated = validate_plan(raw, allowed_tools=allowed_tools, in_scope=in_scope,
                              authorized=authorized, approval_token=approval_token)
    result = {"schema_version":VERSION,"target":target,"objective":objective,
              "provider":raw.get("provider",provider),"model_output":_safe_json(_redact(raw)),
              "validated_plan":validated,"provider_error":error,"created_at":time.time(),
              "reasoning_contract":{"attacker_style_hypothesis_generation":True,
                                    "operator_narrative_ingestion":True,
                                    "self_generated_hypotheses_when_story_is_empty":True,
                                    "adaptive_replanning":True,"source_runtime_correlation":True,
                                    "multi_step_chain_planning":True,"model_controls_execution":False}}
    p = ev / "ai-offensive-agent-v363.json"
    p.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result
