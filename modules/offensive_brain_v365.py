"""V3.65 Adaptive Offensive Brain.

A reasoning coordinator for authorized assessments. Python remains the primary
capability provider; the AI is a second reasoning/exploration method, and the
hybrid mode continuously feeds Python evidence back into the AI.

The model may reason broadly, but execution is always expressed as structured
registered-tool actions and rechecked by the platform before execution.
"""
from __future__ import annotations
import json, os, time
from pathlib import Path
from typing import Any, Iterable

VERSION = "3.65.0"


def _load_jsons(root: Path, limit: int = 120) -> list[dict[str, Any]]:
    ev = root / "evidence"
    out=[]
    if not ev.exists(): return out
    for p in sorted(ev.glob("*.json"), key=lambda x: x.stat().st_mtime):
        try:
            obj=json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        out.append({"artifact":p.name,"data":obj})
    return out[-limit:]


def build_brain_context(root: str | Path, *, target: str, objective: str,
                        story: str = "", prior_findings: Iterable[Any] = ()) -> dict[str, Any]:
    root=Path(root)
    observations=_load_jsons(root)
    findings=list(prior_findings)[-80:]
    return {
        "schema_version": VERSION,
        "target": target,
        "objective": objective,
        "operator_story": story[:30000],
        "observations": observations,
        "prior_findings": findings,
        "reasoning_questions": [
            "What is the strongest attacker-relevant hypothesis?",
            "What evidence supports or contradicts it?",
            "What is the cheapest safe test that would reduce uncertainty?",
            "What alternative attack path should be considered if the first hypothesis fails?",
            "Can several weak observations form a meaningful attack chain?",
            "What evidence would be required before calling the finding proven?",
        ],
    }


def summarize_context(ctx: dict[str, Any]) -> dict[str, Any]:
    """Deterministic meta-analysis used even when no external AI provider exists."""
    text=(ctx.get("operator_story","") + " " + json.dumps(ctx.get("observations",[]), ensure_ascii=False)).lower()
    keyword_map={
        "access-control": ["idor","authorization","access control","another user","role"],
        "injection": ["sql","sqli","injection","query","database"],
        "client-side": ["xss","script","dom","javascript"],
        "server-side": ["ssrf","ssti","template","internal service"],
        "authentication": ["jwt","session","cookie","login","authentication"],
        "routing": ["redirect","host header","smuggling","proxy"],
        "file-handling": ["lfi","path traversal","upload","file"],
    }
    signals=[]
    for cls, words in keyword_map.items():
        hits=sum(text.count(w) for w in words)
        if hits: signals.append({"class":cls,"signal_strength":min(1.0, hits/4),"hits":hits})
    signals.sort(key=lambda x:(-x["signal_strength"],x["class"]))
    return {"signals":signals,"observation_count":len(ctx.get("observations",[])),
            "finding_count":len(ctx.get("prior_findings",[])),
            "story_present":bool(ctx.get("operator_story","").strip())}


def run_brain(*, root: str | Path, target: str, objective: str, story: str = "",
              prior_findings: Iterable[Any] = (), max_cycles: int = 4) -> dict[str, Any]:
    ctx=build_brain_context(root,target=target,objective=objective,story=story,prior_findings=prior_findings)
    meta=summarize_context(ctx)
    provider=os.getenv("SECURITY_AI_PROVIDER","heuristic-v365").lower()
    result={"schema_version":VERSION,"created_at":time.time(),"target":target,
            "objective":objective,"provider":provider,"context":ctx,"meta_analysis":meta,
            "loop_design":{"python_first":True,"ai_reasoning":True,"hybrid_feedback":True,
                           "max_cycles":max(1,min(int(max_cycles),8)),
                           "reason_about_failures":True,"revisit_suppression":True,
                           "evidence_before_claim":True}}
    p=Path(root)/"evidence"; p.mkdir(parents=True,exist_ok=True)
    (p/"offensive-brain-v365.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf-8")
    return result
