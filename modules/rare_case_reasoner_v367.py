"""V3.67 Rare-Case Reasoner.

Provides case-based reasoning for unusual assessments. It retrieves analogous
historical cases, transfers only evidence-supported patterns, and creates novel
hypotheses through constraint decomposition and experiment design. It never
executes arbitrary model output.
"""
from __future__ import annotations
import hashlib, json, math, re, time
from pathlib import Path
from typing import Any, Iterable

VERSION="3.67.0"
STOPWORDS={"the","and","this","that","with","from","have","into","what","when","where","then","could","would","should","want","test","target"}

def tokens(text:str)->set[str]:
    return {x for x in re.findall(r"[a-z0-9_/-]{3,}",text.lower()) if x not in STOPWORDS}

def similarity(a:str,b:str)->float:
    A,B=tokens(a),tokens(b)
    if not A or not B:return 0.0
    return len(A&B)/max(1,len(A|B))

def _load_cases(root:Path)->list[dict[str,Any]]:
    p=root/"knowledge"/"cases.jsonl"
    if not p.exists(): return []
    out=[]
    for line in p.read_text(encoding="utf-8",errors="ignore").splitlines()[-500:]:
        try:
            x=json.loads(line)
            if isinstance(x,dict): out.append(x)
        except Exception: pass
    return out

def _fingerprint(problem:str)->str:
    return hashlib.sha256(" ".join(sorted(tokens(problem))).encode()).hexdigest()[:16]

def reason(*, root:str|Path, problem:str, story:str="", evidence:Iterable[Any]=(), historical_cases:Iterable[Any]=(), max_analogies:int=5)->dict[str,Any]:
    root=Path(root); problem=(problem or "").strip()
    if not problem: raise ValueError("problem is required")
    evidence=list(evidence); cases=list(historical_cases) or _load_cases(root)
    query=problem+" "+story+" "+json.dumps(evidence,ensure_ascii=False)
    ranked=[]
    for c in cases:
        desc=str(c.get("problem") or c.get("summary") or c.get("case") or "")
        s=similarity(query,desc)
        if s>=.08: ranked.append((s,c))
    ranked.sort(key=lambda x:-x[0]); analogies=[]
    for s,c in ranked[:max_analogies]:
        analogies.append({"similarity":round(s,3),"case_id":c.get("case_id","unknown"),"lesson":c.get("lesson") or c.get("lesson_learned") or c.get("resolution") or "Reuse only the evidence-supported pattern; verify assumptions independently."})
    # Novel reasoning is a structured search over constraints, not a claim that a model has seen the case before.
    novel=[
        {"hypothesis":"Trust-boundary mismatch","why":"The unusual behavior may arise from different assumptions between components, identities, proxies, or services.","test":"Map inputs, identities, transformations and trust boundaries; compare behavior at each boundary."},
        {"hypothesis":"State-dependent behavior","why":"Rare flaws often appear only after a sequence of state changes rather than a single request.","test":"Record state transitions and compare the same action from clean, authenticated, and alternate-role states."},
        {"hypothesis":"Parser or representation disagreement","why":"Different components may interpret the same value differently.","test":"Identify normalization, encoding, parsing and canonicalization boundaries and compare representations."},
        {"hypothesis":"Unexpected composition","why":"Two individually low-severity observations may create a meaningful path when composed.","test":"Construct a dependency graph and check whether one observation unlocks another capability."},
        {"hypothesis":"Hidden precondition","why":"A failed obvious test can indicate a missing prerequisite rather than a dead end.","test":"List prerequisites for the suspected behavior and test the least invasive missing prerequisite one at a time."},
    ]
    plan=[
        "Decompose the case into observable facts, assumptions, constraints, and unknowns.",
        "Retrieve analogous cases and explicitly mark which lessons transfer and which assumptions do not.",
        "Generate competing hypotheses rather than locking onto the first explanation.",
        "Choose the smallest high-information experiment that separates the leading hypotheses.",
        "After each result, update the case model, preserve failures, and search for newly unlocked paths.",
        "Require reproducible evidence before declaring the unusual behavior a vulnerability.",
    ]
    out={"schema_version":VERSION,"created_at":time.time(),"case_fingerprint":_fingerprint(problem),"problem":problem,"story":story[:30000],"analogous_cases":analogies,"novel_hypotheses":novel,"reasoning_plan":plan,"confidence":{"analogical":round(max([x[0] for x in ranked[:1]]+[0]),3),"novelty":"heuristic"},"execution_contract":{"reasoning_only":True,"no_arbitrary_execution":True}}
    p=root/"evidence"; p.mkdir(parents=True,exist_ok=True); (p/f"rare-case-{out['case_fingerprint']}.json").write_text(json.dumps(out,indent=2,sort_keys=True),encoding="utf-8")
    return out

def learn_case(root:str|Path, *, problem:str, lesson:str, resolution:str="", tags:Iterable[str]=()):
    root=Path(root); p=root/"knowledge"; p.mkdir(parents=True,exist_ok=True)
    case={"case_id":"case-"+_fingerprint(problem),"created_at":time.time(),"problem":problem[:5000],"lesson":lesson[:5000],"resolution":resolution[:5000],"tags":list(tags)}
    with (p/"cases.jsonl").open("a",encoding="utf-8") as f:f.write(json.dumps(case,ensure_ascii=False)+"\n")
    return case
