from __future__ import annotations
"""Persistent, evidence-driven investigation loop.

This is an orchestration/intelligence layer. It consumes bounded assessment
artifacts, updates a state graph, retires stale hypotheses, creates the next
low-risk investigative tasks, and escalates tasks that require operator-led or
higher-impact validation. It never creates authority, expands scope, or
executes arbitrary payloads.
"""
import json, hashlib, re, logging
logger = logging.getLogger(__name__)
from pathlib import Path
from typing import Any
from .atomic_io import atomic_write_json

VERSION = "2.9"
MAX_FILES = 500
MAX_BYTES = 512_000
SECRET = re.compile(r"(password|passwd|secret|token|cookie|authorization|api[_-]?key|private[_-]?key)", re.I)
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b|\b(?:127\.0\.0\.1|localhost)\b", re.I)
SIGNALS = {
    "auth": (re.compile(r"\b(login|signin|logout|session|oauth|sso|jwt|bearer|cookie)\b", re.I), "authentication/session boundary"),
    "api": (re.compile(r"\b(openapi|swagger|graphql|/api/|api/v\d+)\b", re.I), "API surface"),
    "workflow": (re.compile(r"\b(workflow|state transition|checkout|approval|reset|invite|transfer)\b", re.I), "stateful workflow"),
    "protocol": (re.compile(r"\b(unknown protocol|custom protocol|tcp/\d+|udp/\d+)\b", re.I), "unknown/custom protocol"),
    "cloud": (re.compile(r"\b(aws|azure|gcp|iam|role|security group|s3|bucket|vpc)\b", re.I), "cloud identity/resource relationship"),
    "mobile": (re.compile(r"\b(android|apk|manifest|webview|adb|ios|mobile)\b", re.I), "mobile artifact"),
    "wireless": (re.compile(r"\b(wifi|wi-fi|pcap|bssid|ssid|802\.11|bluetooth|ble)\b", re.I), "wireless artifact"),
    "binary": (re.compile(r"\b(elf|pe32|mach-o|binary|executable|\.so|\.dll|\.exe)\b", re.I), "binary artifact"),
}

def _redact(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: "[REDACTED]" if SECRET.search(str(k)) else _redact(x) for k, x in v.items()}
    if isinstance(v, list): return [_redact(x) for x in v]
    return v

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

def _artifacts(root: Path) -> list[dict[str, Any]]:
    out=[]
    for p in sorted(root.rglob("*")):
        if len(out)>=MAX_FILES or not p.is_file() or p.name.startswith("adaptive-investigation-v29"):
            continue
        if any(x in p.parts for x in (".git", ".pytest_cache", "__pycache__", "evidence")): continue
        try:
            if p.stat().st_size > MAX_BYTES: continue
            t=p.read_text(encoding="utf-8", errors="ignore")[:MAX_BYTES]
        except OSError: continue
        out.append({"path":str(p.relative_to(root)),"digest":_digest(t),"text":t})
    return out

def _observe(arts):
    env={"hosts":set(),"urls":set(),"technologies":set()}; signals=[]
    for a in arts:
        text=a["text"]
        env["hosts"].update(HOST.findall(text)); env["urls"].update(x.rstrip(".,)") for x in URL.findall(text))
        for k,(rx,label) in SIGNALS.items():
            if rx.search(text): signals.append((k,label,a["path"]))
    grouped={}
    for k,label,path in signals:
        grouped.setdefault(k,{"kind":k,"label":label,"sources":[]})["sources"].append(path)
    for x in grouped.values(): x["sources"]=sorted(set(x["sources"]))[:20]
    return {"hosts":sorted(env["hosts"])[:1000],"urls":sorted(env["urls"])[:1000],"signals":sorted(grouped.values(),key=lambda x:x["kind"])}

def _state(root: Path):
    p=root/"evidence"/"adaptive-investigation-v29.json"
    if not p.exists():
        return {"schema_version":VERSION,"iteration":0,"observations":{},"hypotheses":{},"tasks":{},"history":[]}
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return {"schema_version":VERSION,"iteration":0,"observations":{},"hypotheses":{},"tasks":{},"history":[],"recovered_corrupt_state":True}

def _result_files(root: Path):
    names={"adaptive-result.json","experiment-result.json","test-result.json","platform-run.json","pentest-result.json"}
    out=[]
    for p in root.rglob("*.json"):
        if p.name in names or "results" in p.parts:
            try:
                if p.stat().st_size<=MAX_BYTES: out.append((str(p.relative_to(root)),json.loads(p.read_text(encoding="utf-8"))))
            except Exception as exc: logger.debug("malformed evidence file skipped: %s", exc)
    return out

def _status_for_signal(k):
    return {"auth":"state-model","api":"api-inventory","workflow":"workflow-model","protocol":"protocol-characterization","cloud":"cloud-readonly-graph","mobile":"mobile-triage","wireless":"passive-radio-analysis","binary":"binary-static-triage"}.get(k,"manual-characterization")

def build(root: str|Path, *, target="", scope="", authorized=False, max_iterations=1):
    root=Path(root); (root/"evidence").mkdir(parents=True,exist_ok=True)
    state=_state(root); arts=_artifacts(root); obs=_observe(arts)
    state["iteration"]=int(state.get("iteration",0))+1
    state["schema_version"]=VERSION
    state["observations"]={"target":target,"scope":scope,"artifact_count":len(arts),"hosts":obs["hosts"],"urls":obs["urls"],"signals":obs["signals"]}
    existing=state.setdefault("hypotheses",{}); tasks=state.setdefault("tasks",{})
    seen=set()
    for s in obs["signals"]:
        hid=f"H-{s['kind']}"; seen.add(hid)
        h=existing.get(hid,{"id":hid,"kind":s["kind"],"statement":f"The observed {s['label']} may warrant further investigation.","status":"open","confidence":"candidate","observations":[]})
        h["observations"]=s["sources"]; h["last_seen_iteration"]=state["iteration"]
        existing[hid]=h
        tid=f"T-{s['kind']}"; tasks[tid]={"id":tid,"hypothesis_id":hid,"experiment":_status_for_signal(s["kind"]),"risk":"low","status":"ready","auto_execute":False,"requires_scope":True,"requires_operator":True,"fallback":"collect more passive evidence or escalate"}
    for hid,h in existing.items():
        if hid not in seen and h.get("status")=="open": h["status"]="stale"
    consumed=[]
    for path,data in _result_files(root):
        consumed.append(path)
        if isinstance(data,dict):
            tid=data.get("task_id") or data.get("experiment_id")
            if tid in tasks:
                tasks[tid]["status"]="completed" if data.get("status") in {"completed","pass","confirmed"} else "review"
                tasks[tid]["result_artifact"]=path
                hid=tasks[tid]["hypothesis_id"]
                if hid in existing: existing[hid]["status"]="supported" if tasks[tid]["status"]=="completed" else "needs-review"
    ready=[x for x in tasks.values() if x.get("status")=="ready"]
    escalations=[]
    for x in ready:
        if x["experiment"] in {"protocol-characterization","binary-static-triage"}:
            escalations.append({"task_id":x["id"],"reason":"specialized analysis may require operator guidance"})
    data={"schema_version":VERSION,"target":target,"scope":scope,"authorized_context":bool(authorized),"iteration":state["iteration"],"environment":obs,"hypotheses":list(existing.values()),"tasks":list(tasks.values()),"ready_tasks":ready,"consumed_results":consumed,"escalations":escalations,"loop":{"observe":True,"classify":True,"hypothesize":True,"consume_results":bool(consumed),"replan":True,"next_iteration_available":bool(ready),"max_iterations":max(1,min(int(max_iterations),10))},"decision_policy":{"no_scope_expansion":True,"no_arbitrary_payloads":True,"no_credential_guessing":True,"no_high_impact_auto_execution":True,"unknown_defaults_to_human":True}}
    state["history"].append({"iteration":state["iteration"],"ready_count":len(ready),"consumed_results":consumed})
    state["history"]=state["history"][-50:]
    atomic_write_json(root/"evidence"/"adaptive-investigation-v29.json",_redact(state))
    atomic_write_json(root/"evidence"/"adaptive-next-actions-v29.json",_redact(data))
    return data
