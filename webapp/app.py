from __future__ import annotations
import asyncio, json, time, uuid
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from security_platform.core.engagement import Engagement
from security_platform.core.policy import ScopePolicy
from security_platform.core.preflight import check as preflight_check
from security_platform.engines import PentestEngine
from modules.specialist_orchestrator_v368 import select_specialists
from modules.cyber_advisor_v366 import advise
from modules.security_conversation_v367 import SecurityConversation

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "webapp" / "static"
app = FastAPI(title="Security Platform", version="4.1.0", docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

@app.middleware("http")
async def no_cache_local_ui(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

class Mission(BaseModel):
    client: str = Field(default="authorized-lab", max_length=200)
    target: str = Field(default="127.0.0.1", max_length=500)
    scope: str = Field(default=str(ROOT / "config" / "scope.example.txt"), max_length=1000)
    output: str = Field(default=str(ROOT / "output" / "web-engagement"), max_length=1000)
    objective: str = Field(default="adaptive security assessment", max_length=10000)
    story: str = Field(default="", max_length=30000)
    authorized: bool = False
    approval_token: str = ""
    max_rounds: int = Field(default=3, ge=1, le=5)
    max_specialists: int = Field(default=5, ge=1, le=8)

class Question(BaseModel):
    mission: Mission
    question: str = Field(min_length=1, max_length=10000)

class ChatMessage(BaseModel):
    mission: Mission
    message: str = Field(min_length=1, max_length=10000)

def engine_for(m: Mission) -> PentestEngine:
    scope = Path(m.scope).expanduser().resolve()
    out = Path(m.output).expanduser().resolve()
    engagement = Engagement(m.client, m.target, out, scope)
    policy = ScopePolicy.from_file(scope, engagement.target_host)
    return PentestEngine(engagement, policy)

def conversation_for(m: Mission) -> SecurityConversation:
    return SecurityConversation(Path(m.output).expanduser().resolve(), target=m.target, engagement=m.client)

def _safe_json(result: Any) -> Any:
    if isinstance(result, Path): return str(result)
    if isinstance(result, dict): return {str(k): _safe_json(v) for k, v in result.items()}
    if isinstance(result, (list, tuple, set)): return [_safe_json(v) for v in result]
    try:
        json.dumps(result)
        return result
    except TypeError:
        return str(result)

def mission_dict(m: Mission) -> dict[str, Any]:
    return {"client":m.client,"target":m.target,"scope":m.scope,"output":m.output,"objective":m.objective,"story":m.story,"authorized":m.authorized}

@app.get("/")
def index(): return FileResponse(STATIC / "index.html")

@app.get("/api/health")
def health():
    return {"status":"ok","platform":"Security Platform","version":"4.1.0","execution":"local","governed":True}

@app.post("/api/specialists")
def specialists(m: Mission):
    return {"specialists": select_specialists(story=m.story, objective=m.objective, max_specialists=m.max_specialists)}

@app.post("/api/advisor")
def advisor(q: Question):
    m=q.mission
    context={
        "objective": m.objective,
        "story": m.story,
        "authorized": m.authorized,
        "scope": m.scope,
    }
    try:
        result=advise(question=q.question, target=m.target, engagement=m.client, context=context, root=Path(m.output).expanduser().resolve())
    except (ValueError, OSError, RuntimeError, TypeError) as exc:
        raise HTTPException(400, str(exc))
    return _safe_json(result)

@app.post("/api/conversation")
def conversation(q: ChatMessage):
    m=q.mission
    try: return {"result": conversation_for(m).ask(q.message, story=m.story)}
    except (ValueError, OSError, RuntimeError, TypeError) as exc: raise HTTPException(400, str(exc))

@app.post("/api/intelligence/attack-path")
def attack_path(m: Mission):
    if not m.authorized: raise HTTPException(403,"Authorization confirmation is required")
    try: return _safe_json(engine_for(m).autonomous_attack_path_v367(story=m.story))
    except (ValueError,OSError,RuntimeError,TypeError) as exc: raise HTTPException(400,str(exc))

@app.post("/api/intelligence/rare-case")
def rare_case(q: Question):
    m=q.mission
    if not m.authorized: raise HTTPException(403,"Authorization confirmation is required")
    try: return _safe_json(engine_for(m).rare_case_reasoner_v367(problem=q.question, story=m.story))
    except (ValueError,OSError,RuntimeError,TypeError) as exc: raise HTTPException(400,str(exc))

@app.post("/api/mission/reason")
def reason(m: Mission):
    if not m.authorized: raise HTTPException(403,"Authorization confirmation is required before active reasoning/execution")
    try:
        return _safe_json(engine_for(m).autonomous_offensive_intelligence_v410(objective=m.objective, story=m.story, max_rounds=m.max_rounds, max_specialists=m.max_specialists, approval_token=m.approval_token, authorized=True))
    except (ValueError,OSError,RuntimeError) as exc: raise HTTPException(400,str(exc))

@app.websocket("/api/mission/live")
async def live_mission(ws: WebSocket):
    await ws.accept()
    try:
        raw=await ws.receive_text(); m=Mission.model_validate_json(raw)
        if not m.authorized:
            await ws.send_json({"type":"error","message":"Authorization confirmation is required"}); await ws.close(code=1008); return
        run_id=str(uuid.uuid4())
        await ws.send_json({"type":"started","run_id":run_id,"message":"Governed specialist loop started"})
        # Keep the browser visibly informed while the existing synchronous engine runs.
        task=asyncio.create_task(asyncio.to_thread(engine_for(m).autonomous_offensive_intelligence_v410, objective=m.objective, story=m.story, max_rounds=m.max_rounds, max_specialists=m.max_specialists, approval_token=m.approval_token, authorized=True))
        while not task.done():
            await ws.send_json({"type":"heartbeat","at":time.time(),"message":"Engine working; collecting and correlating evidence…"})
            await asyncio.sleep(0.8)
        result=await task
        await ws.send_json({"type":"completed","result":_safe_json(result)})
        await ws.close()
    except WebSocketDisconnect: return
    except Exception as exc:
        try: await ws.send_json({"type":"error","message":f"{type(exc).__name__}: {str(exc)[:500]}"}); await ws.close(code=1011)
        except Exception: pass

@app.post("/api/mission/action/{action}")
def action(action: str, m: Mission):
    allowed={"precheck":"__canonical_preflight__","discover":"recon","ports":"ports","probe":"probe","web":"crawl_and_scan","api":"api","exploit":"exploitation_loop","report":"finalize","adaptive":"autonomous_offensive_intelligence_v410"}
    if action not in allowed: raise HTTPException(404,"Unknown named capability")
    if not m.authorized: raise HTTPException(403,"Authorization confirmation is required")
    try:
        engine=engine_for(m)
        if action == "precheck":
            result = preflight_check(engine.e.target, engine.e.scope_file, active=True).to_dict()
        else:
            result = getattr(engine, allowed[action])()
        return {"action":action,"result":_safe_json(result)}
    except (ValueError,OSError,RuntimeError,TypeError,AttributeError) as exc: raise HTTPException(400,str(exc))

@app.get("/api/intelligence/state")
def intelligence_state(output: str):
    root=Path(output).expanduser().resolve()
    path=root/"evidence"/"autonomous-offensive-intelligence-v400.json"
    if not path.is_file(): return {"status":"not-started","state":None}
    return _safe_json(json.loads(path.read_text(encoding="utf-8")))

@app.get("/api/evidence")
def evidence(output: str):
    root=Path(output).expanduser().resolve(); ev=root/"evidence"
    if not ev.exists(): return {"files":[]}
    files=[]
    for p in sorted(ev.rglob("*")):
        if p.is_file(): files.append({"name":str(p.relative_to(ev)),"size":p.stat().st_size,"modified":p.stat().st_mtime})
    return {"files":files[-300:]}
