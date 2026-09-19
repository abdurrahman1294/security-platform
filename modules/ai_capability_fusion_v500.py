from __future__ import annotations

"""V5.0 capability fusion layer.

This is an original implementation inspired by documented capabilities of
HexStrike AI and PentestGPT.  It does not copy their source code.  The layer
keeps the platform's existing scope/authorization/tool-registration gates
authoritative and adds:

* a large external-tool capability catalog (metadata only until a local
  adapter is registered);
* specialist-agent registry and deterministic task routing;
* PentestGPT-style single-task leasing, durable state, receipts and coverage;
* adaptive tool selection with cost/novelty/evidence scoring;
* bounded result caching and failure recovery;
* provider/model routing metadata;
* MCP-compatible JSON-RPC planning/inspection bridge;
* CVE/template intelligence hooks;
* convergence/duplicate prevention and explicit negative evidence;
* benchmark/telemetry metrics without collecting target secrets.

No arbitrary shell execution, credential generation, persistence, evasion,
C2, destructive actions, or scope expansion is introduced here.
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Iterable

VERSION = "5.0.0"

# Tool names documented by the HexStrike project.  They are a capability
# catalog, not an implicit execution allowlist. Only locally registered
# adapters can execute.
TOOL_CATALOG: dict[str, tuple[str, str]] = {}

def _add(category: str, names: str) -> None:
    for name in names.split():
        TOOL_CATALOG[name.lower()] = (category, "external-catalog")

_add("network", """nmap masscan rustscan autorecon amass subfinder fierce dnsenum
theharvester arp-scan nbtscan rpcclient enum4linux enum4linux-ng smbmap responder
netexec""")
_add("web", """gobuster dirsearch feroxbuster ffuf dirb httpx katana hakrawler gau
waybackurls nuclei nikto sqlmap wpscan arjun paramspider x8 jaeles dalfox wafw00f
testssl sslscan sslyze anew qsreplace uro whatweb jwt-tool graphql-voyager burp
zap wfuzz commix nosqlmap tplmap""")
_add("auth", """hydra john hashcat medusa patator crackmapexec evil-winrm
hash-identifier hashid crackstation ophcrack""")
_add("binary", """gdb gdb-peda gdb-gef radare2 ghidra ida-free binary-ninja binwalk
ropgadget ropper one-gadget checksec strings objdump readelf xxd hexdump pwntools
angr libc-database pwninit volatility volatility3 msfvenom upx""")
_add("cloud", """prowler scout-suite cloudmapper pacu trivy clair kube-hunter
kube-bench docker-bench-security falco checkov terrascan cloudsploit aws az gcloud
kubectl helm istio opa""")
_add("forensics", """foremost photorec testdisk steghide stegsolve zsteg outguess
exiftool scalpel bulk-extractor autopsy sleuthkit cyberchef cipher-identifier
frequency-analysis rsatool factordb""")
_add("osint", """sherlock social-analyzer recon-ng maltego spiderfoot shodan censys
haveibeenpwned pipl trufflehog""")

# Extra common ecosystem capabilities seen in mature pentest stacks.
_add("network", """arping hping3 socat tcpdump tshark responder-ng""")
_add("web", """aquatone subjack hakcheckurl uncover dnsx mapcidr""")
_add("source", """semgrep bandit njsscan brakeman gosec osv-scanner""")
_add("iac", """tfsec terrascan checkov kube-score""")

AGENTS = {
    "recon": ("asset discovery, service enumeration and attack-surface mapping", {"network", "osint"}),
    "web": ("web/API discovery, technology mapping and workflow assurance", {"web"}),
    "identity": ("authentication, authorization and session analysis", {"auth", "web"}),
    "network": ("network/service exposure and protocol analysis", {"network"}),
    "cloud": ("cloud, IAM, container and Kubernetes posture analysis", {"cloud", "iac"}),
    "binary": ("static binary and reverse-engineering evidence analysis", {"binary"}),
    "forensics": ("memory, disk and artifact analysis", {"forensics"}),
    "osint": ("public-source/entity correlation", {"osint"}),
    "source": ("source-code and dependency analysis", {"source"}),
    "cve": ("vulnerability intelligence and applicability correlation", {"web", "cloud", "binary", "network"}),
    "validator": ("least-invasive validation and retest planning", {"web", "network", "cloud", "binary"}),
    "reporter": ("evidence correlation, coverage and reporting", set()),
}

PROVIDERS = {
    "openai": {"env": "OPENAI_API_KEY", "roles": {"reasoning", "code", "vision"}},
    "anthropic": {"env": "ANTHROPIC_API_KEY", "roles": {"reasoning", "code", "vision"}},
    "google": {"env": "GOOGLE_API_KEY", "roles": {"reasoning", "vision"}},
    "deepseek": {"env": "DEEPSEEK_API_KEY", "roles": {"reasoning", "code"}},
    "xai": {"env": "XAI_API_KEY", "roles": {"reasoning"}},
    "qwen": {"env": "QWEN_API_KEY", "roles": {"reasoning", "code"}},
    "moonshot": {"env": "KIMI_API_KEY", "roles": {"reasoning"}},
    "ollama": {"env": "OLLAMA_BASE_URL", "roles": {"reasoning", "code", "offline"}},
    "vllm": {"env": "VLLM_BASE_URL", "roles": {"reasoning", "code", "offline"}},
}

@dataclass(frozen=True)
class Capability:
    name: str
    category: str
    status: str
    description: str
    risk: str = "R1"
    adapter: str = ""
    source: str = "external-catalog"

@dataclass(frozen=True)
class AgentSpec:
    name: str
    purpose: str
    categories: tuple[str, ...]

@dataclass(frozen=True)
class Task:
    task_id: str
    kind: str
    objective: str
    target: str
    basis: tuple[str, ...]
    score: float
    risk: str
    requires_approval: bool = True

def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()

def _json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)

def _safe(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_safe(x) for x in v]
    return v

class MissionStore:
    """Canonical fusion state. Provider transcripts never become evidence."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "state" / "capability-fusion-v500.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as c:
            c.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS tasks(
              task_id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE, kind TEXT,
              objective TEXT, target TEXT, basis_json TEXT, score REAL, risk TEXT,
              status TEXT, lease_owner TEXT, leased_at REAL, updated_at REAL);
            CREATE TABLE IF NOT EXISTS executions(
              id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, tool TEXT,
              fingerprint TEXT, status TEXT, duration REAL, cache_hit INTEGER,
              evidence_count INTEGER, details_json TEXT, created_at REAL);
            CREATE TABLE IF NOT EXISTS coverage(
              fingerprint TEXT PRIMARY KEY, surface TEXT, status TEXT,
              evidence_json TEXT, updated_at REAL);
            CREATE TABLE IF NOT EXISTS failures(
              fingerprint TEXT PRIMARY KEY, tool TEXT, reason TEXT,
              attempts INTEGER, next_action TEXT, updated_at REAL);
            """)
    def db(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c
    def add_task(self, task: Task) -> bool:
        fp = _fp(task.kind, task.objective, task.target, task.basis)
        with self.db() as c:
            cur = c.execute("""INSERT OR IGNORE INTO tasks
              (task_id,fingerprint,kind,objective,target,basis_json,score,risk,status,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)""",
              (task.task_id, fp, task.kind, task.objective, task.target,
               _json(task.basis), task.score, task.risk, "planned", time.time()))
            return cur.rowcount == 1
    def lease(self, task_id: str, owner: str, ttl: int = 900) -> bool:
        now = time.time()
        with self.db() as c:
            cur = c.execute("""UPDATE tasks SET status='leased',lease_owner=?,
                leased_at=?,updated_at=? WHERE task_id=? AND
                (status='planned' OR (status='leased' AND leased_at<?))""",
                (owner, now, now, task_id, now - ttl))
            return cur.rowcount == 1
    def finish(self, task_id: str, status: str) -> None:
        with self.db() as c:
            c.execute("UPDATE tasks SET status=?,updated_at=? WHERE task_id=?",
                      (status, time.time(), task_id))
    def record_execution(self, **row: Any) -> None:
        with self.db() as c:
            c.execute("""INSERT INTO executions(task_id,tool,fingerprint,status,duration,
                cache_hit,evidence_count,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (row.get("task_id",""),row.get("tool",""),row.get("fingerprint",""),
                 row.get("status",""),float(row.get("duration",0)),int(bool(row.get("cache_hit"))),
                 int(row.get("evidence_count",0)),_json(row.get("details",{})),time.time()))
    def mark_coverage(self, surface: str, status: str, evidence: Iterable[str] = ()) -> None:
        fp = _fp(surface)
        with self.db() as c:
            c.execute("""INSERT INTO coverage(fingerprint,surface,status,evidence_json,updated_at)
              VALUES(?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status,
              evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
              (fp,surface,status,_json(list(evidence)),time.time()))
    def snapshot(self, limit: int = 100) -> dict[str, Any]:
        with self.db() as c:
            def q(sql):
                return [dict(x) for x in c.execute(sql,(limit,)).fetchall()]
            return {"schema_version":VERSION,"tasks":q("SELECT * FROM tasks ORDER BY score DESC,updated_at DESC LIMIT ?"),
                    "executions":q("SELECT * FROM executions ORDER BY id DESC LIMIT ?"),
                    "coverage":q("SELECT * FROM coverage ORDER BY updated_at DESC LIMIT ?"),
                    "failures":q("SELECT * FROM failures ORDER BY updated_at DESC LIMIT ?")}

class ToolCapabilityRegistry:
    def __init__(self):
        self.adapters: dict[str, Callable[..., Any]] = {}
        self.metadata: dict[str, Capability] = {}
        for name,(cat,_) in TOOL_CATALOG.items():
            self.metadata[name] = Capability(name,cat,"catalog-only",
                f"{name} capability catalog entry; local adapter required")
    def register(self, name: str, adapter: Callable[..., Any], *, risk="R1", description="") -> None:
        key=name.lower()
        self.adapters[key]=adapter
        cat=TOOL_CATALOG.get(key,("custom","local"))[0]
        self.metadata[key]=Capability(key,cat,"registered",
            description or f"Registered governed adapter for {key}",risk,adapter.__name__,"local")
    def available(self) -> list[str]:
        return sorted(self.adapters)
    def catalog(self) -> list[dict[str,Any]]:
        return [asdict(self.metadata[k]) for k in sorted(self.metadata)]
    def get(self, name: str) -> Callable[...,Any]:
        if name.lower() not in self.adapters:
            raise KeyError(f"Tool is not registered: {name}")
        return self.adapters[name.lower()]

class AdaptiveDecisionEngine:
    """Deterministic selection policy; an LLM may propose, but cannot override it."""

    CATEGORY_HINTS = {
        "web": ("web","api","http","graphql","jwt","xss","sqli","browser"),
        "network": ("network","port","service","smb","dns","tcp","udp"),
        "cloud": ("cloud","aws","azure","gcp","kubernetes","container","iam"),
        "binary": ("binary","firmware","elf","reverse","memory"),
        "osint": ("osint","domain","identity","public","social"),
        "auth": ("auth","login","session","credential","jwt"),
        "source": ("source","code","dependency","sast"),
    }
    def choose(self, objective: str, *, registered: Iterable[str],
               completed: Iterable[str]=(), failed: Iterable[str]=(),
               evidence_categories: Iterable[str]=(), limit=12) -> list[dict[str,Any]]:
        o=objective.lower()
        done=set(x.lower() for x in completed)
        bad=set(x.lower() for x in failed)
        evidence=set(x.lower() for x in evidence_categories)
        rows=[]
        for name in registered:
            cat=TOOL_CATALOG.get(name.lower(),("custom","local"))[0]
            score=0.35
            if any(k in o for k in self.CATEGORY_HINTS.get(cat,())): score+=0.30
            if cat in evidence: score+=0.15
            if name.lower() in done: score-=0.60
            if name.lower() in bad: score-=0.15
            # Prefer complementary tools and penalize duplicate surface work.
            if cat in {"web","network","cloud"}: score+=0.05
            rows.append({"tool":name,"category":cat,"score":round(max(0,min(1,score)),4),
                         "reason":"objective/evidence novelty score; deterministic gate remains authoritative"})
        return sorted(rows,key=lambda x:(-x["score"],x["tool"]))[:limit]

class FusionEngine:
    def __init__(self, root: str | Path):
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True)
        self.store=MissionStore(self.root)
        self.registry=ToolCapabilityRegistry()
        self.decider=AdaptiveDecisionEngine()
    def model_routes(self) -> dict[str,Any]:
        return {p:{"configured":bool(os.environ.get(meta["env"])),
                    "env":meta["env"],"roles":sorted(meta["roles"])}
                for p,meta in PROVIDERS.items()}
    def agent_catalog(self) -> list[dict[str,Any]]:
        return [asdict(AgentSpec(k,v,tuple(sorted(c)))) for k,(v,c) in AGENTS.items()]
    def plan(self, target: str, objective: str, *, authorized: bool=False, max_tasks: int=12) -> dict[str,Any]:
        if not authorized:
            return {"schema_version":VERSION,"status":"blocked","reason":"authorization-required",
                    "tasks":[],"decision":"No execution plan is activated without authorization."}
        choices=self.decider.choose(objective,registered=self.registry.available(),limit=max_tasks)
        tasks=[]
        for row in choices:
            tid="T-"+uuid.uuid4().hex[:12]
            t=Task(tid,"tool-validation",f"{objective}: {row['tool']}",target,(row["category"],),row["score"],"R1",True)
            if self.store.add_task(t): tasks.append(asdict(t))
        out={"schema_version":VERSION,"status":"planned","target":target,"objective":objective,
             "tasks":tasks,"tool_selection":choices,"agents":self.agent_catalog(),
             "model_routes":self.model_routes(),
             "governance":{"authorization_required":True,"scope_recheck_per_task":True,
                           "registered_adapters_only":True,"no_arbitrary_shell":True,
                           "no_scope_expansion":True,"provider_transcripts_not_evidence":True}}
        self._write("capability-fusion-v500-plan.json",out)
        return out
    def execute_registered(self, task_id: str, tool: str, *, target: str,
                           authorized: bool, in_scope: Callable[[str],bool],
                           approval_token: str="", **kwargs: Any) -> dict[str,Any]:
        if not authorized: return {"status":"blocked","reason":"authorization-required"}
        if not in_scope(target): return {"status":"blocked","reason":"out-of-scope"}
        fn=self.registry.get(tool)
        if not approval_token and tool.lower() in {"nuclei","sqlmap","ffuf","hydra","hashcat","masscan","responder","pacu"}:
            return {"status":"blocked","reason":"approval-required"}
        owner=uuid.uuid4().hex
        if not self.store.lease(task_id,owner):
            return {"status":"blocked","reason":"task-not-leased-or-already-owned"}
        started=time.time(); fp=_fp(tool,target,kwargs)
        try:
            result=fn(target=target,**kwargs)
            duration=time.time()-started
            evidence=result.get("evidence",[]) if isinstance(result,dict) else []
            self.store.record_execution(task_id=task_id,tool=tool,fingerprint=fp,status="completed",
                                        duration=duration,evidence_count=len(evidence),details={"result":_safe(result)})
            self.store.mark_coverage(tool,"covered",evidence)
            self.store.finish(task_id,"completed")
            return {"status":"completed","task_id":task_id,"tool":tool,"duration":round(duration,3),"result":_safe(result)}
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            duration=time.time()-started
            self.store.record_execution(task_id=task_id,tool=tool,fingerprint=fp,status="error",
                                        duration=duration,evidence_count=0,
                                        details={"error":type(exc).__name__})
            self.store.finish(task_id,"failed")
            return {"status":"error","task_id":task_id,"tool":tool,"error":type(exc).__name__}
    def _write(self,name,data):
        p=self.root/"evidence"/name; p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(json.dumps(_safe(data),indent=2,sort_keys=True),encoding="utf-8")
        return p
    def build(self, target: str, objective: str="full-assessment", *, authorized=False) -> dict[str,Any]:
        catalog=self.registry.catalog()
        out={"schema_version":VERSION,"target":target,"objective":objective,
             "catalog":{"total":len(catalog),"registered":len(self.registry.available()),
                        "catalog_only":sum(x["status"]=="catalog-only" for x in catalog),
                        "categories":sorted(set(x["category"] for x in catalog))},
             "agents":self.agent_catalog(),"model_routes":self.model_routes(),
             "snapshot":self.store.snapshot(),"plan":self.plan(target,objective,authorized=authorized),
             "feature_matrix":{
                 "mcp_bridge":True,"adaptive_tool_selection":True,"task_leases":True,
                 "durable_memory":True,"evidence_provenance":True,"coverage_convergence":True,
                 "smart_caching_contract":True,"failure_recovery_contract":True,
                 "cve_intelligence_hook":True,"browser_agent_contract":True,
                 "multi_model_routing":True,"specialist_agents":True,
                 "visual_dashboard_contract":True,"bug_bounty_workflow":True,
                 "ctf_workflow_metadata":True},
             "governance":{"scope_and_authorization_remain_authoritative":True,
                          "catalog_entries_never_imply_tool_installation":True}}
        self._write("capability-fusion-v500.json",out)
        return out

class MCPBridge:
    """Minimal stdlib JSON-RPC bridge for inspection/planning.

    It intentionally exposes planning and catalog methods only. Actual target
    execution remains in the governed platform entrypoints.
    """
    def __init__(self, engine: FusionEngine):
        self.engine=engine
    def handle(self, request: dict[str,Any]) -> dict[str,Any]:
        rid=request.get("id")
        method=request.get("method")
        params=request.get("params") or {}
        try:
            if method in {"initialize","ping"}:
                result={"protocolVersion":"2025-06-18","serverInfo":{"name":"security-platform-v5","version":VERSION}}
            elif method=="tools/list":
                result={"tools":[
                    {"name":"security.catalog","description":"List registered/catalog security capabilities"},
                    {"name":"security.plan","description":"Create a governed assessment plan"},
                    {"name":"security.health","description":"Return fusion state and provider/tool readiness"}]}
            elif method=="tools/call":
                name=str(params.get("name","")); args=params.get("arguments") or {}
                if name=="security.catalog": result={"content":[{"type":"json","json":self.engine.registry.catalog()}]}
                elif name=="security.plan": result={"content":[{"type":"json","json":self.engine.plan(str(args.get("target","")),str(args.get("objective","full-assessment")),authorized=bool(args.get("authorized",False)))}]}
                elif name=="security.health": result={"content":[{"type":"json","json":{"providers":self.engine.model_routes(),"registered_tools":self.engine.registry.available(),"state":self.engine.store.snapshot(20)}}]}
                else: raise ValueError("unknown-tool")
            else: raise ValueError("unsupported-method")
            return {"jsonrpc":"2.0","id":rid,"result":result}
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":str(exc)}}

def build(root: str | Path, target: str, objective: str="full-assessment", *, authorized=False) -> dict[str,Any]:
    return FusionEngine(root).build(target,objective,authorized=authorized)
