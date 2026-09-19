from __future__ import annotations
import json, shutil
from json import JSONDecodeError
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from .tool_manager_v40 import ToolManager, TOOLS
from .result_collector_v43 import collect
from .scope import load_scope, filter_in_scope
from .atomic_io import atomic_write_json, load_json

class ExecutionOrchestrator:
    """V101 dependency-aware, resumable execution over the registered toolchain."""
    GRAPH = {
        "recon-subfinder": [], "recon-assetfinder": [],
        "merge-assets": ["recon-subfinder", "recon-assetfinder"],
        "http-probe": ["merge-assets"], "port-discovery": ["merge-assets"],
        "service-enumeration": ["port-discovery"],
        "web-crawl": ["http-probe"], "vulnerability-discovery": ["http-probe"],
    }
    TOOL_FOR = {"recon-subfinder":"subfinder","recon-assetfinder":"assetfinder","http-probe":"httpx",
                "port-discovery":"naabu","service-enumeration":"nmap","web-crawl":"katana","vulnerability-discovery":"nuclei"}
    def __init__(self, root, target, scope_file, *, max_workers=3, resume=True):
        self.root=Path(root); self.target=target; self.scope_file=scope_file
        self.scope=load_scope(scope_file) if scope_file and Path(scope_file).exists() else []
        self.max_workers=max(1,min(int(max_workers),6)); self.resume=resume
        self.state_path=self.root/'evidence'/'execution-state-v101.json'
        self.root.joinpath('evidence').mkdir(parents=True,exist_ok=True)
        self.state=self._load()
        self.tm=ToolManager(self.root)
    def _load(self):
        if self.resume and self.state_path.exists():
            # load_json quarantines a corrupt state file (renames it aside
            # with a timestamp) instead of the previous bare `except
            # Exception: pass`, which silently discarded a damaged file
            # and any diagnostic trace of why resume stopped working.
            data = load_json(self.state_path, None)
            if isinstance(data, dict):
                return data
        return {'schema_version':'101.0','target':self.target,'started':datetime.now(timezone.utc).isoformat(),'tasks':{}}
    def _save(self):
        # Atomic write so a killed/interrupted run can't leave a truncated
        # state file behind -- previously a plain write_text() here meant
        # an interruption mid-save could corrupt the very state that
        # 'resumable execution' depends on.
        atomic_write_json(self.state_path, self.state)
    def _task(self, tid):
        return self.state['tasks'].get(tid, {})
    def _run_tool(self, tid, tool, argv):
        if shutil.which(TOOLS[tool].executable) is None:
            row={'status':'skipped','reason':'tool-not-installed','tool':tool,'argv':argv}
            self.state['tasks'][tid]=row; self._save(); return row
        task={'task_id':'V101-'+tid,'action':tid,'tool':tool}
        try:
            proc=self.tm.run(tool,argv)
            path=collect(self.root,task,proc.stdout,proc.stderr,proc.returncode,command=argv)
            row={'status':'completed' if proc.returncode==0 else 'failed','tool':tool,'result':str(path),'returncode':proc.returncode,'stdout':proc.stdout}
        except (OSError, RuntimeError, ValueError) as exc:
            row={'status':'failed','tool':tool,'error':str(exc),'argv':argv}
        self.state['tasks'][tid]=row; self._save(); return row
    def _parallel_roots(self):
        pending=[x for x in ('recon-subfinder','recon-assetfinder') if self._task(x).get('status')!='completed']
        if not pending:return
        with ThreadPoolExecutor(max_workers=min(self.max_workers,len(pending))) as ex:
            fut={ex.submit(self._run_tool,t,self.TOOL_FOR[t],([self.TOOL_FOR[t],'-d',self.target,'-silent'] if t=='recon-subfinder' else [self.TOOL_FOR[t],'--subs-only',self.target])):t for t in pending}
            for f in as_completed(fut): f.result()
    def run(self):
        for d in ['recon','ports','web','vulns','evidence']:(self.root/d).mkdir(parents=True,exist_ok=True)
        self._parallel_roots()
        # Merge is deterministic and fail-closed when scope is unavailable.
        vals=set()
        for tid in ('recon-subfinder','recon-assetfinder'):
            out=self._task(tid).get('stdout','')
            vals.update(x.strip().lstrip('*.').lower() for x in out.splitlines() if x.strip())
        subs=filter_in_scope(sorted(vals),allowed=self.scope) if self.scope else []
        if self.target and self.scope and self.target.lower() in self.scope and self.target not in subs: subs.append(self.target.lower())
        subs=sorted(set(subs)); (self.root/'recon'/'subdomains.txt').write_text('\n'.join(subs)+('\n' if subs else ''))
        self.state['tasks']['merge-assets']={'status':'completed','count':len(subs)}; self._save()
        if self._task('http-probe').get('status')!='completed':
            self._run_tool('http-probe','httpx',['httpx','-l',str(self.root/'recon'/'subdomains.txt'),'-json','-silent','-status-code','-title','-tech-detect'])
        if self._task('port-discovery').get('status')!='completed':
            self._run_tool('port-discovery','naabu',['naabu','-list',str(self.root/'recon'/'subdomains.txt'),'-silent','-top-ports','100'])
        if self._task('service-enumeration').get('status')!='completed':
            self._run_tool('service-enumeration','nmap',['nmap','-sV','--top-ports','100','--open','-iL',str(self.root/'recon'/'subdomains.txt'),'-oN',str(self.root/'ports'/'v101-nmap.txt')])
        live=[]
        for line in self._task('http-probe').get('stdout','').splitlines():
            try:
                obj=json.loads(line); u=obj.get('url','')
                if u: live.append(u)
            except JSONDecodeError: pass
        (self.root/'web'/'urls.txt').write_text('\n'.join(sorted(set(live)))+('\n' if live else ''))
        if live:
            if self._task('web-crawl').get('status')!='completed': self._run_tool('web-crawl','katana',['katana','-list',str(self.root/'web'/'urls.txt'),'-silent','-d','2','-jc'])
            if self._task('vulnerability-discovery').get('status')!='completed': self._run_tool('vulnerability-discovery','nuclei',['nuclei','-l',str(self.root/'web'/'urls.txt'),'-silent','-severity','medium,high,critical','-jsonl'])
        else:
            self.state['tasks']['web-crawl']={'status':'blocked','reason':'no-live-http-targets'}
            self.state['tasks']['vulnerability-discovery']={'status':'blocked','reason':'no-live-http-targets'}
        self.state['finished']=datetime.now(timezone.utc).isoformat(); self._save()
        return self.state_path,self.state

def build_plan(root, target):
    p=Path(root)/'evidence'/'execution-plan-v101.json'; p.parent.mkdir(parents=True,exist_ok=True)
    data={'schema_version':'101.0','target':target,'graph':ExecutionOrchestrator.GRAPH,'properties':['dependency-aware','resumable','bounded-concurrency','scope-enforced','registered-tools-only']}
    p.write_text(json.dumps(data,indent=2)); return p
