#!/usr/bin/env python3
"""V44 guarded assessment pipeline runner.

Executes only registered tools through ToolManager and only after the caller has
already passed the framework authorization/scope gate. It uses files generated
inside the engagement directory and never accepts arbitrary shell strings.
"""
from __future__ import annotations
import json, shlex
from pathlib import Path
from .pipeline_v42 import build_pipeline
from .result_collector_v43 import collect, load_results
from .tool_manager_v40 import ToolManager
from .scope import load_scope, filter_in_scope

class PipelineRunner:
    def __init__(self, root, target, scope_file="", profile="full"):
        self.root=Path(root); self.target=target; self.scope_file=scope_file; self.profile=profile
        self.tm=ToolManager(self.root)
    def _read_targets(self):
        p=self.root/"recon"/"subdomains.txt"
        if p.exists():
            vals=[x.strip() for x in p.read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip()]
            return vals[:500]
        return [self.target]
    def _argv(self, action):
        targets=self._read_targets()
        if action=="external-recon": return ["subfinder","-d",self.target,"-silent"]
        if action=="http-probe":
            inp=self.root/"evidence"/"pipeline-http-input.txt"; inp.write_text("\n".join(targets)+"\n",encoding="utf-8")
            return ["httpx","-l",str(inp),"-json","-silent"]
        if action=="port-discovery": return ["naabu","-host",self.target,"-silent","-top-ports","100"]
        if action=="service-enumeration": return ["nmap","-sV","--top-ports","100","--open","-oN",str(self.root/"evidence"/"pipeline-nmap.txt"),self.target]
        if action=="web-crawl": return ["katana","-u",self.target,"-silent","-jc"]
        if action=="vulnerability-discovery": return ["nuclei","-u",self.target,"-silent"]
        raise ValueError(f"Unsupported pipeline action: {action}")
    def run_next(self):
        ep,_=build_pipeline(self.root,self.target,scope_file=self.scope_file,profile=self.profile)
        doc=json.loads(ep.read_text(encoding="utf-8")); results=load_results(self.root); done={r["action"] for r in results if r.get("status")=="completed"}
        for task in doc["tasks"]:
            if task["action"] in done: continue
            if not all(d in done for d in task["depends_on"]): continue
            argv=self._argv(task["action"])
            proc=self.tm.run(task["tool"],argv)
            path=collect(self.root,task,proc.stdout,proc.stderr,proc.returncode,command=argv)
            # Feed only in-scope recon results into later pipeline stages.
            if task["action"] == "external-recon" and proc.returncode == 0:
                scope = load_scope(self.scope_file) if self.scope_file and Path(self.scope_file).exists() else []
                vals=[x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]
                if scope:
                    vals=filter_in_scope(vals, allowed=scope)
                rp=self.root/"recon"/"subdomains.txt"; rp.parent.mkdir(parents=True,exist_ok=True)
                rp.write_text("\n".join(sorted(set(vals)))+(("\n") if vals else ""),encoding="utf-8")
            return task,path
        return None,None

    def run_all(self, max_tasks=20):
        completed=[]
        for _ in range(max_tasks):
            task,path=self.run_next()
            if task is None: break
            completed.append({"task_id":task["task_id"],"action":task["action"],"result":str(path)})
            if task.get("action")=="vulnerability-discovery": break
        return completed
