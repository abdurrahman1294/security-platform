from __future__ import annotations
import json, shutil
from pathlib import Path
from .tool_manager_v40 import ToolManager, TOOLS
from .result_collector_v43 import collect
from .scope import load_scope, filter_in_scope

class IntegratedToolchain:
 def __init__(self, root, target, scope_file):
  self.root=Path(root); self.target=target; self.scope_file=scope_file; self.tm=ToolManager(self.root); self.scope=load_scope(scope_file) if scope_file and Path(scope_file).exists() else []
 def _run(self, task_id, action, tool, argv):
  if shutil.which(TOOLS[tool].executable) is None:
   task={'task_id':task_id,'action':action,'tool':tool}; return {'action':action,'status':'skipped','reason':'tool-not-installed','result':str(collect(self.root,task,'',f'{tool} not installed',127,command=argv))}
  task={'task_id':task_id,'action':action,'tool':tool}; proc=self.tm.run(tool,argv); path=collect(self.root,task,proc.stdout,proc.stderr,proc.returncode,command=argv); return {'action':action,'status':'completed' if proc.returncode==0 else 'failed','result':str(path),'stdout':proc.stdout}
 def run(self):
  (self.root/'recon').mkdir(exist_ok=True); (self.root/'web').mkdir(exist_ok=True); (self.root/'vulns').mkdir(exist_ok=True); (self.root/'ports').mkdir(exist_ok=True); (self.root/'evidence').mkdir(exist_ok=True)
  results=[]
  results.append(self._run('V100-001','subdomain-discovery','subfinder',['subfinder','-d',self.target,'-silent']))
  subs=[]
  if results[-1].get('stdout'):
   subs=[x.strip() for x in results[-1]['stdout'].splitlines() if x.strip()]
  subs=filter_in_scope(sorted(set(subs)),allowed=self.scope) if self.scope else []
  if not subs and self.target and self.scope and filter_in_scope([self.target], allowed=self.scope): subs=[self.target]
  sp=self.root/'recon'/'subdomains.txt'; sp.write_text('\n'.join(subs)+'\n')
  results.append(self._run('V100-002','http-probing','httpx',['httpx','-l',str(sp),'-json','-silent']))
  live=[]
  if results[-1].get('stdout'):
   live=[x for x in results[-1]['stdout'].splitlines() if x.strip()]
  (self.root/'recon'/'live-hosts.jsonl').write_text('\n'.join(live)+'\n')
  urls=[]
  for line in live:
   try: urls.append(json.loads(line).get('url',''))
   except json.JSONDecodeError: pass
  urls=[u for u in urls if u]
  up=self.root/'web'/'urls.txt'; up.write_text('\n'.join(sorted(set(urls)))+'\n')
  results.append(self._run('V100-003','port-discovery','naabu',['naabu','-list',str(sp),'-silent','-top-ports','100']))
  results.append(self._run('V100-004','service-enumeration','nmap',['nmap','-sV','--top-ports','100','-oN',str(self.root/'ports'/'v100-nmap.txt'),self.target]))
  if urls: results.append(self._run('V100-005','web-crawling','katana',['katana','-list',str(up),'-silent','-jc']))
  if urls: results.append(self._run('V100-006','vulnerability-discovery','nuclei',['nuclei','-l',str(up),'-silent','-jsonl']))
  out={'version':'V100','target':self.target,'scope_enforced':bool(self.scope),'results':[{k:v for k,v in r.items() if k!='stdout'} for r in results]}
  ep=self.root/'evidence'/'integrated-toolchain-v100.json'; ep.write_text(json.dumps(out,indent=2)); return ep,out
