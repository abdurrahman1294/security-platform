from __future__ import annotations
import json,time,hashlib
from pathlib import Path
from modules.autonomous_offensive_intelligence_v400 import hypotheses,dependency_analysis,next_tests,specialist_priorities,coverage,attack_chain,mission_memory,_inventory
from modules.dependency_resolution_fabric_v410 import resolve
VERSION='4.1.0'
def _safe(v):
    if isinstance(v,Path): return str(v)
    if isinstance(v,dict): return {str(k):_safe(x) for k,x in v.items()}
    if isinstance(v,(list,tuple,set)): return [_safe(x) for x in v]
    return v
def _fp(v): return hashlib.sha256(json.dumps(v,sort_keys=True,default=str).encode()).hexdigest()[:20]
def run(*,engine,objective,story='',max_rounds=4,max_specialists=6,approval_token='',authorized=False):
    if not authorized:return {'status':'blocked','reason':'Authorization confirmation is required'}
    loop=engine.specialist_reasoning_loop_v369(objective=objective,story=story,max_rounds=max_rounds,max_specialists=max_specialists,approval_token=approval_token,authorized=True)
    actions=[a for r in loop.get('rounds',[]) for a in r.get('actions',[]) if isinstance(a,dict)]; evidence=[a for a in actions if a.get('evidence_produced')]
    hs=hypotheses(objective,story,None); deps=dependency_analysis(hs,actions,evidence); resolution=resolve(engine=engine,dependencies=deps,approval_token=approval_token,authorized=True)
    fp=_fp({'client':engine.e.client,'target':engine.e.target,'scope':str(engine.e.scope_file),'objective':objective,'story':story})
    state={'schema_version':VERSION,'status':resolution['status'],'generated_at':time.time(),'mission_fingerprint':fp,'client':engine.e.client,'target':engine.e.target,'scope':str(engine.e.scope_file),'objective':objective,'story':story,'hypotheses':hs,'dependencies':deps,'next_tests':next_tests(hs,deps),'specialist_priorities':specialist_priorities(objective,story,hs),'attack_chain':attack_chain(hs,next_tests(hs,deps)),'coverage':coverage(Path(engine.e.output),hs),'evidence':_inventory(Path(engine.e.output)),'mission_memory':mission_memory(Path(engine.e.output),fp),'dependency_resolution':resolution,'operator_queue':resolution.get('operator_actions',[]),'decision':{'finding_claims':'none without verified evidence','authority_grant':False,'scope_expansion':False,'why_not_converged':'operator action or verified evidence is still required' if resolution['status']!='converged' else 'no unresolved blocking dependency'},'metrics':{'verified_evidence_artifacts':len(evidence),'successful_executions':sum(1 for a in actions if a.get('execution_status') in {'completed','partial'}),'hypotheses':len(hs),'blocked_dependencies':len([d for d in deps if d['state']!='satisfied'])},'governance':{'authorization_required':True,'scope_policy_authoritative':True,'approval_required_for_sensitive_actions':True,'registered_entrypoints_only':True,'no_arbitrary_shell':True,'no_scope_expansion':True,'no_unverified_finding_claims':True}}
    (Path(engine.e.output)/'evidence'/'autonomous-offensive-intelligence-v410.json').write_text(json.dumps(_safe(state),indent=2,sort_keys=True),encoding='utf-8')
    loop['autonomous_offensive_intelligence_v410']=state; loop['dependency_resolution']=resolution; loop['status']=state['status']; return loop
