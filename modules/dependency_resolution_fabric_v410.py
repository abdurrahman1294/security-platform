from __future__ import annotations
import hashlib, json, time, os
from pathlib import Path
from typing import Any
VERSION='4.1.0'
SENSITIVE={'authenticated','ad','cloud'}
PREREQUISITES={'authenticated':('probe','crawl_and_scan'),'web':('probe','crawl_and_scan'),'ad':('ports',),'network':('ports',),'cloud':()}
def _hash(v): return hashlib.sha256(json.dumps(v,sort_keys=True,default=str).encode()).hexdigest()[:20]
def _safe(v):
    if isinstance(v,Path): return str(v)
    if isinstance(v,dict): return {str(k):_safe(x) for k,x in v.items()}
    if isinstance(v,(list,tuple,set)): return [_safe(x) for x in v]
    return v
def _artifact(root,name):
    p=root/name; return p.is_file() and p.stat().st_size>0
def _phase_ready(root,phase):
    return {'probe':_artifact(root,'evidence/pentest-http-probe.json') or _artifact(root,'recon/live-hosts.txt'),'crawl_and_scan':_artifact(root,'web/urls.txt'),'ports':_artifact(root,'ports/naabu.txt') or _artifact(root,'evidence/pentest-portscan.json')}.get(phase,False)
def _auth_available(): return bool(os.environ.get('PENTEST_AUTH_COOKIE') or os.environ.get('PENTEST_AUTH_BEARER') or os.environ.get('PENTEST_AUTH_HEADER'))
def _before(root):
    ev=root/'evidence'; return {str(p.relative_to(ev)) for p in ev.rglob('*') if p.is_file() and p.stat().st_size} if ev.is_dir() else set()
def resolve(*,engine,dependencies,approval_token='',authorized=False):
    if not authorized:
        return {'schema_version':VERSION,'status':'blocked','reason':'authorization-required','operator_actions':[]}
    root=Path(engine.e.output); root.mkdir(parents=True,exist_ok=True)
    actions=[]; operator=[]; remaining=[]
    for dep in sorted(dependencies,key=lambda x:(-float(x.get('priority',0)),x.get('hypothesis_id',''))):
        phase=str(dep.get('dependency','')); hid=str(dep.get('hypothesis_id',''))
        prereqs=PREREQUISITES.get(phase,())
        # Always establish safe, non-sensitive prerequisites before declaring a dependency blocked.
        prereq_failed=False
        for pre in prereqs:
            if _phase_ready(root,pre): continue
            fn=getattr(engine,pre,None)
            if not callable(fn):
                actions.append({'phase':pre,'status':'unavailable','reason':'registered prerequisite entrypoint unavailable'}); prereq_failed=True; continue
            before=_before(root)
            try:
                r=fn(); after=_before(root); delta=sorted(after-before)
                status=str(r.get('status','completed')).lower() if isinstance(r,dict) else 'completed'
                rc=r.get('returncode',r.get('naabu_returncode',r.get('nuclei_returncode'))) if isinstance(r,dict) else None
                if isinstance(rc,int) and rc!=0: status='failed'
                actions.append({'phase':pre,'status':status,'evidence_produced':bool(delta),'evidence_artifacts':delta,'summary':_safe(r)})
                if not _phase_ready(root,pre): prereq_failed=True
            except Exception as exc:
                actions.append({'phase':pre,'status':'error','reason':f'{type(exc).__name__}: {str(exc)[:500]}'}); prereq_failed=True
        if prereq_failed:
            remaining.append({**dep,'state':'prerequisite_failed','reason':'one or more safe prerequisites did not produce required evidence'})
            continue
        if phase in SENSITIVE and not approval_token:
            remaining.append({**dep,'state':'approval_required','reason':'operator approval token is required before sensitive validation'})
            operator.append({'type':'approval','hypothesis_id':hid,'phase':phase,'action':'Provide the required operator approval token, then resume the mission.'})
            continue
        if phase=='authenticated' and not _auth_available():
            remaining.append({**dep,'state':'operator_input_required','reason':'authenticated validation requires an operator-supplied session/header value'})
            operator.append({'type':'input','hypothesis_id':hid,'phase':phase,'action':'Provide an authorized authentication value for the scoped engagement, then resume.'})
            continue
        # A web dependency is considered prepared once its crawl artifact exists;
        # the existing crawl/scan entrypoint is the registered capability used to
        # establish that prerequisite and should not be redundantly invoked here.
        if phase == 'web' and _phase_ready(root, 'crawl_and_scan'):
            remaining.append({**dep,'state':'ready','reason':'web prerequisite evidence established; targeted web validation can resume'})
            continue
        fn=getattr(engine,phase,None)
        if not callable(fn):
            remaining.append({**dep,'state':'unavailable','reason':'registered target entrypoint unavailable'})
            continue
        before=_before(root)
        try:
            r=fn('aws') if phase=='cloud' else fn()
            after=_before(root); delta=sorted(after-before)
            status=str(r.get('status','completed')).lower() if isinstance(r,dict) else 'completed'
            rc=r.get('returncode',r.get('naabu_returncode',r.get('nuclei_returncode'))) if isinstance(r,dict) else None
            if isinstance(rc,int) and rc!=0: status='failed'
            actions.append({'phase':phase,'status':status,'evidence_produced':bool(delta),'evidence_artifacts':delta,'summary':_safe(r)})
            if status in {'completed','partial'} and delta:
                remaining.append({**dep,'state':'satisfied','reason':'governed target validation executed and produced evidence'})
            elif status in {'blocked','unavailable','skipped'}:
                remaining.append({**dep,'state':status,'reason':str(r.get('reason','target capability did not execute')) if isinstance(r,dict) else 'target capability did not execute'})
            else:
                remaining.append({**dep,'state':'validation_no_evidence','reason':'target capability executed but produced no verified evidence'})
        except Exception as exc:
            actions.append({'phase':phase,'status':'error','reason':f'{type(exc).__name__}: {str(exc)[:500]}'}); remaining.append({**dep,'state':'error','reason':'target validation raised an exception'})
    ready=[x for x in remaining if x.get('state') in {'satisfied','ready'}]; pending=[x for x in remaining if x.get('state') not in {'satisfied','ready'}]
    if pending and operator: status='waiting_for_operator'
    elif ready and any(x.get('state')=='ready' for x in ready): status='ready_to_resume'
    elif ready and not pending: status='resolved'
    elif ready: status='partially_resolved'
    else: status='blocked_pending_evidence'
    state={'schema_version':VERSION,'status':status,'generated_at':time.time(),'mission_fingerprint':_hash({'target':str(engine.e.target),'scope':str(engine.e.scope_file),'dependencies':dependencies}),'resolved_dependencies':remaining,'prerequisite_actions':actions,'operator_actions':operator,'ready_dependencies':ready,'blocked_dependencies':pending,'policy':{'registered_entrypoints_only':True,'no_arbitrary_shell':True,'no_scope_expansion':True,'no_credential_generation':True,'no_authority_grant':True}}
    (root/'evidence').mkdir(parents=True,exist_ok=True)
    (root/'evidence'/'dependency-resolution-v410.json').write_text(json.dumps(_safe(state),indent=2,sort_keys=True),encoding='utf-8'); return state
