"""V3.43 Complete Testing Lab.

Builds one deterministic, isolated validation campaign covering the engine's
capability taxonomy. The lab uses synthetic fixtures and governed contract
execution; dangerous behaviors are represented by lab simulations only.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, json, time, traceback
from modules.reliability_execution_integrity_v331 import atomic_write, redact
from modules.capability_closure_fabric_v342 import CAPABILITY_FAMILIES, capability_contract, DANGEROUS, simulate_dangerous_capability

VERSION='3.43.0'
LAB_SCHEMA='complete-lab-v1'

def _id(*p): return hashlib.sha256('|'.join(map(str,p)).encode()).hexdigest()[:20]

def _write(root,name,obj):
    path=Path(root)/name
    path.parent.mkdir(parents=True,exist_ok=True)
    atomic_write(path,redact(obj)); return str(path)

def build_lab_catalog() -> list[dict[str,Any]]:
    rows=[]
    for family,caps in CAPABILITY_FAMILIES.items():
        for cap in caps:
            c=capability_contract(family,cap)
            rows.append({
                'scenario_id':_id('v343',family,cap), 'family':family, 'capability':cap,
                'risk':c['risk'], 'mode':c['execution_mode'],
                'fixture':f'{family}/{cap}',
                'expected': 'lab-simulation' if cap in DANGEROUS else 'contract-validation',
                'checks':['preflight','scope','authorization','lifecycle','evidence','validation','reportability'],
            })
    return rows

def _fixture_for(row):
    # Synthetic, non-operational vulnerability fixture. It contains no secrets,
    # real credentials, exploit payloads, or destructive instructions.
    return {
      'fixture_id':row['scenario_id'], 'family':row['family'], 'capability':row['capability'],
      'synthetic':True, 'finding_class':row['capability'],
      'evidence':{'marker':_id('fixture-evidence',row['scenario_id']), 'source':'complete-testing-lab', 'confidence':'synthetic'},
      'effect':'simulated-observation-only'
    }

def _run_one(root,row,target,authorized=True):
    started=time.time(); checks={}; status='passed'; error=None
    try:
        fixture=_fixture_for(row)
        c=capability_contract(row['family'],row['capability'])
        checks['preflight']=bool(target)
        checks['scope']=target != ''
        checks['authorization']=authorized
        checks['lifecycle']=tuple(c['lifecycle']) == ('preflight','approval','execution','evidence','finding','validation','remediation','retest')
        if row['capability'] in DANGEROUS:
            sim=simulate_dangerous_capability(root,capability=row['capability'],target=target,approved=authorized,lab_id='v343-complete-lab')
            checks['execution']=sim.get('status') == 'simulated'
            fixture['simulation_status']=sim.get('status')
        else:
            checks['execution']=c['status']=='implemented-contract'
        checks['evidence']=bool(fixture['evidence'])
        checks['validation']=bool(c['validation_required'])
        checks['reportability']=bool(c['evidence_required'])
        if not all(checks.values()): status='failed'
        return {'scenario_id':row['scenario_id'],'family':row['family'],'capability':row['capability'],'status':status,'checks':checks,'fixture':fixture,'duration_ms':round((time.time()-started)*1000,2),'error':error}
    except Exception as exc:
        return {'scenario_id':row['scenario_id'],'family':row['family'],'capability':row['capability'],'status':'error','checks':checks,'fixture':{},'duration_ms':round((time.time()-started)*1000,2),'error':f'{type(exc).__name__}: {exc}','traceback':traceback.format_exc(limit=2)}

def build_complete_lab(root: str|Path, *, target='127.0.0.1', authorized=True, objective='complete-engine-validation') -> dict[str,Any]:
    root=Path(root); root.mkdir(parents=True,exist_ok=True); (root/'fixtures').mkdir(exist_ok=True); (root/'evidence').mkdir(exist_ok=True)
    catalog=build_lab_catalog()
    for row in catalog: _write(root/'fixtures',row['scenario_id']+'.json',_fixture_for(row))
    results=[_run_one(root,row,target,authorized) for row in catalog]
    families={}
    for r in results:
        f=families.setdefault(r['family'],{'total':0,'passed':0,'failed':0,'errors':0})
        f['total']+=1; f[r['status'] if r['status'] in ('passed','failed','errors') else ('errors' if r['status']=='error' else 'failed')]+=1
    summary={'total':len(results),'passed':sum(r['status']=='passed' for r in results),'failed':sum(r['status']=='failed' for r in results),'errors':sum(r['status']=='error' for r in results)}
    gaps=[]
    for r in results:
        if r['status']!='passed': gaps.append({'scenario_id':r['scenario_id'],'family':r['family'],'capability':r['capability'],'reason':r.get('error') or [k for k,v in r['checks'].items() if not v]})
    report={'schema_version':VERSION,'lab_schema':LAB_SCHEMA,'target':target,'authorized':authorized,'objective':objective,'started_at':time.time(),'catalog_count':len(catalog),'summary':summary,'families':families,'results':results,'gaps':gaps,'coverage':{'taxonomy_entries':len(catalog),'tested_entries':len(results),'tested_ratio':round(len(results)/len(catalog),4) if catalog else None},'limitations':['This lab is deterministic and local.','Synthetic fixtures do not prove real-world exploitability.','Dangerous capabilities use lab simulation envelopes only.','Specialist tool effectiveness requires separate isolated integration tests.']}
    _write(root,'evidence/complete-lab-report-v343.json',report)
    _write(root,'evidence/complete-lab-gap-register-v343.json',{'schema_version':VERSION,'gaps':gaps,'summary':summary})
    return report

def v343_test_matrix():
    names=['catalog-complete','fixture-generation','all-capabilities-covered','scope-check','authorization-check','canonical-lifecycle','evidence-production','validation-contract','reportability','dangerous-lab-envelope','no-real-secrets','no-real-impact','gap-register','family-accounting','deterministic-scenario-id','atomic-artifacts','resume-readable','machine-readable','single-command-compatible','synthetic-fixture-marker','specialist-boundary-visible','coverage-accounting','error-accounting','failure-visible','limitations-visible','target-lock','authorization-lock','redaction','report-generated','gap-report-generated']
    return {'schema_version':VERSION,'scenario_count':len(names),'scenarios':[{'id':_id('v343-test',n),'name':n,'expected':'pass'} for n in names]}
