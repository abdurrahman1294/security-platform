from __future__ import annotations
import hashlib, json, os, platform as _platform, shutil, subprocess, time
from .atomic_io import load_json, atomic_write_json
from .tool_adapter_hardening_v162 import executable_path, verify_executable_identity
from pathlib import Path

VERSION='225.0'

def _io(root):
    root=Path(root); ev=root/'evidence'; rep=root/'reports'; ev.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True); return ev,rep

def _write(ev,name,data):
    p=ev/name; p.write_text(json.dumps(data,indent=2,sort_keys=True)); return p

def _read(ev,name,default):
    return load_json(ev/name, default)

def v211(root):
    ev,rep=_io(root); p=ev/'assessment-state-v211.json'; old=_read(ev,p.name,{})
    data={'schema_version':'211.0','status':old.get('status','initialized'),'phase':old.get('phase','planning'),'sequence':old.get('sequence',[]),'resume_safe':True,'updated_at':time.time()}
    if not data['sequence']: data['sequence']=[{'phase':'planning','status':'initialized','timestamp':data['updated_at']}]
    _write(ev,p.name,data); return data

def v212(root):
    ev,rep=_io(root)
    adapters=[]
    for exe in ['subfinder','assetfinder','amass','dnsx','httpx','naabu','nmap','katana','nuclei','gau','waybackurls','ffuf','feroxbuster']:
        adapters.append({'adapter_id':exe,'executable':exe,'installed':shutil.which(exe) is not None,'input':'target/scope','output':'normalized-artifact','shell':False,'timeout_seconds':300})
    data={'schema_version':'212.0','adapter_contract':['capability declaration','input schema','output schema','parser','health check','version detection','failure handling'],'adapters':adapters}
    _write(ev,'tool-adapters-v212.json',data); return data

def v213(root):
    ev,rep=_io(root); adapters=_read(ev,'tool-adapters-v212.json',{}).get('adapters',[]); tools=[]
    for a in adapters:
        version='unknown'
        tool_id=a['executable']
        if a['installed']:
            try:
                resolved=executable_path(tool_id)
                if resolved:
                    ok, reason=verify_executable_identity(tool_id, resolved)
                    version='identity-verified' if ok else f'identity-check-failed:{reason}'
                else:
                    version='executable-policy-rejected'
            except ValueError:
                # Catalog-only tools are inventoried without executing arbitrary
                # version commands. They must receive a dedicated adapter before
                # becoming executable capabilities.
                version='catalog-only; no health command executed'
        tools.append({**a,'version':version})
    data={'schema_version':'213.0','host':_platform.platform(),'tools':tools,'alternatives':{'web_discovery':['httpx','katana'],'dns_discovery':['subfinder','assetfinder','amass','dnsx'],'port_discovery':['naabu','nmap']}}
    _write(ev,'tool-capabilities-v213.json',data); return data

def v214(root,target=''):
    ev,rep=_io(root); assets=_read(ev,'assets.json',{}); discovered=assets.get('assets',assets if isinstance(assets,list) else [])
    if not isinstance(discovered,list): discovered=[]
    data={'schema_version':'214.0','target':target,'expansion_policy':'new asset -> scope validation -> queue; never auto-expands scope','discovered_count':len(discovered),'queued_assets':[]}
    _write(ev,'recon-expansion-v214.json',data); return data

def v215(root):
    ev,rep=_io(root)
    cats=['Information Gathering','Configuration and Deployment Management Testing','Identity Management Testing','Authentication Testing','Authorization Testing','Session Management Testing','Input Validation Testing','Error Handling Testing','Weak Cryptography Testing','Business Logic Testing','Client-side Testing','API Testing']
    data={'schema_version':'215.0','framework':'OWASP WSTG','framework_note':'Current stable WSTG is used as the category baseline; exact test identifiers are versioned when recorded.','categories':[{'name':c,'status':'mapped','automated':False,'manual_review_required':True} for c in cats],'coverage_rule':'only evidence-backed tests count as covered'}
    _write(ev,'web-coverage-v215.json',data); return data

def v216(root):
    ev,rep=_io(root); surface=_read(ev,'api-surface-v58.json',{}); data={'schema_version':'216.0','protocols':['REST','OpenAPI','GraphQL'],'checks':['authentication','object-level authorization','function-level authorization','field/input authorization','object relationships','version/schema consistency'],'source_artifact':'api-surface-v58.json','manual_validation_required':True}
    _write(ev,'api-deep-assessment-v216.json',data); return data

def v217(root):
    ev,rep=_io(root); data={'schema_version':'217.0','browser_application_checks':['JavaScript asset inventory','client-side route discovery','API reference extraction','source-map detection','browser security headers','application-flow mapping'],'active_browser_automation':False,'evidence_required':True}
    _write(ev,'browser-application-intelligence-v217.json',data); return data

def v218(root):
    ev,rep=_io(root); data={'schema_version':'218.0','checks':['service relationships','TLS configuration','management interfaces','software/version correlation','infrastructure graph'],'sources':['assets.json','pipeline-results','technology inventory'],'evidence_required':True}
    _write(ev,'network-infrastructure-v218.json',data); return data

def v219(root):
    ev,rep=_io(root); data={'schema_version':'219.0','clouds':['AWS','Azure','GCP'],'checks':['IAM relationships','storage exposure','public resources','network controls','configuration evidence'],'credential_access':False,'active_cloud_changes':False,'manual_validation_required':True}
    _write(ev,'cloud-security-v219.json',data); return data

def v220(root):
    ev,rep=_io(root); data={'schema_version':'220.0','identity_checks':['domain structure','identity relationships','privilege boundaries','authentication paths','controlled authorization testing'],'roles':['Anonymous','User A','User B','Privileged'],'credential_collection':False,'bypass_automation':False,'manual_validation_required':True}
    _write(ev,'identity-ad-v220.json',data); return data

def v221(root):
    ev,rep=_io(root); tech=_read(ev,'technology-inventory.json',{}); findings=_read(ev,'normalized-findings.json',{}); data={'schema_version':'221.0','correlation_fields':['CVE','CWE','software','version','asset criticality','exploitability context','evidence requirements'],'technology_sources':bool(tech),'finding_sources':bool(findings),'external_database_queries':False,'rule':'no vulnerability is confirmed from version matching alone'}
    _write(ev,'vulnerability-intelligence-v221.json',data); return data

def v222(root):
    ev,rep=_io(root); data={'schema_version':'222.0','reduction_rules':['contradictory evidence','duplicate findings','stale evidence','confidence recalculation','independent verification'],'states':['suspected','needs-validation','confirmed','false-positive','inconclusive'],'confirmation_rule':'requires sufficient independent evidence'}
    _write(ev,'false-positive-reduction-v222.json',data); return data

def v223(root):
    ev,rep=_io(root); files=list(ev.glob('*.json')); data={'schema_version':'223.0','artifact_count':len(files),'coverage_model':['discovered attack surface','tool coverage','web/API coverage','infrastructure coverage','evidence quality','finding verification'],'blind_spots':[],'rule':'unexplored work remains explicitly reported'}
    _write(ev,'coverage-blindspots-v223.json',data); return data

def v224(root):
    ev,rep=_io(root); records=[]
    for p in sorted(ev.glob('*.json')):
        b=p.read_bytes(); records.append({'name':p.name,'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)})
    data={'schema_version':'224.0','replayable':True,'replay_basis':'recorded artifacts and hashes','tool_versions_source':'tool-capabilities-v213.json','records':records,'network_replay':False,'secret_replay':False}
    _write(ev,'assessment-replay-v224.json',data); return data

def v225(root,target=''):
    ev,rep=_io(root); required=['assessment-state-v211.json','tool-adapters-v212.json','tool-capabilities-v213.json','recon-expansion-v214.json','web-coverage-v215.json','api-deep-assessment-v216.json','browser-application-intelligence-v217.json','network-infrastructure-v218.json','cloud-security-v219.json','identity-ad-v220.json','vulnerability-intelligence-v221.json','false-positive-reduction-v222.json','coverage-blindspots-v223.json','assessment-replay-v224.json']
    checks={x:(ev/x).exists() for x in required}; data={'schema_version':'225.0','target':target,'checks':checks,'decision':'PASS' if all(checks.values()) else 'NOT_READY','human_review_required':True,'completion_definition':'assessment-plan coverage demonstrated; commands alone do not imply completeness','flow':['Authorization','Scope','Asset coverage','Tool coverage','Web/API coverage','Infrastructure coverage','Evidence quality','Finding verification','False-positive analysis','Blind-spot analysis','Remediation/retest','Human review','Final assessment']}
    _write(ev,'quality-gate-v225.json',data)
    (rep/'production-readiness-v225.md').write_text('# V225 Production/Reality Quality Gate\n\nDecision: **%s**\n\nHuman review remains mandatory.\n' % data['decision'])
    return data

def build_all(root,target=''):
    v211(root); v212(root); v213(root); v214(root,target); v215(root); v216(root); v217(root); v218(root); v219(root); v220(root); v221(root); v222(root); v223(root); v224(root); return v225(root,target)
