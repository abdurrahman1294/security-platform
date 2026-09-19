from pathlib import Path
from security_platform.core.engagement import Engagement

def test_01_engagement_target_host_and_paths(tmp_path):
    e=Engagement('Client','https://example.com/path',tmp_path/'out')
    assert e.target_host == 'example.com'
    assert e.evidence.is_dir()
    assert e.reports.is_dir()
from security_platform.core.policy import ScopePolicy

def test_02_scope_fail_closed_and_ipv6(tmp_path):
    missing=tmp_path/'missing.txt'
    try: ScopePolicy.from_file(missing,'example.com')
    except ValueError: pass
    else: raise AssertionError('missing scope must fail closed')
    scope=tmp_path/'scope.txt'; scope.write_text('example.com\n*.sub.example.com\n10.0.0.0/8\n2001:db8::/32\n')
    p=ScopePolicy.from_file(scope,'example.com')
    assert p.contains('https://foo.sub.example.com/path')
    assert p.contains('10.2.3.4')
    assert p.contains('[2001:db8::1]')
    assert not p.contains('evil-example.com')
from modules.approval_queue import ApprovalQueue

def test_04_approval_survives_restart_without_raw_token(tmp_path):
    q=ApprovalQueue(tmp_path/'evidence'); req=q.submit('controlled_validation','https://a.example','reason')
    token=q.approve(req.request_id); raw=(tmp_path/'evidence/approval-queue.json').read_text()
    assert token and token not in raw
    q2=ApprovalQueue(tmp_path/'evidence')
    assert q2.consume_token(req.request_id, token, 'controlled_validation','https://a.example')
    assert not q2.consume_token(req.request_id, token, 'controlled_validation','https://a.example')
from modules.autonomous_loop import AutonomousLoop
from modules.autonomy_policy import AutonomyPolicy

def test_05_loop_consumes_request_bound_approval(tmp_path):
    v=tmp_path/'vulns'; v.mkdir()
    (v/'findings.json').write_text('[{"info":{"name":"X","severity":"high"},"host":"https://a.example.com"}]')
    loop=AutonomousLoop(tmp_path,'example.com',policy=AutonomyPolicy('assess'),authorized=True,in_scope=True,dry_run=True)
    first=loop.run_once(); req=next(r for r in first['results'] if r['action']=='controlled_validation')['request_id']
    token=loop.queue.approve(req); assert token
    second=loop.run_once(approval_tokens={req:token})
    assert any(r['action']=='controlled_validation' and r['status']=='dry_run' for r in second['results'])
from modules.task_prioritizer import prioritize

def test_06_prioritizer_is_deterministic_and_malformed_safe(tmp_path):
    (tmp_path/'vulns').mkdir(); (tmp_path/'vulns/findings.json').write_text('{bad json')
    a=[x.to_dict() for x in prioritize(tmp_path,'example.com')]
    b=[x.to_dict() for x in prioritize(tmp_path,'example.com')]
    assert a==b
    (tmp_path/'vulns/findings.json').write_text('[null, {"info":{"severity":"high","name":"X"},"host":"https://a.example.com"}]')
    c=prioritize(tmp_path,'example.com')
    assert any(t.action=='controlled_validation' for t in c)
from modules.tool_adapter_hardening_v162 import validate_argv, sanitized_environment

def test_07_tool_boundary_and_aws_runtime_env(monkeypatch):
    assert not validate_argv('nmap',['nmap','--script','evil','example.com'])[0]
    assert not validate_argv('aws',['aws','iam','delete-user','--user-name','x'])[0]
    monkeypatch.setenv('AWS_ACCESS_KEY_ID','x')
    assert sanitized_environment('aws')['AWS_ACCESS_KEY_ID'] == 'x'
    assert 'PENTEST_SECRET' not in sanitized_environment('aws')
from modules.safe_http import request as safe_request

def test_08_safe_http_rejects_mutation_and_unsafe_urls(monkeypatch):
    assert safe_request('https://example.com',method='POST')['error']=='method-not-allowed'
    assert safe_request('https://user:pass@example.com')['error']=='invalid-url'
    assert safe_request('https://example.com/#x')['error']=='invalid-url'
    assert safe_request('file:///etc/passwd')['error']=='invalid-url'
from modules.atomic_io import atomic_write_json, load_json
from modules.findings_io import load_findings_file

def test_09_atomic_io_and_findings_formats(tmp_path):
    p=tmp_path/'state.json'; atomic_write_json(p,{'a':1}); assert load_json(p,{})=={'a':1}
    p.write_text('{broken'); assert load_json(p,{'fallback':1})=={'fallback':1}; assert not p.exists(); assert list(tmp_path.glob('state.json.corrupt-*'))
    f=tmp_path/'findings.json'; f.write_text('{"findings":[{"id":"1"},null]}'); assert load_findings_file(f)==[{'id':'1'}]
    f.write_text('{"id":"1"}\nBAD\n{"id":"2"}\n'); assert len(load_findings_file(f))==2
from security_platform.engines.pentest import PentestEngine
from security_platform.core.engagement import Engagement
from security_platform.core.policy import ScopePolicy

def test_10_pentest_phase_alias_preserves_failure(monkeypatch,tmp_path):
    scope=tmp_path/'scope'; scope.write_text('example.com\n')
    e=Engagement('c','example.com',tmp_path/'out',scope)
    eng=PentestEngine(e,ScopePolicy.from_file(scope,'example.com'))
    monkeypatch.setattr(eng,'finalize',lambda: {'status':'NOT_READY','blockers':['missing-evidence']})
    out=eng.run(('report',),require_authorization=False)
    assert out['status']=='partial' and out['summary']['report']['status']=='NOT_READY'
from security_platform.core.handoff import publish, load

def test_11_handoff_integrity_and_size_limit(tmp_path):
    publish(tmp_path,'osint',{'assets':['api.example.com']})
    assert load(tmp_path,'osint')['payload']['assets']==['api.example.com']
    p=tmp_path/'evidence/handoff-osint.json'; p.write_text(p.read_text().replace('api.example.com','evil.example.com'))
    assert load(tmp_path,'osint')=={}
    try: publish(tmp_path,'osint',{'blob':'x'*(4*1024*1024)})
    except ValueError: pass
    else: raise AssertionError('oversized handoff must be rejected')
import json, subprocess, sys

def test_12_cli_autonomy_surface(tmp_path):
    scope=tmp_path/'scope.txt'; scope.write_text('example.com\n')
    out=tmp_path/'out'
    r=subprocess.run([sys.executable,'securityctl.py','autonomy','-c','C','-t','example.com','-o',str(out),'--scope',str(scope),'--profile','assess','--cycles','1'],capture_output=True,text=True)
    assert r.returncode==0, r.stderr
    data=json.loads(r.stdout); assert data['dry_run'] is True
from modules.html_report import generate_html_report

def test_13_html_report_uses_all_finding_formats_and_redacts(tmp_path):
    f=tmp_path/'findings.json'; f.write_text('{"findings":[{"info":{"name":"X","severity":"high","description":"token=SECRET123"},"host":"https://example.com"}]}')
    out=tmp_path/'report.html'; generate_html_report(str(f),'C','example.com',''+str(out))
    text=out.read_text(); assert 'SECRET123' not in text and '[REDACTED]' in text and 'X' in text
import concurrent.futures

def test_14_approval_queue_thread_safety(tmp_path):
    q=ApprovalQueue(tmp_path/'evidence')
    def submit(i): return q.submit('controlled_validation',f'https://a{i}.example','r').request_id
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex: ids=list(ex.map(submit,range(40)))
    assert len(ids)==40 and len(set(ids))==40
    assert len(q._items)==40
from modules.autonomy_policy import Budget

def test_15_budget_limits_are_validated_and_fail_closed(tmp_path):
    try: Budget(max_tasks=0)
    except ValueError: pass
    else: raise AssertionError('invalid budget must fail')
    p=AutonomyPolicy(); p.budgets.max_tasks=0
    loop=AutonomousLoop(tmp_path,'example.com',policy=p,authorized=True,in_scope=True)
    assert loop.run_once()['status']=='budget_exhausted'
from security_platform.core.platform import SecurityPlatform
from security_platform.core.engagement import Engagement

def test_16_registry_versions_are_consistent(tmp_path):
    specs=SecurityPlatform(Engagement('c','x',tmp_path)).catalog()
    assert specs and all(s['version']=="3.2" for s in specs)
def test_17_tool_executor_normalizes_naabu_before_nmap(tmp_path):
    scope=tmp_path/'scope'; scope.write_text('example.com\n')
    ports=tmp_path/'ports'; ports.mkdir(); (ports/'naabu.txt').write_text('example.com:443\nexample.com:80\n')
    from modules.tool_executor import HardenedToolExecutor
    ex=HardenedToolExecutor(tmp_path,scope)
    calls=[]
    ex._run=lambda tool,argv,timeout=600: calls.append((tool,argv)) or {'status':'completed','returncode':0}
    out=ex.execute('service_enum','example.com',tmp_path)
    assert out['status']=='completed'; assert calls[0][0]=='nmap'; assert any('nmap-targets.txt' in x for x in calls[0][1])
    assert (ports/'nmap-targets.txt').read_text().strip()=='example.com'
def test_18_osint_public_collection_uses_bounded_nonredirect_http(monkeypatch):
    import modules.osint_orchestrator_v233 as o
    monkeypatch.setattr(o,'_public_host',lambda host: True)
    monkeypatch.setattr(o.urllib.parse,'urlparse',o.urllib.parse.urlparse)
    import modules.safe_http as sh
    calls=[]
    monkeypatch.setattr(sh,'request',lambda *a,**k: calls.append((a,k)) or {'ok':True,'status':200,'headers':{},'body':'x','redirects_followed':False})
    result=o._get('https://example.com/robots.txt')
    assert result['redirects_followed'] is False and calls and calls[0][1]['max_body']==65536
def test_20_end_to_end_governance_and_safe_r2(monkeypatch,tmp_path):
    from modules.tool_executor import HardenedToolExecutor
    from modules.roe_policy_v18 import ROEPolicy
    from modules.autonomy_policy import AutonomyPolicy, Decision
    scope=tmp_path/'scope.txt'; scope.write_text('example.com\n')
    ex=HardenedToolExecutor(tmp_path,scope)
    import modules.safe_http as sh
    monkeypatch.setattr(sh,'request',lambda *a,**k:{'ok':True,'status':200,'headers':{'X-Test':'ok'},'body':'safe','redirects_followed':False})
    out=ex.execute('header_verification','example.com',tmp_path)
    assert out['status']=='completed' and Path(out['artifact']).exists()
    roe=ROEPolicy(enabled=True,allowed_actions=frozenset({'controlled_persistence_test'}),operator='op',engagement_reference='ENG-1',target='example.com')
    p=AutonomyPolicy('assisted')
    assert p.decide('controlled_persistence_test',authorized=True,in_scope=True,approval_token='x',roe_permitted=roe.permits('controlled_persistence_test',target='example.com'))==Decision.ALLOW_AUTO
    assert p.decide('exploit_rce',authorized=True,in_scope=True,approval_token='x',roe_permitted=True)==Decision.DENY

def test_19_full_module_audit_and_cli_discovery():
    import subprocess, sys, json
    r=subprocess.run([sys.executable,'tools/audit_engine.py'],capture_output=True,text=True)
    assert r.returncode==0, r.stdout+r.stderr
    data=json.loads(r.stdout); assert data['module_count'] >= 190
    r2=subprocess.run([sys.executable,'-m','compileall','-q','.'],capture_output=True,text=True)
    assert r2.returncode==0
    r3=subprocess.run([sys.executable,'-m','security_platform','engines'],capture_output=True,text=True)
    assert r3.returncode==0 and 'pentest' in r3.stdout and 'osint' in r3.stdout and 'bounty' in r3.stdout
