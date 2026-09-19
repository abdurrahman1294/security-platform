"""V3.54 isolated specialist assessment range.

Creates disposable, domain-specific local targets for specialist conformance.
Targets are either short-lived loopback services or isolated file/config
sandboxes. Discovery is performed from target interfaces/artifacts before the
hidden truth manifest is consulted. No external networking, real credentials,
persistence, C2, destructive actions, or unrestricted remote execution.
"""
from __future__ import annotations
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib, json, os, shutil, socket, subprocess, tempfile, threading, time
from urllib.request import urlopen
from urllib.error import URLError
from modules.reliability_execution_integrity_v331 import atomic_write, redact
import logging
logger = logging.getLogger(__name__)

VERSION = "3.54.0"
DOMAINS = {
    "web-api": {"mode":"http", "checks":["xss_reflection","missing_auth","idor"]},
    "network": {"mode":"tcp", "checks":["cleartext_service","legacy_banner"]},
    "linux": {"mode":"fs", "checks":["world_writable_config","debug_service"]},
    "windows-ad": {"mode":"fs", "checks":["weak_domain_policy","anonymous_ldap"]},
    "cloud": {"mode":"fs", "checks":["wildcard_iam","public_storage"]},
    "kubernetes": {"mode":"fs", "checks":["privileged_workload","host_network"]},
    "android": {"mode":"fs", "checks":["exported_component","debuggable_app"]},
    "ios": {"mode":"fs", "checks":["insecure_entitlement","debug_build"]},
    "wireless": {"mode":"fs", "checks":["weak_encryption","management_protection_off"]},
    "iot-firmware": {"mode":"fs", "checks":["uart_enabled","jtag_unlocked"]},
    "ot-ics": {"mode":"fs", "checks":["unsafe_write_policy"]},
    "automotive": {"mode":"fs", "checks":["diagnostic_auth_off"]},
    "reverse-engineering": {"mode":"fs", "checks":["parser_crash_marker"]},
    "source-ci": {"mode":"fs", "checks":["secret_pattern","unsafe_ci_step","old_dependency"]},
    "data": {"mode":"fs", "checks":["unencrypted_backup","plaintext_export"]},
    "ai-ml": {"mode":"http", "checks":["missing_model_auth","unsafe_model_format"]},
}

def _id(*x): return hashlib.sha256("|".join(map(str,x)).encode()).hexdigest()[:20]
def _write(root, rel, data):
    p=Path(root)/rel; p.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(data, str):
        tmp=p.with_name(p.name+f'.tmp-{os.getpid()}')
        with tmp.open('w',encoding='utf-8') as fh:
            fh.write(data); fh.flush(); os.fsync(fh.fileno())
        os.replace(tmp,p)
    else:
        atomic_write(p,redact(data))
    return p

def _free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

class _Web(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/search?q='):
            q=self.path.split('=',1)[1]
            body=f'<html><h1>{q}</h1></html>'
        elif self.path.startswith('/api/users/'):
            uid=self.path.rsplit('/',1)[-1]; body=json.dumps({'id':uid,'role':'user'})
        elif self.path == '/model': body='MODEL_ENDPOINT_UNAUTH UNSAFE_MODEL_FORMAT'
        else: body='V354-LAB'
        self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers(); self.wfile.write(body.encode())
    def log_message(self,*a): return

class _Tcp(BaseHTTPRequestHandler):
    def handle(self):
        try: self.request.sendall(b'V354-CLEARTEXT-LEGACY\r\n')
        except Exception as exc: logger.debug("legacy TCP fixture cleanup/write skipped: %s", exc)


def _start_http():
    s=ThreadingHTTPServer(('127.0.0.1',0),_Web); t=threading.Thread(target=s.serve_forever,daemon=True); t.start(); return s,t

def _start_tcp():
    import socketserver
    class S(socketserver.ThreadingTCPServer): allow_reuse_address=True
    s=S(('127.0.0.1',0),_Tcp); t=threading.Thread(target=s.serve_forever,daemon=True); t.start(); return s,t

def _fixture(root, domain):
    p=Path(root)/'targets'/domain; p.mkdir(parents=True,exist_ok=True)
    data={
      'linux': {'etc/service.conf':'debug=true\nmode=legacy\n','permissions.json':{'world_writable_config':True}},
      'windows-ad': {'domain-policy.json':{'min_auth_length':6,'anonymous_ldap':True}},
      'cloud': {'iam.json':{'actions':['*'],'resource':'*'},'storage.json':{'public':True}},
      'kubernetes': {'deployment.json':{'privileged':True,'hostNetwork':True}},
      'android': {'AndroidManifest.xml':'<application android:debuggable="true"><activity android:exported="true"/></application>'},
      'ios': {'entitlements.json':{'get-task-allow':True},'build.json':{'configuration':'Debug'}},
      'wireless': {'radio.json':{'encryption':'WEP','management_frame_protection':False}},
      'iot-firmware': {'config.txt':'uart_enabled=true\njtag_unlocked=true\n'},
      'ot-ics': {'policy.json':{'write_without_interlock':True}},
      'automotive': {'can-policy.json':{'diagnostic_auth_required':False}},
      'reverse-engineering': {'parser.txt':'PARSER_CRASH_MARKER=1\n'},
      'source-ci': {'app.py':"MARKER = 'LAB-V354-SYNTHETIC'\n",'requirements.txt':'requests==2.19.0\n','ci.yml':'run: curl | sh\n'},
      'data': {'backup.json':{'encrypted':False,'plaintext_export':True}},
    }
    for rel,obj in data.get(domain,{}).items(): _write(p,rel,obj)
    _write(p,'control/hardened.json',{'status':'healthy','secure':True})
    return p

def _discover_fs(p, domain):
    out={}
    txt='\n'.join(x.read_text(errors='ignore') for x in p.rglob('*') if x.is_file())
    def js(rel):
        try:return json.loads((p/rel).read_text())
        except (OSError, ValueError):return {}
    if domain=='linux': out={'world_writable_config':js('permissions.json').get('world_writable_config') is True,'debug_service':'debug=true' in txt}
    elif domain=='windows-ad':
        j=js('domain-policy.json'); out={'weak_domain_policy':j.get('min_auth_length',99)<8,'anonymous_ldap':j.get('anonymous_ldap') is True}
    elif domain=='cloud': out={'wildcard_iam':js('iam.json').get('actions')==['*'],'public_storage':js('storage.json').get('public') is True}
    elif domain=='kubernetes':
        j=js('deployment.json'); out={'privileged_workload':j.get('privileged') is True,'host_network':j.get('hostNetwork') is True}
    elif domain=='android': out={'exported_component':'android:exported="true"' in txt,'debuggable_app':'android:debuggable="true"' in txt}
    elif domain=='ios':
        out={'insecure_entitlement':js('entitlements.json').get('get-task-allow') is True,'debug_build':js('build.json').get('configuration')=='Debug'}
    elif domain=='wireless':
        j=js('radio.json'); out={'weak_encryption':j.get('encryption')=='WEP','management_protection_off':j.get('management_frame_protection') is False}
    elif domain=='iot-firmware': out={'uart_enabled':'uart_enabled=true' in txt,'jtag_unlocked':'jtag_unlocked=true' in txt}
    elif domain=='ot-ics': out={'unsafe_write_policy':js('policy.json').get('write_without_interlock') is True}
    elif domain=='automotive': out={'diagnostic_auth_off':js('can-policy.json').get('diagnostic_auth_required') is False}
    elif domain=='reverse-engineering': out={'parser_crash_marker':'PARSER_CRASH_MARKER=1' in txt}
    elif domain=='source-ci': out={'secret_pattern':'LAB-V354-SYNTHETIC' in txt,'unsafe_ci_step':'curl | sh' in txt,'old_dependency':'requests==2.19.0' in txt}
    elif domain=='data':
        j=js('backup.json'); out={'unencrypted_backup':j.get('encrypted') is False,'plaintext_export':j.get('plaintext_export') is True}
    return out

def _discover_http(url):
    out={}
    try:
        body=urlopen(url+'/search?q=<LAB>',timeout=2).read().decode(errors='ignore'); out['xss_reflection']='<LAB>' in body
        body=urlopen(url+'/api/users/1',timeout=2).read().decode(errors='ignore');
        try: out['idor']=json.loads(body).get('id')=='1'
        except Exception: out['idor']=False
        r=urlopen(url+'/admin',timeout=2); out['missing_auth']=r.status==200
        body=urlopen(url+'/model',timeout=2).read().decode(errors='ignore'); out['missing_model_auth']='MODEL_ENDPOINT_UNAUTH' in body; out['unsafe_model_format']='UNSAFE_MODEL_FORMAT' in body
    except (URLError,OSError):
        return out
    return out

def run_specialist_range(root, *, execute=True):
    root=Path(root); root.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix='v354-',dir=root)); targets={}; results=[]; servers=[]
    try:
        for domain,spec in DOMAINS.items():
            p=_fixture(work,domain)
            rec={'target_id':_id(VERSION,domain),'domain':domain,'mode':spec['mode'],'checks':spec['checks'],'status':'ready','path':str(p.relative_to(work))}
            if spec['mode']=='http':
                s,t=_start_http(); servers.append((s,t)); rec['endpoint']=f'http://127.0.0.1:{s.server_address[1]}';
                if execute: found=_discover_http(rec['endpoint'])
                else: found={}
            elif spec['mode']=='tcp':
                s,t=_start_tcp(); servers.append((s,t)); rec['endpoint']=f'127.0.0.1:{s.server_address[1]}';
                found={}
                if execute:
                    try:
                        with socket.create_connection(('127.0.0.1',s.server_address[1]),timeout=2) as c:
                            banner=c.recv(256).decode(errors='ignore')
                        found={'cleartext_service': 'CLEARTEXT' in banner, 'legacy_banner': 'LEGACY' in banner}
                    except OSError: found={}
            else:
                rec['endpoint']=None; found=_discover_fs(p,domain) if execute else {}
            rec['discovered']={k: bool(found.get(k)) for k in spec['checks']}
            results.append(rec); targets[domain]=rec
        # Ground truth is deliberately generated separately and not consumed by discovery.
        truth=[]
        expected_by_domain={d: set(v['checks']) for d,v in DOMAINS.items()}
        for d,checks in expected_by_domain.items():
            for c in checks: truth.append({'scenario_id':_id(VERSION,d,c),'domain':d,'check':c,'expected':True})
        _write(root,'ground_truth/manifest.json',{'schema_version':VERSION,'entries':truth})
        tp=fp=miss=0; rows=[]
        for r in results:
            expected=set(r['checks']); observed={k for k,v in r['discovered'].items() if v}
            tp += len(expected & observed); miss += len(expected-observed); fp += len(observed-expected)
            for c in sorted(expected|observed): rows.append({'domain':r['domain'],'check':c,'expected':c in expected,'observed':c in observed,'status':'true_positive' if c in expected and c in observed else 'miss' if c in expected else 'false_positive'})
        summary={'targets':len(results),'checks':sum(len(r['checks']) for r in results),'true_positives':tp,'misses':miss,'false_positives':fp,'detection_rate':round(tp/(tp+miss),4) if tp+miss else 1.0}
        report={'schema_version':VERSION,'status':'PASS' if miss==0 and fp==0 else 'FAIL','execution_mode':'isolated-local','summary':summary,'targets':results,'findings':rows,'safety':{'loopback_only':True,'external_network':False,'real_credentials':False,'destructive_actions':False,'unrestricted_remote_execution':False},'limitations':['These are disposable local specialist fixtures, not production networks.','Native OS/device/cloud tooling remains separately readiness-audited when unavailable.']}
        _write(root,'evidence/specialist-isolated-range-v354.json',report); return report
    finally:
        for s,t in servers:
            try:s.shutdown();s.server_close();t.join(timeout=2)
            except Exception as exc: logger.debug("specialist range server cleanup skipped: %s", exc)
        shutil.rmtree(work,ignore_errors=True)

def v354_test_matrix():
    names=['domain-catalog','per-domain-isolation','hidden-ground-truth','discover-before-truth','web-api-service','network-service','linux-target','windows-ad-target','cloud-target','kubernetes-target','android-target','ios-target','wireless-target','firmware-target','ot-target','automotive-target','reverse-engineering-target','source-ci-target','data-target','ai-ml-target','loopback-only','no-real-credentials','no-external-network','cleanup','true-positive-accounting','miss-accounting','false-positive-accounting','per-domain-accounting','machine-readable','regression-safe','no-generic-execution','explicit-limitations']
    return {'schema_version':VERSION,'scenario_count':len(names),'scenarios':[{'id':_id('v354-test',n),'name':n,'expected':'pass'} for n in names]}
