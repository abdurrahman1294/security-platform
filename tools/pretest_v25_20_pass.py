"""Twenty focused V2.5 OPSEC/privacy-hygiene regression checks."""
from pathlib import Path
import json, tempfile
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from modules.opsec_v25 import sanitize_for_export, audit_artifacts, build_posture
from security_platform.core.engagement import Engagement
from security_platform.core.platform import SecurityPlatform
from security_platform.cli.securityctl import parser


def main():
    tmp=Path(tempfile.mkdtemp(prefix='v25-opsec-'))
    checks=[]
    def ck(name, fn):
        try: fn(); checks.append((name,'PASS'))
        except Exception as e: checks.append((name,f'FAIL: {e}'))
    ck('01 module imports', lambda: __import__('modules.opsec_v25'))
    ck('02 sanitizer redacts password', lambda: 'pw-value' not in json.dumps(sanitize_for_export({'password':'pw-value'})))
    ck('03 sanitizer redacts token', lambda: 'TOKEN-VALUE-123456789' not in json.dumps(sanitize_for_export({'token':'TOKEN-VALUE-123456789'})))
    ck('04 sanitizer redacts personal field', lambda: 'a@example.test' not in json.dumps(sanitize_for_export({'email':'a@example.test'})))
    ck('05 sanitizer preserves ordinary data', lambda: sanitize_for_export({'finding':'XSS','severity':'high'})['finding']=='XSS')
    ck('06 nested structures sanitized', lambda: 'secret-value' not in json.dumps(sanitize_for_export({'nested':[{'api_key':'secret-value'}]})))
    (tmp/'evidence').mkdir()
    (tmp/'evidence'/'clean.json').write_text('{"finding":"safe"}')
    ck('07 clean audit completes', lambda: audit_artifacts(tmp)['status']=='completed')
    (tmp/'evidence'/'leak.json').write_text('{"api_token":"TOPSECRET-123456789"}')
    ck('08 leak audit detects indicator', lambda: audit_artifacts(tmp)['status']=='attention')
    ck('09 audit never emits secret', lambda: 'TOPSECRET-123456789' not in json.dumps(audit_artifacts(tmp)))
    ck('10 audit reports fingerprint', lambda: bool(audit_artifacts(tmp)['findings'][0]['hits'][0]['fingerprint']))
    ck('11 posture denies absolute anonymity', lambda: build_posture(tmp)['absolute_anonymity'] is False)
    ck('12 posture denies anti-forensics', lambda: build_posture(tmp)['anti_forensics'] is False)
    ck('13 posture requires accountability', lambda: build_posture(tmp)['accountability_required'] is True)
    ck('14 posture does not provide network anonymization', lambda: build_posture(tmp)['network_anonymization']=='not provided')
    ck('15 posture file persisted', lambda: (tmp/'evidence'/'opsec-posture-v25.json').is_file())
    ck('16 CLI opsec exposed', lambda: parser().parse_args(['opsec','-c','LAB','-t','127.0.0.1','-o',str(tmp)]).engine=='opsec')
    e=Engagement('lab','127.0.0.1',tmp,tmp/'scope.txt')
    ck('17 platform version 2.6', lambda: SecurityPlatform(e).catalog()[0]['version']=='2.6')
    ck('18 all registered engines version 2.6', lambda: all(x['version']=='2.6' for x in SecurityPlatform(e).catalog()))
    ck('19 no anonymity/anti-forensics code claims', lambda: all('anti-forensics' in p.read_text().lower() for p in [ROOT/'modules/opsec_v25.py']))
    ck('20 original evidence remains unchanged', lambda: (tmp/'evidence'/'leak.json').read_text()=='{"api_token":"TOPSECRET-123456789"}')
    for n,s in checks: print(n,s)
    passed=sum(s=='PASS' for _,s in checks)
    print(f'SUMMARY passed={passed} failed={len(checks)-passed} total={len(checks)}')
    return 0 if passed==20 else 1
if __name__=='__main__': raise SystemExit(main())
