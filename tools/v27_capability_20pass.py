from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.expert_capability_audit_v27 import build
from modules.network_surface_v27 import dns_observe, tls_observe
import security_platform.engines
from security_platform.core.platform import SecurityPlatform
from security_platform.core.engagement import Engagement

checks=[]
def ok(name, cond):
    checks.append((name, bool(cond)))

with tempfile.TemporaryDirectory() as td:
    root=Path(td); (root/'evidence').mkdir(); (root/'recon').mkdir()
    (root/'recon'/'subdomains.txt').write_text('127.0.0.1\n')
    data=build(root, tool_inventory=[{'name':'subfinder','status':'ready'},{'name':'assetfinder','status':'ready'},{'name':'nmap','status':'ready'}])
    ok('01 schema 2.7', data['schema_version']=='2.7')
    ok('02 catalog >= 60', data['catalog_size']>=60)
    ok('03 priority gaps visible', len(data['priority_gaps'])>=1)
    ok('04 gap status visible', any(x['status']=='gap' for x in data['capabilities']))
    ok('05 human boundary visible', any(x['status']=='human-required' for x in data['capabilities']))
    ok('06 lab boundary visible', any(x['status']=='lab-only' for x in data['capabilities']))
    ok('07 missing tool state visible', any(x['status']=='implemented-but-tool-missing' for x in data['capabilities']))
    ok('08 evidence-backed state visible', any(x['status']=='executed-evidence-backed' for x in data['capabilities']))
    dns=dns_observe(root,'127.0.0.1')
    ok('09 DNS observation', dns['status']=='completed')
    ok('10 DNS evidence', (root/'evidence'/'dns-observation-v27.json').exists())
    tls=tls_observe(root,'127.0.0.1',port=1,timeout=0.2)
    ok('11 TLS bounded failure recorded', tls['status'] in {'failed','certificate-verification-failed'})
    ok('12 TLS evidence', (root/'evidence'/'tls-observation-v27.json').exists())
    audit=(root/'evidence'/'expert-capability-audit-v27.json').read_text()
    ok('13 audit persisted', 'expert pentest' in audit)
    ok('14 score is bounded', 0 <= data['maturity_score'] <= 100)
    ok('15 red-team boundary present', len(data['red_team_boundary']) >= 5)
    p=SecurityPlatform(Engagement('c','127.0.0.1',root,Path('config/scope.example.txt')))
    cat=p.catalog()
    ok('16 six engines', len(cat)==6)
    ok('17 all engines 2.7', all(x['version']=='2.7' for x in cat))
    p.write_manifest(); ok('18 platform manifest 2.7', 'platform-2.7' in (root/'evidence'/'platform-manifest.json').read_text())
    ok('19 CLI audit module imports', __import__('modules.expert_capability_audit_v27'))
    ok('20 CLI/default depth includes DNS/TLS', 'dns' in open('security_platform/engines/pentest.py').read() and 'tls' in open('security_platform/engines/pentest.py').read())

failed=[n for n,p in checks if not p]
print('\n'.join(f'{n} {"PASS" if p else "FAIL"}' for n,p in checks))
print(f'SUMMARY passed={len(checks)-len(failed)} failed={len(failed)} total={len(checks)}')
raise SystemExit(1 if failed else 0)
