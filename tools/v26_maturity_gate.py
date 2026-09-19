#!/usr/bin/env python3
"""20-pass operational maturity gate for Security Platform v2.6."""
from pathlib import Path
import json, tempfile, subprocess, sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from modules.operational_maturity_v26 import artifact_inventory, correlate, coverage, health, build_run_state

root = Path(tempfile.mkdtemp(prefix='sp-v26-gate-'))
(root/'evidence').mkdir(); (root/'web').mkdir(); (root/'recon').mkdir()
(root/'web'/'urls.txt').write_text('https://app.example.test/login\n')
(root/'recon'/'subdomains.txt').write_text('app.example.test\n')
(root/'evidence'/'finding.json').write_text(json.dumps({'severity':'high','host':'app.example.test','username':'alice','password':'DO-NOT-LEAK'}))
checks=[]
def ok(name, cond): checks.append((name,bool(cond)))

inv=artifact_inventory(root); ok('01 artifact inventory', bool(inv['files']))
row=next(x for x in inv['files'] if x['path'].endswith('urls.txt')); ok('02 artifact hash', len(row['sha256'])==64)
cov=coverage(root); ok('03 recon evidence counts', cov['domains']['recon'])
ok('04 web evidence counts', cov['domains']['web'])
ok('05 ports remain uncovered without evidence', not cov['domains']['ports'])
cor=correlate(root); ok('06 URL correlation', 'https://app.example.test/login' in cor['urls'])
ok('07 host correlation', 'app.example.test' in cor['hosts'])
ok('08 identity correlation', 'alice' in cor['identity_references'])
raw=json.dumps(cor); ok('09 correlation redacts secret values', 'DO-NOT-LEAK' not in raw)
h=health(root, tool_inventory=[{'name':'nmap','available':True}]); ok('10 degraded health is explicit', h['status']=='degraded')
ok('11 missing tools listed', 'nmap' not in h['missing_tools'])
ok('12 unavailable tool listed', 'nuclei' in h['missing_tools'])
state=build_run_state(root,engine='pentest',phase='credentials',status='completed',details={'token':'SECRET'})
ok('13 run state persists', state['last']['phase']=='credentials')
ok('14 run state redacts secrets', state['last']['details']['token']=='[REDACTED]')
ok('15 run state file exists', (root/'evidence'/'run-state-v26.json').exists())
manifest=(Path(__file__).resolve().parents[1]/'VERSION').read_text().strip(); ok('16 platform version', manifest=='2.6.0')
eng=subprocess.run([sys.executable,'securityctl.py','engines'],capture_output=True,text=True)
items=json.loads(eng.stdout); ok('17 six engines catalogued', len(items)==6)
ok('18 all engines report v2.6', all(x['version']=='2.6' for x in items))
help_out=subprocess.run([sys.executable,'securityctl.py','platform','--help'],capture_output=True,text=True).stdout
ok('19 maturity CLI exposed','--maturity' in help_out)
run=subprocess.run([sys.executable,'securityctl.py','platform','-c','gate','-t','127.0.0.1','-o',str(root/'cli'),'--scope',str(ROOT/'config/scope.example.txt'),'--maturity'],capture_output=True,text=True)
ok('20 maturity CLI runs', run.returncode==0 and 'cross-engine' not in run.stderr)

for n,p in checks: print(f'{n} {"PASS" if p else "FAIL"}')
print(f'SUMMARY passed={sum(p for _,p in checks)} failed={sum(not p for _,p in checks)} total={len(checks)}')
sys.exit(0 if all(p for _,p in checks) else 1)
