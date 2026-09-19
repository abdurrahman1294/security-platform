from __future__ import annotations
import json,re
from pathlib import Path

def _read(root, rel):
    p=Path(root)/rel
    return p.read_text(errors='ignore') if p.exists() else ''

def build(root):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    text='\n'.join([_read(root,'ports/naabu.txt'),_read(root,'ports/nmap-detailed.nmap'),_read(root,'ports/nmap-top.nmap'),_read(root,'servers/server-enum.txt'),_read(root,'internal/internal-scan.txt')])
    ports=[]
    for host,port in re.findall(r'([A-Za-z0-9_.:-]+):(\d+)', text):
        ports.append({'host':host,'port':int(port)})
    services=[]
    for line in text.splitlines():
        if '/tcp' in line or '/udp' in line:
            services.append(line.strip())
    data={'schema_version':'1.0','version':'V63','ports':ports[:500],'service_observations':services[:500],
          'trust_candidates':[],'configuration_review_candidates':[],'planning_only':True,'credentials_collected':False}
    for s in services:
        low=s.lower()
        if any(x in low for x in ['ssh','rdp','smb','ldap','winrm','ftp','telnet','snmp']):
            data['trust_candidates'].append({'observation':s,'reason':'service may cross an identity/trust boundary; review manually'})
        if any(x in low for x in ['http','https','ssl','tls']):
            data['configuration_review_candidates'].append({'observation':s,'reason':'review protocol configuration and exposure'})
    (ev/'infrastructure-intelligence-v63.json').write_text(json.dumps(data,indent=2))
    (rp/'infrastructure-intelligence-v63.md').write_text('# Infrastructure Intelligence V63\n\nArtifact-derived infrastructure/service model. No network actions are performed by this module.\n\n- Ports: %d\n- Service observations: %d\n- Trust candidates: %d\n- Configuration candidates: %d\n' % (len(data['ports']),len(data['service_observations']),len(data['trust_candidates']),len(data['configuration_review_candidates'])))
    return ev/'infrastructure-intelligence-v63.json', rp/'infrastructure-intelligence-v63.md'
