from __future__ import annotations
import json,re
from pathlib import Path

def build(root):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    corpus='\n'.join(str(p.read_text(errors='ignore')) for p in (root/'ad').glob('*') if p.is_file()) if (root/'ad').exists() else ''
    data={'schema_version':'1.0','version':'V65','domain_candidates':[], 'identity_boundaries':[], 'privilege_review':[], 'lateral_movement_hypotheses':[], 'planning_only':True,'credential_access':False}
    for m in re.findall(r'(?i)(?:domain|realm)\s*[:=]\s*([A-Za-z0-9._-]+)',corpus):
        if m not in data['domain_candidates']: data['domain_candidates'].append(m)
    if corpus or (root/'ad').exists():
        data['identity_boundaries'].append({'review':'domain users, groups, service accounts and delegated roles'})
        data['privilege_review'].append({'review':'admin-tier separation and excessive privilege'})
        data['lateral_movement_hypotheses'].append({'review':'trust paths and remote-management exposure; validate manually'})
    (ev/'ad-intelligence-v65.json').write_text(json.dumps(data,indent=2))
    (rp/'ad-intelligence-v65.md').write_text('# Active Directory Intelligence V65\n\nSafe artifact-derived AD review model. No credential collection or lateral movement is performed.\n')
    return ev/'ad-intelligence-v65.json',rp/'ad-intelligence-v65.md'
