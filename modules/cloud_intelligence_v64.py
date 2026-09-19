from __future__ import annotations
import json,re
from pathlib import Path

def build(root):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    corpus='\n'.join(str(p.read_text(errors='ignore')) for p in list(root.rglob('*')) if p.is_file() and p.suffix.lower() in {'.txt','.md','.json','.yaml','.yml','.xml'} and 'reports' not in p.parts)
    providers=[]
    for name, pats in {'AWS':[r'\baws\b',r'\.amazonaws\.com\b',r'iam'], 'Azure':[r'azure',r'\.windows\.net\b'], 'GCP':[r'google cloud',r'\.googleapis\.com\b']}.items():
        if any(re.search(p,corpus,re.I) for p in pats): providers.append(name)
    data={'schema_version':'1.0','version':'V64','providers':providers,'identity_candidates':[], 'storage_candidates':[], 'network_candidates':[], 'planning_only':True,'cloud_credentials_collected':False}
    for p in providers:
        data['identity_candidates'].append({'provider':p,'review':'review IAM/role/service-account boundaries'})
        data['storage_candidates'].append({'provider':p,'review':'review exposed storage and public-access configuration'})
        data['network_candidates'].append({'provider':p,'review':'review network segmentation and security-group/firewall posture'})
    (ev/'cloud-intelligence-v64.json').write_text(json.dumps(data,indent=2))
    (rp/'cloud-intelligence-v64.md').write_text('# Cloud Intelligence V64\n\nArtifact-derived cloud provider intelligence. No cloud APIs or credentials are used.\n\nDetected providers: %s\n' % (', '.join(providers) if providers else 'none'))
    return ev/'cloud-intelligence-v64.json',rp/'cloud-intelligence-v64.md'
