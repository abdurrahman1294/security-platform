from __future__ import annotations
import json
from pathlib import Path
from .atomic_io import load_json

def _load(root, rel):
    p=Path(root)/rel
    return load_json(p, {})

def build(root):
    root=Path(root); ev=root/'evidence'; rp=root/'reports'; ev.mkdir(exist_ok=True); rp.mkdir(exist_ok=True)
    sources={
      'web':_load(root,'web-surface-v45.json'), 'endpoints':_load(root,'web-endpoints-v46.json'),
      'api':_load(root,'api-surface-intelligence-v58.json'), 'infra':_load(root,'infrastructure-intelligence-v63.json'),
      'cloud':_load(root,'cloud-intelligence-v64.json'), 'ad':_load(root,'ad-intelligence-v65.json'),
      'auth':_load(root,'auth-intelligence-v51.json'), 'session':_load(root,'session-intelligence-v54.json'),
      'workflow':_load(root,'workflow-intelligence-v60.json')}
    counts={k:(len(v) if isinstance(v,list) else sum(len(x) if isinstance(x,list) else 1 for x in v.values())) for k,v in sources.items()}
    data={'schema_version':'1.0','version':'V66','domains':[], 'hosts':[], 'applications':[], 'apis':[], 'infrastructure':[], 'cloud':[], 'identity':[], 'workflows':[], 'source_counts':counts, 'planning_only':True}
    data['domains']=sources['web'].get('domains',[]) if isinstance(sources['web'],dict) else []
    data['hosts']=sources['web'].get('hosts',[]) if isinstance(sources['web'],dict) else []
    data['applications']=sources['web'].get('applications',[]) if isinstance(sources['web'],dict) else []
    data['apis']=sources['api'].get('endpoints',sources['endpoints'].get('endpoints',[])) if isinstance(sources['api'],dict) else []
    data['infrastructure']=sources['infra'].get('ports',[]) if isinstance(sources['infra'],dict) else []
    data['cloud']=sources['cloud'].get('providers',[]) if isinstance(sources['cloud'],dict) else []
    data['identity']=sources['auth'].get('surfaces',[]) if isinstance(sources['auth'],dict) else []
    data['workflows']=sources['workflow'].get('workflows',[]) if isinstance(sources['workflow'],dict) else []
    (ev/'unified-attack-surface-v66.json').write_text(json.dumps(data,indent=2))
    (rp/'unified-attack-surface-v66.md').write_text('# Unified Attack Surface V66\n\nA normalized view across web, API, infrastructure, cloud, identity and workflows.\n\n```text\nDiscover → Normalize → Correlate → Prioritize → Validate → Prove → Report\n```\n')
    return ev/'unified-attack-surface-v66.json',rp/'unified-attack-surface-v66.md'
