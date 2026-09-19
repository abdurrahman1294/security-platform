from __future__ import annotations
import json,re
from pathlib import Path
from urllib.parse import urlparse
from .atomic_io import load_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); endpoints=[]
    for fn in ['web-endpoints-v46.json','api-surface-intelligence-v58.json','api-schema-intelligence-v57.json']:
        p=ev/fn
        if not p.exists(): continue
        o=load_json(p, None, quarantine_on_error=False)
        if o is None: continue
        stack=o if isinstance(o,list) else o.get('endpoints',o.get('records',[]))
        if isinstance(stack,list): endpoints.extend(stack)
    candidates=[]
    for x in endpoints:
        s=json.dumps(x).lower()
        kind='graphql' if 'graphql' in s else 'openapi/swagger' if any(k in s for k in ['openapi','swagger']) else 'rest'
        candidates.append({'surface':kind,'object_reference_candidate':bool(re.search(r'(^|[^a-z])(id|uuid|user_id|account_id|order_id)([^a-z]|$)',s)),'auth_boundary_candidate':any(k in s for k in ['login','auth','token','admin','role'])})
    data={'schema_version':'106.0','protocols':['REST','OpenAPI/Swagger','GraphQL'],'candidates':candidates,'review_actions':['map methods to roles','review object ownership','compare API versions','review undocumented endpoints'],'execution':'analysis-first; operator approval required for active checks'}
    p=ev/'advanced-api-intelligence-v106.json'; p.write_text(json.dumps(data,indent=2)); return p
