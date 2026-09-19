from __future__ import annotations
import json
from pathlib import Path

def build(root):
 root=Path(root); e=root/'evidence'; hy=[]
 for name,kind,nextstep in [('web-endpoints-v46.json','object-boundary','authorization review'),('api-surface-intelligence-v58.json','api-object-access','object-level authorization review'),('workflow-intelligence-v60.json','workflow-state','state transition review')]:
  p=e/name
  if p.exists(): hy.append({'hypothesis_id':'H-'+str(len(hy)+1).zfill(3),'source':name,'kind':kind,'confidence':'candidate','recommended_next':nextstep,'status':'hypothesis'})
 out={'version':'V95','hypotheses':hy,'rule':'hypotheses are not findings and require validation'}
 ep=e/'hypothesis-engine-v95.json'; ep.write_text(json.dumps(out,indent=2)); return ep
