"""V205: independent-source corroboration."""
from pathlib import Path
import json
def build(outdir,claims=None):
 out=[]
 for c in claims or []:
  src={str(x.get('source')) for x in c.get('evidence',[]) if x.get('source')}; out.append({"claim":c.get('claim'),"sources":sorted(src),"independent_source_count":len(src),"confidence":"high" if len(src)>=2 else "low"})
 data={"version":"V205","claims":out}; p=Path(outdir)/"evidence/osint-corroboration-v205.json"; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(data,indent=2)); return data
