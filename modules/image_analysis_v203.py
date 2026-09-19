"""V203: local image analysis extensions."""
from pathlib import Path
import hashlib,json
def build(outdir,image_paths=None):
 rows=[]
 for s in image_paths or []:
  p=Path(s)
  if not p.is_file(): continue
  b=p.read_bytes(); rows.append({"path":str(p),"sha256":hashlib.sha256(b).hexdigest(),"size":len(b),"reverse_search":"operator-assisted public service workflow","exif":"inspect locally when supported"})
 data={"version":"V203","images":rows,"policy":"No biometric identification or private-source matching."}; q=Path(outdir)/"evidence/image-analysis-v203.json"; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(json.dumps(data,indent=2)); return data
