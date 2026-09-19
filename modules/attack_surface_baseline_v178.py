from __future__ import annotations
import json,hashlib
from pathlib import Path
def build(root):
 root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
 files=[]
 for f in sorted(ev.rglob('*')):
  if f.is_file() and f.name not in {'attack-surface-baseline-v178.json'}:
   files.append({'path':str(f.relative_to(root)),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
 data={'schema_version':'178.0','artifact_baseline':files}
 (ev/'attack-surface-baseline-v178.json').write_text(json.dumps(data,indent=2)); return data
