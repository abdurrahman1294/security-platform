from __future__ import annotations
import hashlib,json
from pathlib import Path
def inspect_image(path,root):
 p=Path(path); valid=p.exists() and p.is_file(); data={'schema_version':'176.0','file':p.name,'exists':valid,'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if valid else None,'analysis':['file-type','dimensions-if-supported','EXIF-if-present','GPS-if-present','perceptual-hash-ready'],'reverse_search':'operator-assisted public search only'}
 ev=Path(root)/'evidence'; ev.mkdir(parents=True,exist_ok=True); (ev/'image-osint-v176.json').write_text(json.dumps(data,indent=2)); return data
def build(root): return inspect_image('',root)
