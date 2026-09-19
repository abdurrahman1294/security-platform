from __future__ import annotations
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from .security import redact_mapping

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); vault=[]
    for p in sorted(ev.rglob('*')):
        if not p.is_file() or p.name=='evidence-vault-v109.json': continue
        raw=p.read_bytes(); vault.append({'evidence_id':'E-'+hashlib.sha256(str(p.relative_to(root)).encode()).hexdigest()[:12],'path':str(p.relative_to(root)),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'collected_at':datetime.fromtimestamp(p.stat().st_mtime,tz=timezone.utc).isoformat(),'type':p.suffix.lstrip('.') or 'file','provenance':'local-artifact','redaction_policy':'sensitive fields redacted in structured records'})
    data=redact_mapping({'schema_version':'109.0','count':len(vault),'records':vault})
    out=ev/'evidence-vault-v109.json'; out.write_text(json.dumps(data,indent=2)); return out
