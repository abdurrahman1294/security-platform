from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

REQUIRED={'name':str,'version':str,'capabilities':list,'inputs':list,'outputs':list,'risk_level':str,'approval_required':bool}
def validate_plugin(manifest):
    if not isinstance(manifest,dict): return False,['manifest-not-object']
    errors=[]
    for key,typ in REQUIRED.items():
        if key not in manifest: errors.append(f'missing:{key}')
        elif not isinstance(manifest[key],typ): errors.append(f'type:{key}')
    if isinstance(manifest.get('capabilities'),list) and any(not isinstance(x,str) or not x.strip() for x in manifest['capabilities']): errors.append('invalid-capability')
    return not errors,errors

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    candidates=[]
    for p in sorted((root/'plugins').glob('*.json')) if (root/'plugins').exists() else []:
        try:
            import json; candidates.append({'file':p.name,'valid':validate_plugin(json.loads(p.read_text(encoding='utf-8')))[0]})
        except (OSError,ValueError): candidates.append({'file':p.name,'valid':False})
    data={'schema_version':'184.1','contract':list(REQUIRED),'plugin_count':len(candidates),'plugins':candidates,'execution':'registered capabilities only; no arbitrary shell'}
    atomic_write_json(ev/'plugin-sdk-v184.json',data); return data
