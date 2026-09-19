from __future__ import annotations
from pathlib import Path
import json
from .plugin_sdk_v184 import validate_plugin
from .atomic_io import atomic_write_json

def build(root):
    root=Path(root); ep=root/'evidence'/'plugin-architecture-v98.json'; ep.parent.mkdir(parents=True,exist_ok=True)
    candidates=[]
    for p in sorted((root/'plugins').glob('*.json')) if (root/'plugins').exists() else []:
        try:
            ok,errors=validate_plugin(json.loads(p.read_text(encoding='utf-8'))); candidates.append({'file':p.name,'valid':ok,'errors':errors})
        except (OSError,json.JSONDecodeError) as exc: candidates.append({'file':p.name,'valid':False,'errors':[type(exc).__name__]})
    data={'version':'V98.1','plugin_contract':{'required_fields':['name','version','capabilities','inputs','outputs','risk_level','approval_required'],'execution':'plugins must call registered capabilities; arbitrary shell execution is forbidden'},'installed_plugins':candidates,'valid_plugin_count':sum(x['valid'] for x in candidates)}
    atomic_write_json(ep,data); return ep
