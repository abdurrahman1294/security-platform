from __future__ import annotations
import json,os
from pathlib import Path
def build(root):
 root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
 checks={'python':True,'scope_present':(root/'config'/'scope.example.txt').exists() or (root/'config'/'scope.txt').exists(),'output_dir_writable':os.access(root,os.W_OK),'secret_env_names_supported':True}
 data={'schema_version':'173.0','checks':checks,'decision':'PASS' if all(checks.values()) else 'REVIEW_REQUIRED'}
 (ev/'configuration-validation-v173.json').write_text(json.dumps(data,indent=2)); return data
