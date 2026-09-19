from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json

def build(root):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    required=['unit regression','tool availability','scope enforcement','pipeline integration','malformed outputs','interrupted execution','OSINT provenance','image metadata','API/auth labs','report accuracy']
    test_count=len(list((root/'tests').glob('test_*.py'))) if (root/'tests').exists() else 0
    data={'schema_version':'190.0','baseline':'V170 hardened + V171-V189 excellence','test_plan':required,'test_file_count':test_count,'success_rule':'never claim capability without observed evidence','decision':'TEST_SUITE_PRESENT' if test_count else 'TEST_SUITE_MISSING'}
    atomic_write_json(ev/'pretest-manifest-v190.json',data); return data
