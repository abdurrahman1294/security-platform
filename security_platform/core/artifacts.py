from __future__ import annotations
from pathlib import Path
import json
from modules.atomic_io import atomic_write_json

def write_json(root: str | Path, name: str, data) -> Path:
    p=Path(root)/"evidence"/name
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(p, data)
    return p

def read_json(root: str | Path, name: str, default=None):
    p=Path(root)/"evidence"/name
    if not p.is_file(): return {} if default is None else default
    try: return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError): return {} if default is None else default
