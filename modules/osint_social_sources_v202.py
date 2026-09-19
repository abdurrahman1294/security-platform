"""V202: public social-source registry with evidence coverage accounting."""
from __future__ import annotations
from pathlib import Path
from .atomic_io import atomic_write_json
SOURCES=["public profile pages","public posts","public code repositories","public professional profiles","public forum pages"]
def build(outdir):
    root=Path(outdir); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    artifacts=[p.name for p in ev.rglob('*') if p.is_file() and any(k in p.name.lower() for k in ('social','osint','profile','timeline'))]
    data={'version':'V202.1','sources':SOURCES,'collection':'manual/operator-assisted public-source research','observed_artifacts':sorted(set(artifacts)),'coverage':len(set(artifacts)),'forbidden':['private-account access','credential harvesting','session theft','doxxing','mass unsolicited contact']}
    atomic_write_json(ev/'osint-social-sources-v202.json',data); return data
