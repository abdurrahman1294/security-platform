"""V201: cross-domain public-source entity graph."""
from pathlib import Path
import json,hashlib
def build(outdir,entities=None,edges=None):
 nodes=[]
 for e in entities or []:
  raw=str(e.get('value','')); nodes.append({"type":e.get('type','unknown'),"value":raw,"id":hashlib.sha256(raw.encode()).hexdigest()[:16],"source":e.get('source','unknown'),"confidence":e.get('confidence','unknown')})
 data={"version":"V201","nodes":nodes,"edges":edges or [],"rules":["public sources only","retain provenance","no unsupported attribution"]}; p=Path(outdir)/"evidence/osint-entity-graph-v201.json"; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(data,indent=2)); return data
