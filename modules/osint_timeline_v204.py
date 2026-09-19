"""V204: public-source timeline synthesis."""
from pathlib import Path
import json
def build(outdir,events=None):
 rows=sorted(events or [],key=lambda x:str(x.get('timestamp',''))); data={"version":"V204","events":rows,"ordering":"timestamp string; preserve original source","confidence":"event-level provenance required"}; p=Path(outdir)/"evidence/osint-timeline-v204.json"; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(data,indent=2)); return data
