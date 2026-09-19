from __future__ import annotations
from pathlib import Path
from security_platform.core.engagement import Engagement
from modules.osint_orchestrator_v233 import build as collect
from modules.osint_ingest_v234 import ingest
from modules.osint_correlation_v235 import build as correlate
from modules.osint_gap_engine_v236 import build as gaps
from modules.osint_intelligence_report_v237 import build as report
from modules.research_exhaustion_v241 import build as exhaustion
from security_platform.core.handoff import publish

class OSINTEngine:
    name="osint"
    def __init__(self, engagement: Engagement): self.e=engagement
    def run(self, objective="general", inputs=(), collect_public=True):
        collect(self.e.output,self.e.target,objective,collect=collect_public)
        paths=list(inputs); built=self.e.output/"evidence"/"osint-public-collection-v233.json"
        if built.exists(): paths.append(str(built))
        ingest(self.e.output,paths)
        correlate(self.e.output); gaps(self.e.output); report(self.e.output,self.e.target)
        exhaustion(self.e.output,self.e.target)
        # Publish only structured, public-intelligence asset candidates. The pentest
        # engine still applies its own authorization and scope controls.
        from modules.atomic_io import load_json
        corr=load_json(self.e.output/"evidence"/"osint-correlation-v235.json", {})
        assets=[]
        for ent in corr.get("entities", []):
            value=ent.get("value") or ent.get("host")
            if isinstance(value,str) and value: assets.append(value)
        publish(self.e.output,"osint",{"assets":sorted(set(assets)),"objective":objective})
        return {"engine":"osint","target":self.e.target,"objective":objective,"input_count":len(paths),"handoff_assets":len(set(assets))}
