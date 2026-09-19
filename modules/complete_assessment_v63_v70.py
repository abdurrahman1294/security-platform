from __future__ import annotations
from modules.infrastructure_intelligence_v63 import build as b63
from modules.cloud_intelligence_v64 import build as b64
from modules.ad_intelligence_v65 import build as b65
from modules.unified_attack_surface_v66 import build as b66
from modules.platform_controller_v67 import build as b67
from modules.evidence_quality_v68 import build as b68
from modules.final_report_v69 import build as b69
from modules.complete_platform_v70 import build as b70

def build(root, client, target):
    results=[]
    for fn,args in [(b63,(root,)),(b64,(root,)),(b65,(root,)),(b66,(root,)),(b67,(root,)),(b68,(root,)),(b69,(root,client,target))]:
        results.append(fn(*args))
    results.append(b70(root,client,target))
    return results
