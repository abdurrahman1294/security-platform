"""V3.8 safe end-to-end intelligence orchestration."""
from pathlib import Path
from modules.intelligence_fabric_v38 import asset_context,multi_hop_paths,calibrate_findings,provenance_chain,remediation_dependencies,session_model,plugin_contract,coverage

PHASES=("asset_context","multi_hop_paths","confidence_calibration","provenance_chain","remediation_dependencies","session_model","plugin_contract","coverage")

def build(root):
    root=Path(root); results={}
    results["asset_context"]=asset_context(root)
    results["multi_hop_paths"]=multi_hop_paths(root)
    results["confidence_calibration"]=calibrate_findings(root)
    results["provenance_chain"]=provenance_chain(root)
    results["remediation_dependencies"]=remediation_dependencies(root)
    results["session_model"]=session_model(root)
    results["plugin_contract"]=plugin_contract(root)
    results["coverage"]=coverage(root)
    return {"schema_version":"3.8","status":"completed","phases":list(PHASES),"results":results}
