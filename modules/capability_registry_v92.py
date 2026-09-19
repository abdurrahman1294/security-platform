from __future__ import annotations
from pathlib import Path
import shutil
from .atomic_io import atomic_write_json
from .tool_adapter_hardening_v162 import executable_path, verify_executable_identity
CAPABILITIES={
 'recon':{'description':'Authorized subdomain and asset discovery','tool_chain':['subfinder','assetfinder','httpx'],'risk':'low','approval':'required'},
 'network':{'description':'Port and service enumeration','tool_chain':['naabu','nmap'],'risk':'low','approval':'required'},
 'web':{'description':'Web crawling and endpoint intelligence','tool_chain':['katana','httpx'],'risk':'low','approval':'required'},
 'vulnerability':{'description':'Template-based vulnerability discovery','tool_chain':['nuclei'],'risk':'medium','approval':'required'},
 'intelligence':{'description':'Evidence normalization, correlation and prioritization','tool_chain':[],'risk':'none','approval':'not-required'},
 'reporting':{'description':'Evidence-driven report generation','tool_chain':[],'risk':'none','approval':'not-required'}
}
def build(root):
    root=Path(root); p=root/'evidence'/'capability-registry-v92.json'; p.parent.mkdir(parents=True,exist_ok=True)
    tools={}
    for tool in sorted({t for c in CAPABILITIES.values() for t in c['tool_chain']}):
        resolved=executable_path(tool)
        if not resolved: tools[tool]={'status':'not-installed'}; continue
        ok,reason=verify_executable_identity(tool,resolved); tools[tool]={'status':'ready' if ok else 'identity-mismatch','path':resolved,'identity':reason}
    data={'version':'V92.1','capabilities':CAPABILITIES,'tool_readiness':tools}
    atomic_write_json(p,data); return p
