"""V86 passive public-source collection adapters. No private access or active probing."""
from pathlib import Path
import json, urllib.parse, urllib.request, ssl

def _crtsh(target):
    q=urllib.parse.quote("%."+target,safe="")
    url="https://crt.sh/?q="+q+"&output=json"
    req=urllib.request.Request(url,headers={"User-Agent":"SecurityOperator/86 (passive research)"})
    with urllib.request.urlopen(req,timeout=15) as r: return json.loads(r.read().decode())

def build(outdir,target,collect=False):
    outdir=Path(outdir); results=[]; errors=[]
    if collect:
        try:
            data=_crtsh(target); names=set()
            for row in data:
                for n in str(row.get("name_value","" )).splitlines():
                    n=n.strip().lower().lstrip("*.")
                    if n.endswith(target.lower()): names.add(n)
            results=sorted(names)
        except (OSError, ValueError) as e: errors.append(f'{type(e).__name__}: {e}')
    payload={"version":"V86","target":target,"passive_only":True,"collection_requested":bool(collect),"sources":["crt.sh certificate transparency"],"subdomains":results,"errors":errors,"forbidden":["credential_harvesting","private_account_access","doxxing","unauthorized_probing"]}
    p=outdir/"evidence"/"osint-collection-v86.json"; p.write_text(json.dumps(payload,indent=2)); return p
