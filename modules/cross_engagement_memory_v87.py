"""V87 durable engagement memory with hashed, sanitized records."""
from pathlib import Path
import json,hashlib,re
SECRET=re.compile(r"(?i)(authorization\s*:\s*bearer\s+[^\s]+|cookie\s*:\s*[^\n]+|set-cookie\s*:\s*[^\n]+|password\s*[=:]\s*[^\s,]+|token\s*[=:]\s*[^\s,]+)")
def clean(v):
    if isinstance(v,str): return SECRET.sub("[REDACTED]",v)
    if isinstance(v,dict): return {k:clean(x) for k,x in v.items()}
    if isinstance(v,list): return [clean(x) for x in v]
    return v
def build(outdir,target):
    outdir=Path(outdir); entries=[]
    for p in sorted((outdir/"evidence").glob("*.json")):
        if p.name=="cross-engagement-memory-v87.json": continue
        try:
            d=clean(json.loads(p.read_text(errors="ignore"))); entries.append({"artifact":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"summary":d if len(json.dumps(d))<3500 else {"keys":list(d)[:30] if isinstance(d,dict) else []}})
        except (OSError, json.JSONDecodeError, UnicodeError): pass
    payload={"version":"V87","target":target,"records":entries,"secrets":"redacted","reusable_context":True}
    p=outdir/"evidence"/"cross-engagement-memory-v87.json"; p.write_text(json.dumps(payload,indent=2)); return p
