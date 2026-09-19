"""V78 evidence memory: normalized cross-module context without retaining secrets."""
from pathlib import Path
import json,re,hashlib
_SECRET=re.compile(r'(?i)(authorization\s*:\s*bearer\s+[^\s]+|cookie\s*:\s*[^\n]+|set-cookie\s*:\s*[^\n]+|password\s*[=:]\s*[^\s,]+|token\s*[=:]\s*[^\s,]+)')
def sanitize(v):
    if isinstance(v,str): return _SECRET.sub(lambda m:m.group(0).split(':',1)[0]+': [REDACTED]',v)
    if isinstance(v,dict): return {k:sanitize(x) for k,x in v.items()}
    if isinstance(v,list): return [sanitize(x) for x in v]
    return v
def build(outdir):
    outdir=Path(outdir); records=[]
    for p in sorted((outdir/"evidence").glob("*.json")):
        try:
            data=json.loads(p.read_text(errors="ignore")); clean=sanitize(data)
            records.append({"artifact":str(p.relative_to(outdir)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"keys":sorted(clean.keys()) if isinstance(clean,dict) else [],"summary":clean if isinstance(clean,dict) and len(json.dumps(clean))<5000 else None})
        except (OSError, json.JSONDecodeError, UnicodeError): continue
    payload={"version":"V78","record_count":len(records),"records":records,"secret_policy":"redacted"}
    ep=outdir/"evidence"/"evidence-memory-v78.json"; ep.write_text(json.dumps(payload,indent=2))
    rp=outdir/"reports"/"evidence-memory-v78.md"; rp.write_text("# Evidence Memory\n\nArtifacts indexed: %d\n\nSecrets are redacted before indexing.\n"%len(records)); return ep
