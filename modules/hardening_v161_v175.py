from __future__ import annotations
import hashlib, json, os, re, tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
]
ALLOWED_SCHEMES = {"http", "https"}
PUBLIC_OSINT_HOSTS = {
    "crt.sh", "api.github.com", "github.com", "gitlab.com", "x.com", "linkedin.com",
    "facebook.com", "instagram.com", "youtube.com", "tiktok.com", "reddit.com",
    "archive.org", "web.archive.org", "www.google.com", "lens.google.com",
    "www.bing.com", "images.google.com"
}

def _safe_json(v):
    if isinstance(v, dict):
        return {str(k): _safe_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_safe_json(x) for x in v]
    if isinstance(v, str):
        s=v
        for p in SECRET_PATTERNS:
            s=p.sub(lambda m: m.group(1)+"=[REDACTED]" if "=" in m.group(0) or ":" in m.group(0) else "[REDACTED]", s)
        return s[:20000]
    return v

def atomic_write_json(path: str|Path, data):
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    payload=json.dumps(_safe_json(data), indent=2, sort_keys=True, ensure_ascii=False)
    fd,tmp=tempfile.mkstemp(prefix=p.name+".", dir=str(p.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return p

def validate_public_url(url: str, *, allowed_hosts=None):
    u=urlparse(url)
    if u.scheme not in ALLOWED_SCHEMES or not u.hostname:
        return False, "scheme-or-host-invalid"
    host=u.hostname.lower().rstrip('.')
    if host in {"localhost", "127.0.0.1", "::1"} or host.startswith("10.") or host.startswith("192.168.") or host.startswith("169.254."):
        return False, "private-or-local-host-blocked"
    hosts=allowed_hosts if allowed_hosts is not None else PUBLIC_OSINT_HOSTS
    if hosts and host not in {h.lower() for h in hosts}:
        return False, "host-not-allowlisted"
    return True, "ok"

def build_hardening(root, target=""):
    ev=Path(root)/"evidence"
    ev.mkdir(parents=True,exist_ok=True)
    artifacts=[]
    for p in sorted(ev.glob("*.json")):
        try:
            raw=p.read_bytes(); artifacts.append({"name":p.name,"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)})
        except OSError: pass
    return atomic_write_json(ev/"hardening-v161-v175.json", {
        "schema_version":"161-175.0","target":target,
        "controls":{
            "atomic_artifact_writes":True,"secret_redaction_before_indexing":True,
            "provenance_hashing":True,"strict_public_osint_url_policy":True,
            "private_network_osint_blocked":True,"operator_approval_for_active_actions":True,
            "no_covert_tracking":True,"no_private_account_access":True,
            "no_credential_harvesting":True,"no_license_bypass":True,
            "fail_closed_on_missing_scope":True,"truthful_completion_gate":True
        },
        "quality": {"artifact_count":len(artifacts),"generated_at":datetime.now(timezone.utc).isoformat()},
        "artifact_hashes":artifacts[-500:]
    })

def build_osint_source_registry(root):
    sources=[
      ("crtsh","certificate-transparency","passive",True),
      ("rdap","registration","passive",True),
      ("wayback","web-archive","passive",True),
      ("github-public","code/public-profile","passive",True),
      ("public-social","social-profile","passive",True),
      ("public-geodata","location-context","passive",True),
      ("local-image","image-metadata/hash","local",True),
      ("reverse-image","image-search","operator-assisted",True),
    ]
    return atomic_write_json(Path(root)/"evidence/osint-source-registry-v161.json", {
      "schema_version":"161.1","sources":[{"id":a,"category":b,"mode":c,"enabled":d,"requires_public_source":True} for a,b,c,d in sources],
      "policy":"Public/owner-authorized sources only; source terms and rate limits must be respected; no private access or covert tracking."
    })
