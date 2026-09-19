"""Offline container image security assessment for OCI/Docker archives.

No image is run and no registry is contacted.  The analyzer inspects manifests
and config JSON only, making it suitable for CI and evidence preservation.
"""
from __future__ import annotations
import hashlib, json, tarfile, logging
logger = logging.getLogger(__name__)
from pathlib import Path
from modules.atomic_io import atomic_write_json

VERSION="3.3"

def assess_archive(root: str|Path, archive: str|Path) -> dict:
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); p=Path(archive)
    if not p.is_file(): return {"status":"blocked","reason":"container-archive-required"}
    if p.stat().st_size>2*1024*1024*1024: return {"status":"blocked","reason":"container-archive-too-large"}
    findings=[]; configs=[]; manifests=[]
    try:
        with tarfile.open(p,'r:*') as tf:
            names=tf.getnames()[:20000]
            for n in names:
                if n.endswith(('manifest.json','index.json')) and tf.getmember(n).size<5*1024*1024:
                    try: manifests.append(json.loads(tf.extractfile(n).read().decode()))
                    except Exception as exc: logger.debug("malformed container manifest skipped: %s", exc)
                if ('config' in n.lower() or n.endswith('.json')) and tf.getmember(n).size<10*1024*1024:
                    try:
                        obj=json.loads(tf.extractfile(n).read().decode())
                        if isinstance(obj,dict) and ('config' in obj or 'container_config' in obj): configs.append(obj)
                    except Exception as exc: logger.debug("malformed container config skipped: %s", exc)
    except (OSError,tarfile.TarError) as exc:
        return {"status":"blocked","reason":f"invalid-container-archive:{exc}"}
    for c in configs:
        cfg=c.get('config') or c.get('container_config') or {}
        user=str(cfg.get('User','')).strip()
        if user in {'','0','root'}:
            findings.append({"id":"CTR-ROOT","title":"Container image defaults to root user","severity":"medium"})
        env=[str(x) for x in cfg.get('Env',[]) if isinstance(x,str)]
        secret_env=[x.split('=',1)[0] for x in env if any(k in x.lower() for k in ('secret','password','token','apikey','api_key','access_key'))]
        if secret_env:
            findings.append({"id":"CTR-SECRET-ENV","title":"Potential secret-bearing environment variable names","severity":"high","names":sorted(set(secret_env))})
        ports=cfg.get('ExposedPorts') or {}
        if ports: findings.append({"id":"CTR-EXPOSED","title":"Image declares exposed ports","severity":"info","ports":sorted(map(str,ports.keys()))[:100]})
        if cfg.get('Healthcheck') is None:
            findings.append({"id":"CTR-NO-HEALTHCHECK","title":"No container healthcheck declared","severity":"low"})
    out={"schema_version":VERSION,"status":"completed","archive":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"manifest_count":len(manifests),"config_count":len(configs),"findings":findings,"limitations":["Static archive analysis only; the image is never executed.","Runtime isolation, registry policy and Kubernetes admission controls require separate assessment."]}
    atomic_write_json(ev/'container-security-v33.json',out); return out
