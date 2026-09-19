"""Safe static IPA analysis for iOS applications."""
from __future__ import annotations
import hashlib, plistlib, re, zipfile, logging
logger = logging.getLogger(__name__)
from pathlib import Path
from modules.atomic_io import atomic_write_json

VERSION="3.2"
SECRET_PATTERNS=(re.compile(rb"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[A-Za-z0-9_\-]{8,}"), re.compile(rb"https?://[^\s\"']+"))

def analyze_ipa(root: str | Path, ipa: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True); p=Path(ipa)
    if not p.is_file() or p.suffix.lower() != ".ipa": return {"status":"blocked","reason":"ipa-file-required"}
    if p.stat().st_size > 250*1024*1024: return {"status":"blocked","reason":"ipa-too-large"}
    findings=[]; files=[]; urls=set(); markers=0; info={}
    with zipfile.ZipFile(p) as z:
        names=z.namelist(); files=names[:10000]
        plist_names=[n for n in names if n.endswith("Info.plist")]
        for name in plist_names[:3]:
            try:
                obj=plistlib.loads(z.read(name))
                if isinstance(obj,dict): info.update({str(k):obj[k] for k in obj if isinstance(k,str) and k in {"CFBundleIdentifier","CFBundleName","CFBundleShortVersionString","CFBundleVersion","MinimumOSVersion","NSAppTransportSecurity","UIBackgroundModes"}})
            except Exception as exc: logger.debug("invalid plist entry skipped: %s", exc)
        for name in names:
            if name.endswith("/") or z.getinfo(name).file_size > 8*1024*1024: continue
            raw=z.read(name)
            for pat in SECRET_PATTERNS:
                hits=pat.findall(raw[:2*1024*1024]); markers += len(hits)
            for u in re.findall(rb"https?://[^\s\"'<>]{4,200}",raw):
                urls.add(u.decode("utf-8","ignore"))
            if raw.startswith(b"\xcf\xfa\xed\xfe") or raw.startswith(b"\xfe\xed\xfa\xcf") or raw.startswith(b"\xca\xfe\xba\xbe"):
                findings.append({"id":"IOS-MACHO","title":"Mach-O native binary present","file":name,"severity":"info"})
    if "NSAppTransportSecurity" in info: findings.append({"id":"IOS-ATS","title":"ATS configuration requires review","severity":"medium"})
    if markers: findings.append({"id":"IOS-SECRET-MARKER","title":"Potential embedded secret markers","count":markers,"severity":"medium"})
    data={"schema_version":VERSION,"status":"completed","ipa":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"file_count":len(names),"metadata":info,"url_count":len(urls),"url_samples":sorted(urls)[:200],"findings":findings,"secret_marker_count":markers,"limitations":["Static markers are not proof of secrets.","Dynamic runtime behavior and server-side controls require separate authorized testing."]}
    atomic_write_json(ev/"ios-static-v32.json",data); return data
