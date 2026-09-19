from __future__ import annotations
import hashlib, json, mimetypes
from datetime import datetime, timezone
from pathlib import Path
from .hardening_v161_v175 import atomic_write_json

try:
    from PIL import Image, ExifTags
except ImportError:
    Image=None; ExifTags={}

def inspect_image(path):
    p=Path(path); out={"path":str(p),"exists":p.is_file()}
    if not p.is_file(): return out
    b=p.read_bytes(); out.update({"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"mime":mimetypes.guess_type(p.name)[0]})
    if Image is None: out["metadata_status"]="pillow-unavailable"; return out
    try:
        with Image.open(p) as im:
            out["format"]=im.format; out["dimensions"]=[im.width,im.height]; ex=im.getexif(); meta={}
            for k,v in ex.items():
                name=ExifTags.TAGS.get(k,str(k))
                if name in {"GPSInfo","DateTime","DateTimeOriginal","Make","Model","Software","Artist","Copyright"}:
                    meta[name]=str(v)[:1000]
            out["exif"]=meta; out["gps_present"]=bool(meta.get("GPSInfo")); out["metadata_status"]="parsed"
    except (OSError, ValueError, TypeError, KeyError) as exc: out["metadata_status"]="parse-error"; out["error"]=str(exc)[:200]
    return out

def build_osint_quality(root, image_paths=None):
    images=[inspect_image(p) for p in (image_paths or [])]
    return atomic_write_json(Path(root)/"evidence/osint-quality-v165-v170.json", {
        "schema_version":"165-170.0","generated_at":datetime.now(timezone.utc).isoformat(),
        "source_quality": {"provenance_required":True,"independent_corroboration_for_high_confidence":True,"stale_data_flagging":True},
        "image_analysis":{"local_metadata":True,"sha256":True,"gps_is_unverified_until_corroborated":True,"reverse_search":"operator-assisted public service workflow"},
        "images":images,
        "tracking_policy":{"lost_device":"owner-controlled official recovery only","person_tracking":"not provided","covert_tracking":"blocked"}
    })
