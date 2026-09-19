"""V233 OSINT investigation orchestrator and passive collection layer.
Public-source research only. No authentication bypass, private-account access,
credential harvesting, covert tracking, or arbitrary active scanning.
"""
from __future__ import annotations
import json, re, ssl, socket, ipaddress, urllib.parse, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from .atomic_io import atomic_write_json

SOURCE_CLASSES = {
    "technical": ["certificate-transparency", "rdap", "public-dns", "public-ip-data", "asn-routing"],
    "web": ["public-web", "web-archives", "robots", "sitemaps", "security-txt"],
    "code": ["public-code-hosts", "package-registries", "public-issues"],
    "documents": ["public-documents", "advisories", "public-reports"],
    "organization": ["official-sites", "public-registries", "public-filings"],
    "social": ["public-profile-pages", "public-posts"],
    "media": ["public-news", "press-releases", "public-interviews"],
    "images": ["public-images", "metadata", "reverse-image-research"],
}

def _target_kind(target: str) -> str:
    s = str(target).strip().lower()
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", s): return "domain"
    if s.startswith(("http://", "https://")): return "url"
    return "entity"

def _domain(target):
    raw=str(target).strip()
    return urllib.parse.urlparse(raw).hostname or raw.split('/')[0].split(':')[0]


def _public_host(host: str) -> bool:
    host=(host or '').strip().rstrip('.')
    if not host or host.lower() in {'localhost','localhost.localdomain'}:
        return False
    try:
        ip=ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        pass
    try:
        infos=socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses={info[4][0] for info in infos}
    if not addresses:
        return False
    for addr in addresses:
        try:
            ip=ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
    return True

def _get(url, timeout=10, max_bytes=65536):
    # Public OSINT still needs SSRF/redirect discipline. Never follow a redirect
    # from a public seed to an unreviewed host.
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme not in {"http","https"} or not parsed.hostname or not _public_host(parsed.hostname):
        raise ValueError("non-public-or-unsafe-source-host")
    from modules.safe_http import request as safe_request
    result=safe_request(url, method="GET", headers={"User-Agent":"PentestOSINT/233 (+authorized-public-research)"}, timeout=min(10,int(timeout)), max_body=min(max_bytes,65536))
    if not result.get("ok"):
        raise urllib.error.URLError(result.get("detail") or result.get("error") or "request-failed")
    return {"url":url,"status":result.get("status"),"content_type":(result.get("headers") or {}).get("Content-Type",""),"bytes":len((result.get("body") or "").encode("utf-8","replace")),"redirects_followed":False,"location":result.get("location","")}

def collect_public(root, target):
    """Collect only bounded public metadata endpoints useful for OSINT."""
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True); domain=_domain(target)
    if not _public_host(domain):
        data={"schema_version":"233.1","target":target,"domain":domain,"collection":"blocked","results":[],"errors":[{"error":"target-host-is-not-public-or-could-not-be-safely-resolved"}],"restrictions":["GET-only metadata endpoints","no authentication","no private sources","no arbitrary crawling","no credential harvesting"]}
        atomic_write_json(ev/'osint-public-collection-v233.json',data); return data
    urls=[
        f"https://crt.sh/?q={urllib.parse.quote('%.'+domain,safe='')}&output=json",
        f"https://rdap.org/domain/{urllib.parse.quote(domain,safe='')}",
        f"https://{domain}/robots.txt",
        f"https://{domain}/security.txt",
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/sitemap.xml",
        f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=A",
    ]
    results=[]; errors=[]
    for url in urls:
        try: results.append(_get(url))
        except (OSError, ValueError, urllib.error.URLError) as exc: errors.append({"url":url,"error":f"{type(exc).__name__}: {exc}"})
    data={"schema_version":"233.1","target":target,"domain":domain,"collection":"bounded_public_metadata","results":results,"errors":errors,"restrictions":["GET-only metadata endpoints","no authentication","no private sources","no arbitrary crawling","no credential harvesting"]}
    atomic_write_json(ev/'osint-public-collection-v233.json',data); return data

def build(root, target, objective="general", requested_sources=None, collect=False):
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    requested = requested_sources or list(SOURCE_CLASSES)
    selected = {k: SOURCE_CLASSES[k] for k in requested if k in SOURCE_CLASSES}
    data = {
        "schema_version": "233.0", "target": str(target).strip(), "target_kind": _target_kind(target),
        "objective": objective or "general", "collection_requested": bool(collect),
        "collection_policy": "public_sources_only", "source_classes": selected,
        "collection_loop": ["seed", "discover", "normalize", "correlate", "score", "identify_gaps", "expand", "finalize"],
        "coverage_dimensions": ["infrastructure", "web", "code", "documents", "organization", "social", "media", "images", "history"],
        "quality_requirements": ["source_url", "retrieved_at", "provenance", "deduplication", "independent_corroboration", "confidence", "limitations"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(ev / "osint-orchestrator-v233.json", data)
    if collect and _target_kind(target) in ("domain", "url"):
        data["collection"] = collect_public(root, target)
        atomic_write_json(ev / "osint-orchestrator-v233.json", data)
    return data
