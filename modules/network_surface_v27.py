from __future__ import annotations
import ipaddress, socket, ssl
from pathlib import Path
from urllib.parse import urlparse
from .atomic_io import atomic_write_json

VERSION = "2.7"


def _host(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    return raw.rstrip(".")


def dns_observe(root: str | Path, target: str, *, timeout: float = 5.0) -> dict:
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    host = _host(target)
    if not host or len(host) > 253:
        raise ValueError("invalid DNS target")
    try:
        ipaddress.ip_address(host)
        data = {"status":"completed", "target":host, "addresses":[host], "reverse":socket.gethostbyaddr(host)[0] if ":" not in host or "." in host else None, "mode":"address-observation"}
    except ValueError:
        old = socket.getdefaulttimeout(); socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addrs = sorted({i[4][0] for i in infos})
            try: reverse = socket.gethostbyaddr(host)[0]
            except OSError: reverse = None
            data = {"status":"completed", "target":host, "addresses":addrs[:100], "reverse":reverse, "mode":"resolver-observation"}
        except OSError as exc:
            data = {"status":"failed", "target":host, "addresses":[], "error":str(exc)[:300]}
        finally:
            socket.setdefaulttimeout(old)
    atomic_write_json(root / "evidence" / "dns-observation-v27.json", data)
    return data


def tls_observe(root: str | Path, target: str, *, port: int = 443, timeout: float = 8.0) -> dict:
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    host = _host(target)
    if not host or not (1 <= int(port) <= 65535):
        raise ValueError("invalid TLS target")
    ctx = ssl.create_default_context()
    # Certificate observation intentionally does not disable verification.
    # If a lab/self-signed certificate is presented, the report records that
    # verification failed rather than weakening the client.
    data = {"status":"failed", "target":host, "port":int(port)}
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                data.update({"status":"completed", "protocol":s.version(), "cipher":s.cipher()[0] if s.cipher() else None,
                             "cipher_bits":s.cipher()[2] if s.cipher() else None,
                             "subject":cert.get("subject"), "issuer":cert.get("issuer"),
                             "san":cert.get("subjectAltName", [])})
    except ssl.SSLCertVerificationError as exc:
        data.update({"status":"certificate-verification-failed", "error":str(exc)[:300]})
    except (OSError, ssl.SSLError) as exc:
        data.update({"error":str(exc)[:300]})
    atomic_write_json(root / "evidence" / "tls-observation-v27.json", data)
    return data
