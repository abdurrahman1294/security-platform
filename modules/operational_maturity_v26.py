from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from typing import Any
from .atomic_io import atomic_write_json, load_json

VERSION = "2.6"
_SECRET_KEYS = re.compile(r"(password|passwd|secret|token|authorization|cookie|api[_-]?key|private[_-]?key)", re.I)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def artifact_inventory(root: str | Path, *, max_files: int = 5000, max_bytes: int = 8 * 1024 * 1024) -> dict:
    root = Path(root).resolve()
    records = []
    skipped = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or ".git" in p.parts or ".pytest_cache" in p.parts:
            continue
        if len(records) >= max_files:
            skipped += 1
            continue
        try:
            size = p.stat().st_size
            rec = {"path": str(p.relative_to(root)), "size": size}
            if size <= max_bytes:
                rec["sha256"] = _sha256(p)
            else:
                rec["sha256"] = None
                rec["hash_skipped"] = "size-limit"
            records.append(rec)
        except OSError as exc:
            records.append({"path": str(p.relative_to(root)), "status": "unreadable", "error": str(exc)[:200]})
    data = {"schema_version": VERSION, "files": records, "skipped": skipped}
    atomic_write_json(root / "evidence" / "artifact-inventory-v26.json", data)
    return data


def _load_findings(root: Path) -> list[dict]:
    out = []
    roots = [root / x for x in ("vulns", "api", "web", "evidence")]
    for base in roots:
        if not base.exists():
            continue
        for p in base.glob("**/*.json"):
            try:
                obj = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            vals = obj if isinstance(obj, list) else obj.get("findings", []) if isinstance(obj, dict) else []
            if isinstance(vals, list):
                for x in vals:
                    if isinstance(x, dict) and any(k in x for k in ("severity", "info", "template-id", "finding_id", "title")):
                        out.append({"source": str(p.relative_to(root)), "record": _redact(x)})
    return out

def correlate(root: str | Path) -> dict:
    root = Path(root)
    hosts: set[str] = set()
    urls: set[str] = set()
    findings = _load_findings(root)
    identity_refs: set[str] = set()
    for p in root.rglob("*.txt"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")[:2_000_000]
        except OSError:
            continue
        for token in re.findall(r"https?://[^\s\"'<>]+", text):
            urls.add(token.rstrip(".,)"))
        for token in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b|\b(?:127\.0\.0\.1|localhost)\b", text):
            hosts.add(token)
    for p in root.rglob("*.json"):
        try:
            obj = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        stack = [obj]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if k.lower() in {"url", "target", "host", "hostname", "fqdn"} and isinstance(v, str):
                        if v.startswith(("http://", "https://")): urls.add(v)
                        elif v: hosts.add(v)
                    if k.lower() in {"username", "principal", "account", "identity", "user"} and isinstance(v, str):
                        identity_refs.add(v)
                    stack.append(v)
            elif isinstance(cur, list):
                stack.extend(cur)
    data = {
        "schema_version": VERSION,
        "hosts": sorted(hosts)[:10000],
        "urls": sorted(urls)[:10000],
        "identity_references": sorted(identity_refs)[:10000],
        "finding_records": findings[:10000],
        "correlation_rule": "Correlations are evidence references, not proof of exploitability or attribution.",
    }
    atomic_write_json(root / "evidence" / "cross-engine-correlation-v26.json", data)
    return data


def coverage(root: str | Path, *, executed: dict | None = None) -> dict:
    root = Path(root)
    executed = executed or {}
    artifacts = {p.name for p in root.rglob("*") if p.is_file()}
    checks = {
        "recon": "subdomains.txt" in artifacts or "pentest-recon.json" in artifacts,
        "web": "live-hosts.txt" in artifacts or "urls.txt" in artifacts,
        "ports": "naabu.txt" in artifacts or "nmap-detailed.nmap" in artifacts or "nmap-top.nmap" in artifacts,
        "vulnerabilities": "findings.json" in artifacts or "findings.txt" in artifacts,
        "credentials": "credential-discovery.json" in artifacts,
        "mobile": any(p.name == "android-analysis.json" for p in root.rglob("*")),
        "wireless": any("wireless" in p.name.lower() or "pcap" in p.name.lower() for p in root.rglob("*")),
        "remote": "remote-assessment.json" in artifacts or "remote-lab-assessment.json" in artifacts,
    }
    for key, val in executed.items():
        if key in checks:
            checks[key] = bool(val) and checks[key]
    covered = [k for k, v in checks.items() if v]
    data = {"schema_version": VERSION, "domains": checks, "covered": covered, "coverage_count": len(covered), "coverage_rule": "Only evidence-backed execution counts."}
    atomic_write_json(root / "evidence" / "coverage-v26.json", data)
    return data


def health(root: str | Path, *, tool_inventory=None) -> dict:
    root = Path(root)
    tools = tool_inventory or []
    tool_map = {}
    for item in tools:
        if isinstance(item, dict) and item.get("name"):
            tool_map[item["name"]] = item
    required = ["subfinder", "assetfinder", "httpx", "naabu", "nmap", "katana", "nuclei"]
    available = [x for x in required if tool_map.get(x, {}).get("available") is True]
    data = {
        "schema_version": VERSION,
        "status": "healthy" if len(available) == len(required) else "degraded",
        "required_tools": required,
        "available_tools": available,
        "missing_tools": [x for x in required if x not in available],
        "principle": "Tool absence reduces executable coverage; it never turns planned work into completed work.",
    }
    atomic_write_json(root / "evidence" / "engine-health-v26.json", data)
    return data


def build_run_state(root: str | Path, *, engine: str, phase: str, status: str, details=None) -> dict:
    root = Path(root)
    path = root / "evidence" / "run-state-v26.json"
    current = load_json(path, default={}) or {}
    runs = current.get("runs", []) if isinstance(current, dict) else []
    runs.append({"engine": engine, "phase": phase, "status": status, "details": _redact(details or {})})
    data = {"schema_version": VERSION, "runs": runs[-1000:], "last": runs[-1]}
    atomic_write_json(path, data)
    return data
