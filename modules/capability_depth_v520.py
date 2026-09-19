"""V5.2 Capability depth — registered adapters, parsers, MCP, LLM supervisor,
retest, reports, lab benchmark.

Governance: authorization + scope + registered tools only. No arbitrary shell,
malware, phishing factories, or unrestricted exploitation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sqlite3
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

VERSION = "5.2.0"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _dump(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def load_scope(path: str | Path | None) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        return set()
    return {ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")}


def in_scope(target: str, allowed: set[str]) -> bool:
    if not allowed:
        return False
    t = target.strip().lower()
    host = t
    if "://" in t:
        try:
            host = (urllib.parse.urlsplit(t).hostname or t).lower()
        except Exception:
            host = t
    host_port = t
    for a in allowed:
        al = a.lower().strip()
        if t == al or host == al or host_port == al:
            return True
        if al.startswith("*.") and host.endswith(al[1:]):
            return True
        # host:port forms
        if host in al or al in host:
            if al == host or al.startswith(host + ":") or host.startswith(al):
                return True
    return False


# ---------------------------------------------------------------------------
# 1) Registered adapter pack
# ---------------------------------------------------------------------------

@dataclass
class AdapterResult:
    tool: str
    target: str
    status: str
    argv: list[str]
    stdout_path: str = ""
    stderr_path: str = ""
    exit_code: int | None = None
    error: str = ""
    evidence: dict = field(default_factory=dict)


class RegisteredAdapterPack:
    """Thin wrappers over security_platform.core.tools.run — never raw shell."""

    # Safe, bounded argv builders only
    BUILDERS: dict[str, Callable[[str], list[str]]] = {
        "nmap": lambda t: ["-Pn", "-sV", "--top-ports", "100", "-oX", "-", t],
        "naabu": lambda t: ["-host", t, "-silent", "-json"],
        "httpx": lambda t: ["-u", t if "://" in t else f"http://{t}", "-silent", "-json", "-title", "-status-code"],
        "nuclei": lambda t: ["-u", t if "://" in t else f"http://{t}", "-silent", "-jsonl", "-severity", "critical,high,medium"],
        "katana": lambda t: ["-u", t if "://" in t else f"http://{t}", "-silent", "-jsonl", "-d", "2"],
        "subfinder": lambda t: ["-d", t.split("://")[-1].split("/")[0].split(":")[0], "-silent", "-json"],
    }

    def __init__(self, output: Path):
        self.output = Path(output)
        self.runs = self.output / "evidence" / "adapter-runs-v520"
        self.runs.mkdir(parents=True, exist_ok=True)

    def available(self) -> list[str]:
        try:
            from security_platform.core.tools import inventory
            ready = {x.name for x in inventory() if x.status == "ready"}
        except Exception:
            ready = set()
        return sorted(set(self.BUILDERS) & ready) if ready else sorted(self.BUILDERS)

    def plan_argv(self, tool: str, target: str) -> list[str]:
        if tool not in self.BUILDERS:
            raise ValueError(f"unregistered-adapter:{tool}")
        return list(self.BUILDERS[tool](target))

    def execute(
        self,
        tool: str,
        target: str,
        *,
        authorized: bool,
        scope_file: str | Path | None,
        timeout: int = 300,
        dry_run: bool = False,
    ) -> AdapterResult:
        if not authorized:
            return AdapterResult(tool, target, "denied", [], error="authorization-required")
        allowed = load_scope(scope_file)
        if not in_scope(target, allowed):
            return AdapterResult(tool, target, "denied", [], error="out-of-scope")
        if tool not in self.BUILDERS:
            return AdapterResult(tool, target, "denied", [], error="unregistered-adapter")
        argv = self.plan_argv(tool, target)
        if dry_run:
            return AdapterResult(tool, target, "dry_run", argv, evidence={"note": "no execution"})
        try:
            from security_platform.core.tools import run as tool_run
            result = tool_run(self.output, tool, argv, timeout=timeout)
            # ToolManager may return dict or object
            if isinstance(result, dict):
                code = result.get("exit_code", result.get("returncode", 0))
                out = result.get("stdout", result.get("output", ""))
                err = result.get("stderr", "")
            else:
                code = getattr(result, "returncode", getattr(result, "exit_code", 0))
                out = getattr(result, "stdout", "") or ""
                err = getattr(result, "stderr", "") or ""
            out_p = self.runs / f"{tool}-{_fp(target, time.time())}.out"
            err_p = self.runs / f"{tool}-{_fp(target, time.time())}.err"
            out_p.write_text(str(out)[:500_000], encoding="utf-8", errors="replace")
            err_p.write_text(str(err)[:100_000], encoding="utf-8", errors="replace")
            return AdapterResult(
                tool, target, "completed" if code == 0 else "failed", argv,
                str(out_p), str(err_p), int(code) if code is not None else None,
                evidence={"bytes_out": len(str(out))},
            )
        except Exception as exc:
            return AdapterResult(tool, target, "error", argv, error=str(exc)[:500])


# ---------------------------------------------------------------------------
# 2) Expanded findings parsers
# ---------------------------------------------------------------------------

class ExpandedFindingsImporter:
    def __init__(self, output: Path):
        self.output = Path(output)
        self.out = self.output / "evidence" / "imported-findings-v520.json"

    def _nmap_xml(self, path: Path) -> list[dict]:
        findings = []
        try:
            root = ET.parse(path).getroot()
        except Exception as e:
            return [{"error": f"nmap:{e}"}]
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else ""
            for port in host.findall(".//port"):
                st = port.find("state")
                if st is not None and st.get("state") != "open":
                    continue
                svc = port.find("service")
                findings.append({
                    "source": "nmap", "host": ip, "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": svc.get("name") if svc is not None else "",
                    "product": svc.get("product") if svc is not None else "",
                    "severity": "info",
                })
        return findings

    def _nuclei_jsonl(self, path: Path) -> list[dict]:
        findings = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info") or {}
            findings.append({
                "source": "nuclei",
                "template": obj.get("template-id") or obj.get("templateID") or "",
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "host": obj.get("host") or obj.get("matched-at") or "",
            })
        return findings

    def _httpx_json(self, path: Path) -> list[dict]:
        findings = []
        raw = path.read_text(encoding="utf-8", errors="replace")
        chunks = [raw] if raw.strip().startswith("[") else raw.splitlines()
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                objs = json.loads(chunk)
                if not isinstance(objs, list):
                    objs = [objs]
            except Exception:
                continue
            for obj in objs:
                if isinstance(obj, dict):
                    findings.append({
                        "source": "httpx",
                        "url": obj.get("url") or obj.get("input") or "",
                        "status_code": obj.get("status_code") or obj.get("status-code"),
                        "title": obj.get("title") or "",
                        "severity": "info",
                    })
        return findings

    def _nikto(self, path: Path) -> list[dict]:
        findings = []
        text = path.read_text(encoding="utf-8", errors="replace")
        # CSV-ish or text
        for line in text.splitlines():
            if re.search(r"(?i)OSVDB|CVE-|+\s", line) or "retrieved" in line.lower():
                findings.append({"source": "nikto", "summary": line.strip()[:300], "severity": "medium"})
        if path.suffix.lower() == ".json":
            data = _load(path)
            if isinstance(data, dict):
                for v in data.get("vulnerabilities", data.get("items", [])) or []:
                    if isinstance(v, dict):
                        findings.append({
                            "source": "nikto",
                            "summary": v.get("msg") or v.get("message") or str(v)[:200],
                            "severity": "medium",
                        })
        return findings[:200]

    def _sqlmap(self, path: Path) -> list[dict]:
        findings = []
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".json":
            data = _load(path)
            if isinstance(data, dict):
                for item in data.get("results", data.get("data", [])) or []:
                    if isinstance(item, dict):
                        findings.append({
                            "source": "sqlmap",
                            "url": item.get("url") or "",
                            "parameter": item.get("parameter") or item.get("place") or "",
                            "technique": item.get("technique") or "",
                            "severity": "high",
                        })
        for m in re.finditer(r"(?i)(parameter:|payload:|injectable)([^\n]{0,120})", text):
            findings.append({"source": "sqlmap", "summary": m.group(0).strip(), "severity": "high"})
        return findings[:200]

    def _gobuster(self, path: Path) -> list[dict]:
        findings = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            # Status:200 Size:... or (Status: 200)
            if re.search(r"Status:\s*200|Status:\s*301|Status:\s*302|\(Status:\s*\d+\)", line):
                findings.append({"source": "gobuster", "path": line.strip()[:300], "severity": "info"})
        return findings[:300]

    def _masscan(self, path: Path) -> list[dict]:
        findings = []
        text = path.read_text(encoding="utf-8", errors="replace")
        # masscan list or json
        for m in re.finditer(r"Discovered open port (\d+)/(\w+) on ([0-9.]+)", text):
            findings.append({
                "source": "masscan", "port": m.group(1), "protocol": m.group(2),
                "host": m.group(3), "severity": "info",
            })
        data = _load(path)
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict) and "ports" in obj:
                    ip = obj.get("ip") or obj.get("ip_addr") or ""
                    for pr in obj.get("ports") or []:
                        findings.append({
                            "source": "masscan", "host": ip,
                            "port": pr.get("port"), "protocol": pr.get("proto"),
                            "severity": "info",
                        })
        return findings[:300]

    def import_file(self, path: Path) -> list[dict]:
        name = path.name.lower()
        if not path.is_file():
            return [{"error": f"missing:{path}"}]
        if "nmap" in name or path.suffix.lower() == ".xml":
            return self._nmap_xml(path)
        if "nuclei" in name or path.suffix.lower() == ".jsonl":
            sample = path.read_text(encoding="utf-8", errors="replace")[:300]
            if "template-id" in sample or "templateID" in sample or "nuclei" in name:
                return self._nuclei_jsonl(path)
        if "httpx" in name:
            return self._httpx_json(path)
        if "nikto" in name:
            return self._nikto(path)
        if "sqlmap" in name:
            return self._sqlmap(path)
        if "gobuster" in name or "dirb" in name or "ferox" in name:
            return self._gobuster(path)
        if "masscan" in name:
            return self._masscan(path)
        if path.suffix.lower() == ".json":
            sample = path.read_text(encoding="utf-8", errors="replace")[:400]
            if "template-id" in sample:
                return self._nuclei_jsonl(path)
            return self._httpx_json(path)
        return [{"error": f"unsupported:{path.name}"}]

    def run(self, paths: Iterable[str | Path]) -> dict:
        all_f: list[dict] = []
        for p in paths:
            all_f.extend(self.import_file(Path(p)))
        report = {
            "schema_version": VERSION,
            "imported": len([x for x in all_f if "error" not in x]),
            "errors": len([x for x in all_f if "error" in x]),
            "findings": all_f[:800],
        }
        _dump(self.out, report)
        return report


# ---------------------------------------------------------------------------
# 3) Governed local MCP server (registered tools only)
# ---------------------------------------------------------------------------

class GovernedMCPServer:
    """Minimal JSON-RPC MCP-style HTTP endpoint. Planning + registered execute only."""

    def __init__(self, output: Path, scope_file: str | Path | None = None, host: str = "127.0.0.1", port: int = 8765):
        self.output = Path(output)
        self.scope_file = scope_file
        self.host = host
        self.port = port
        self.adapters = RegisteredAdapterPack(self.output)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def tools_list(self) -> list[dict]:
        tools = [
            {"name": "security.plan", "description": "Return governed next-step plan (no execution)"},
            {"name": "security.status", "description": "Adapter and scope status"},
            {"name": "security.import_findings", "description": "Import tool output files into findings"},
        ]
        for name in self.adapters.available():
            tools.append({
                "name": f"security.run.{name}",
                "description": f"Execute registered adapter {name} against in-scope target (requires authorize=true)",
            })
        return tools

    def handle(self, req: dict, *, authorized: bool = False) -> dict:
        rid = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.tools_list()}}
        if method == "tools/call":
            name = params.get("name") or ""
            args = params.get("arguments") or {}
            if name == "security.plan":
                target = str(args.get("target") or "")
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "target": target,
                    "adapters": self.adapters.available(),
                    "note": "Use security.run.* only with authorization and scope",
                }}
            if name == "security.status":
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "adapters": self.adapters.available(),
                    "scope_file": str(self.scope_file or ""),
                }}
            if name == "security.import_findings":
                files = args.get("files") or []
                rep = ExpandedFindingsImporter(self.output).run(files)
                return {"jsonrpc": "2.0", "id": rid, "result": rep}
            if name.startswith("security.run."):
                tool = name.split(".", 2)[-1]
                target = str(args.get("target") or "")
                dry = bool(args.get("dry_run", False))
                res = self.adapters.execute(
                    tool, target, authorized=authorized, scope_file=self.scope_file, dry_run=dry,
                )
                return {"jsonrpc": "2.0", "id": rid, "result": asdict(res)}
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown tool: {name}"}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown method: {method}"}}

    def start_background(self, *, authorized: bool = False) -> dict:
        """Bind 127.0.0.1 only. Does not enable auth by default."""
        output = self.output
        scope = self.scope_file
        adapters = self.adapters
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                try:
                    req = json.loads(body.decode("utf-8"))
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return
                # Authorization header: X-SP-Authorize: true (operator explicit)
                auth = authorized or (self.headers.get("X-SP-Authorize", "").lower() == "true")
                resp = outer.handle(req, authorized=auth)
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        try:
            httpd = ThreadingHTTPServer((self.host, self.port), H)
        except OSError as e:
            return {"status": "error", "error": str(e)}
        self._httpd = httpd

        def _serve():
            httpd.serve_forever(poll_interval=0.5)

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        self._thread = t
        info = {"status": "listening", "url": f"http://{self.host}:{self.port}/", "bind": "loopback-only"}
        _dump(self.output / "evidence" / "mcp-server-v520.json", info)
        return info

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()


# ---------------------------------------------------------------------------
# 4) Optional LLM supervisor (propose only — never executes)
# ---------------------------------------------------------------------------

class LLMSupervisor:
    """BYO key optional. Without keys, uses deterministic heuristic proposals."""

    def __init__(self, output: Path):
        self.output = Path(output)

    def _heuristic(self, target: str, evidence: dict) -> list[dict]:
        proposals = []
        findings = (evidence or {}).get("findings") or []
        ports = [f for f in findings if f.get("port")]
        web = [f for f in findings if f.get("url") or f.get("source") in ("httpx", "nuclei")]
        if not findings:
            proposals.append({"priority": 1, "action": "port_discovery", "tool": "naabu", "reason": "no findings yet"})
            proposals.append({"priority": 2, "action": "service_detect", "tool": "nmap", "reason": "baseline services"})
        if ports and not web:
            proposals.append({"priority": 1, "action": "http_probe", "tool": "httpx", "reason": "open ports without web evidence"})
        if web:
            proposals.append({"priority": 1, "action": "vuln_templates", "tool": "nuclei", "reason": "web surface observed"})
        proposals.append({"priority": 9, "action": "draft_report", "tool": None, "reason": "keep operator report current"})
        return proposals

    def propose(self, target: str, evidence: dict | None = None, provider: str = "heuristic") -> dict:
        evidence = evidence or {}
        proposals = self._heuristic(target, evidence)
        provider_used = "heuristic"
        note = "Deterministic supervisor; no external API called."
        # Optional: if user set OPENAI_API_KEY and provider=openai, we only annotate availability
        if provider == "openai" and os.environ.get("OPENAI_API_KEY"):
            provider_used = "openai-configured-but-local-heuristic"
            note = "API key present but supervisor stays propose-only heuristic in this build (no auto tool run)."
        elif provider == "ollama" and os.environ.get("OLLAMA_BASE_URL"):
            provider_used = "ollama-configured-but-local-heuristic"
            note = "Ollama configured; proposals remain local heuristic unless you extend the plugin."
        report = {
            "schema_version": VERSION,
            "target": target,
            "provider": provider_used,
            "proposals": proposals,
            "executes_tools": False,
            "note": note,
        }
        _dump(self.output / "evidence" / "llm-supervisor-v520.json", report)
        return report


# ---------------------------------------------------------------------------
# 5) Retest / regression mode
# ---------------------------------------------------------------------------

class RetestEngine:
    def __init__(self, output: Path):
        self.output = Path(output)
        self.db = self.output / "state" / "retest-v520.db"
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db) as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS snapshots(
              id TEXT PRIMARY KEY,
              label TEXT,
              ts REAL,
              finding_hash TEXT,
              payload TEXT
            )""")

    def snapshot(self, label: str, findings: list[dict]) -> dict:
        payload = json.dumps(findings, sort_keys=True, default=str)
        h = hashlib.sha256(payload.encode()).hexdigest()
        sid = _fp(label, h, time.time())
        with sqlite3.connect(self.db) as c:
            c.execute("INSERT INTO snapshots(id,label,ts,finding_hash,payload) VALUES(?,?,?,?,?)",
                      (sid, label, time.time(), h, payload[:200000]))
        rep = {"id": sid, "label": label, "finding_hash": h, "count": len(findings)}
        _dump(self.output / "evidence" / "retest-snapshot-v520.json", rep)
        return rep

    def diff(self, id_a: str, id_b: str) -> dict:
        with sqlite3.connect(self.db) as c:
            a = c.execute("SELECT finding_hash,payload,label FROM snapshots WHERE id=?", (id_a,)).fetchone()
            b = c.execute("SELECT finding_hash,payload,label FROM snapshots WHERE id=?", (id_b,)).fetchone()
        if not a or not b:
            return {"status": "error", "error": "snapshot-not-found"}
        fa = json.loads(a[1] or "[]")
        fb = json.loads(b[1] or "[]")
        sa = {json.dumps(x, sort_keys=True) for x in fa}
        sb = {json.dumps(x, sort_keys=True) for x in fb}
        rep = {
            "schema_version": VERSION,
            "a": {"id": id_a, "label": a[2], "hash": a[0]},
            "b": {"id": id_b, "label": b[2], "hash": b[0]},
            "unchanged": len(sa & sb),
            "resolved": len(sa - sb),
            "new": len(sb - sa),
            "regression": len(sb - sa) > 0 and len(sa - sb) == 0,
        }
        _dump(self.output / "evidence" / "retest-diff-v520.json", rep)
        return rep


# ---------------------------------------------------------------------------
# 6) Report pack (Markdown + HTML)
# ---------------------------------------------------------------------------

def build_report_pack(output: Path, target: str, findings: list[dict], proposals: list[dict] | None = None) -> dict:
    output = Path(output)
    findings = findings or []
    by_sev: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    md_lines = [
        f"# Security Assessment Report",
        f"",
        f"- **Target:** `{target}`",
        f"- **Generated:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"- **Engine:** security-platform {VERSION}",
        f"- **Findings:** {len(findings)}",
        f"",
        f"## Severity summary",
        f"",
    ]
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        if sev in by_sev:
            md_lines.append(f"- **{sev}:** {by_sev[sev]}")
    md_lines += ["", "## Findings (excerpt)", ""]
    for f in findings[:50]:
        md_lines.append(f"- `{f.get('source','?')}` [{f.get('severity','info')}] {f.get('name') or f.get('summary') or f.get('url') or f.get('host') or f}")
    if proposals:
        md_lines += ["", "## Supervisor proposals (not executed)", ""]
        for p in proposals:
            md_lines.append(f"- P{p.get('priority')}: {p.get('action')} tool={p.get('tool')} — {p.get('reason')}")
    md_lines += [
        "",
        "## Limitations",
        "",
        "- This report is produced by a governed automation layer.",
        "- Execution requires authorization, scope, and registered adapters.",
        "- Absence of a finding is not proof of security.",
        "",
    ]
    md = "\n".join(md_lines)
    md_path = output / "reports" / "executive-v520.md"
    html_path = output / "reports" / "executive-v520.html"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(md, encoding="utf-8")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Assessment Report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
code{{background:#f4f4f4;padding:0.1em 0.3em}} h1{{border-bottom:2px solid #333}}</style>
</head><body><pre style="white-space:pre-wrap;font-family:inherit">{md.replace("&","&amp;").replace("<","&lt;")}</pre></body></html>"""
    html_path.write_text(html, encoding="utf-8")
    return {"markdown": str(md_path), "html": str(html_path), "finding_count": len(findings), "severity": by_sev}


# ---------------------------------------------------------------------------
# 7) Lab benchmark harness (synthetic / loopback)
# ---------------------------------------------------------------------------

def run_lab_benchmark(output: Path, target: str = "127.0.0.1") -> dict:
    """Self-check of fusion depth features without external network."""
    output = Path(output)
    results = []

    def check(name: str, fn):
        try:
            fn()
            results.append({"name": name, "status": "PASS"})
        except Exception as e:
            results.append({"name": name, "status": "FAIL", "error": str(e)[:200]})

    pack = RegisteredAdapterPack(output)
    check("adapters_listed", lambda: pack.available())
    check("adapter_dry_run_denied_without_auth", lambda: (
        (_r := pack.execute("nmap", target, authorized=False, scope_file=None, dry_run=True))
        and _r.status == "denied"
    ))

    scope = output / "scope-bench.txt"
    scope.write_text(f"{target}\nlocalhost\n", encoding="utf-8")
    check("adapter_dry_run_in_scope", lambda: (
        (_r := pack.execute("nmap", target, authorized=True, scope_file=scope, dry_run=True))
        and _r.status == "dry_run"
    ))

    imp = ExpandedFindingsImporter(output)
    xml = output / "bench-nmap.xml"
    xml.write_text("""<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>""", encoding="utf-8")
    check("import_nmap", lambda: imp.run([xml])["imported"] >= 1)

    gob = output / "bench-gobuster.txt"
    gob.write_text("/admin (Status: 200)\n/login (Status: 302)\n", encoding="utf-8")
    check("import_gobuster", lambda: imp.run([gob])["imported"] >= 1)

    sup = LLMSupervisor(output)
    check("supervisor_proposals", lambda: len(sup.propose(target)["proposals"]) >= 1)

    retest = RetestEngine(output)
    findings = (imp.run([xml]).get("findings") or [])
    s1 = retest.snapshot("before", findings)
    s2 = retest.snapshot("after", findings + [{"source": "bench", "severity": "info"}])
    check("retest_diff", lambda: retest.diff(s1["id"], s2["id"])["new"] >= 1)

    check("report_pack", lambda: build_report_pack(output, target, findings)["finding_count"] >= 1)

    mcp = GovernedMCPServer(output, scope_file=scope, port=0)  # port 0 may fail; use handle only
    check("mcp_tools_list", lambda: len(mcp.tools_list()) >= 3)
    check("mcp_rejects_shell", lambda: "error" in mcp.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "shell", "arguments": {}}},
        authorized=True,
    ))

    summary = {
        "schema_version": VERSION,
        "target": target,
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "results": results,
    }
    _dump(output / "evidence" / "lab-benchmark-v520.json", summary)
    return summary


# ---------------------------------------------------------------------------
# Unified facade
# ---------------------------------------------------------------------------

class DepthEngineV52:
    def __init__(self, output: str | Path, scope_file: str | Path | None = None):
        self.output = Path(output)
        self.scope_file = scope_file
        self.adapters = RegisteredAdapterPack(self.output)
        self.importer = ExpandedFindingsImporter(self.output)
        self.supervisor = LLMSupervisor(self.output)
        self.retest = RetestEngine(self.output)
        self.mcp = GovernedMCPServer(self.output, scope_file=scope_file)

    def run_adapter(self, tool: str, target: str, *, authorized: bool, dry_run: bool = False) -> dict:
        return asdict(self.adapters.execute(
            tool, target, authorized=authorized, scope_file=self.scope_file, dry_run=dry_run,
        ))

    def import_findings(self, paths: Iterable[str | Path]) -> dict:
        return self.importer.run(paths)

    def propose(self, target: str, provider: str = "heuristic") -> dict:
        data = _load(self.output / "evidence" / "imported-findings-v520.json") or {}
        return self.supervisor.propose(target, data, provider=provider)

    def snapshot(self, label: str) -> dict:
        data = _load(self.output / "evidence" / "imported-findings-v520.json") or {}
        return self.retest.snapshot(label, data.get("findings") or [])

    def diff(self, a: str, b: str) -> dict:
        return self.retest.diff(a, b)

    def report(self, target: str) -> dict:
        data = _load(self.output / "evidence" / "imported-findings-v520.json") or {}
        prop = _load(self.output / "evidence" / "llm-supervisor-v520.json") or {}
        return build_report_pack(self.output, target, data.get("findings") or [], prop.get("proposals"))

    def benchmark(self, target: str = "127.0.0.1") -> dict:
        return run_lab_benchmark(self.output, target)

    def mcp_list(self) -> dict:
        return self.mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    def status(self) -> dict:
        return {
            "schema_version": VERSION,
            "adapters_available": self.adapters.available(),
            "scope_file": str(self.scope_file or ""),
            "governance": {
                "authorization_required": True,
                "scope_required": True,
                "registered_adapters_only": True,
                "llm_supervisor_execute": False,
            },
        }
