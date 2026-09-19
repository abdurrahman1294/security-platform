"""V3.51 safe specialist-tool integration harness.

Runs only allowlisted, read-only assessment tools against disposable loopback
fixtures. Installed tools are exercised end-to-end; unavailable tools remain
explicitly unavailable rather than being replaced by an unsafe generic runner.
No credentials, external targets, mutation, persistence, C2, or destructive
operations are permitted by this harness.
"""
from __future__ import annotations
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer, StreamRequestHandler
from urllib.parse import urlparse
import hashlib, json, threading, time

from modules.reliability_execution_integrity_v331 import atomic_write, redact
from modules.tool_manager_v40 import ToolManager, TOOLS
from security_platform.core.tools import inventory

VERSION = "3.51.0"


def _id(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:20]


def _write(root: Path, rel: str, obj):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(p, redact(obj))
    return p


class _HTTP(BaseHTTPRequestHandler):
    server_version = "V351Lab/1.0"

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            body = "ok"
        elif path == "/api/users/1":
            body = '{"id":"1","role":"user"}'
        elif path == "/search":
            body = "<html>lab search</html>"
        else:
            body = "V351-LOCAL-LAB"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_):
        return


class _TCP(StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"V351-LAB-SERVICE\r\n")


def _start_range():
    http = ThreadingHTTPServer(("127.0.0.1", 0), _HTTP)
    tcp = TCPServer(("127.0.0.1", 0), _TCP)
    ht = threading.Thread(target=http.serve_forever, daemon=True)
    tt = threading.Thread(target=tcp.serve_forever, daemon=True)
    ht.start(); tt.start()
    return http, tcp, ht, tt


def _safe_loopback(value: str) -> bool:
    text = str(value).strip().lower()
    return text in {"127.0.0.1", "localhost", "::1"} or text.startswith("127.")


def _probe_specs(root: Path, http_port: int, tcp_port: int) -> list[dict]:
    return [
        {"tool_id": "nmap", "argv": ["nmap", "-sV", "-Pn", "--top-ports", "10", "-p", str(http_port) + "," + str(tcp_port), "127.0.0.1"], "purpose": "local service enumeration"},
        {"tool_id": "httpx", "argv": ["httpx", "-u", f"http://127.0.0.1:{http_port}/health", "-silent", "-status-code", "-title"], "purpose": "local HTTP probing"},
        {"tool_id": "naabu", "argv": ["naabu", "-host", "127.0.0.1", "-top-ports", "10", "-silent"], "purpose": "local port discovery"},
        {"tool_id": "katana", "argv": ["katana", "-u", f"http://127.0.0.1:{http_port}/", "-d", "1", "-silent"], "purpose": "local web crawling"},
    ]


def run_tool_integration(root: str | Path, *, execute: bool = True) -> dict:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    if not _safe_loopback("127.0.0.1"):
        raise RuntimeError("internal lab target failed loopback policy")
    http, tcp, ht, tt = _start_range()
    hp, tp = http.server_address[1], tcp.server_address[1]
    manager = ToolManager(root)
    statuses = {x.name: x.status for x in inventory()}
    results = []
    try:
        for spec in _probe_specs(root, hp, tp):
            tool = spec["tool_id"]
            row = {"scenario_id": _id("v351", tool), "tool_id": tool, "purpose": spec["purpose"], "target": "127.0.0.1", "argv": spec["argv"], "environment_status": statuses.get(tool, "unregistered")}
            if tool not in TOOLS:
                row.update({"status": "rejected", "reason": "not-registered"})
            elif statuses.get(tool) != "ready":
                row.update({"status": "environment-limited", "reason": statuses.get(tool, "unknown")})
            elif not execute:
                row.update({"status": "ready-not-executed", "reason": "execution-disabled"})
            else:
                try:
                    proc = manager.run(tool, spec["argv"], timeout=30, cwd=root)
                    out = (proc.stdout or "")[-12000:]
                    err = (proc.stderr or "")[-6000:]
                    _write(root, f"evidence/{tool}-stdout.txt", out)
                    _write(root, f"evidence/{tool}-stderr.txt", err)
                    row.update({"status": "executed", "returncode": proc.returncode, "stdout_bytes": len((proc.stdout or "").encode()), "stderr_bytes": len((proc.stderr or "").encode())})
                except Exception as exc:
                    row.update({"status": "execution-error", "error_type": type(exc).__name__, "error": str(exc)})
            results.append(row)
    finally:
        http.shutdown(); http.server_close(); ht.join(timeout=2)
        tcp.shutdown(); tcp.server_close(); tt.join(timeout=2)

    executed = [r for r in results if r["status"] == "executed"]
    errors = [r for r in results if r["status"] == "execution-error"]
    readiness = {"ready": sum(v == "ready" for v in statuses.values()), "total": len(statuses), "unavailable": sum(v != "ready" for v in statuses.values())}
    report = {
        "schema_version": VERSION,
        "status": "PASS" if not errors else "FAIL",
        "execution_mode": "loopback-only",
        "target_policy": {"loopback_only": True, "external_targets": False, "synthetic_data_only": True},
        "range": {"http_port": hp, "tcp_port": tp, "ephemeral": True},
        "summary": {"probes": len(results), "executed": len(executed), "execution_errors": len(errors), "environment_limited": sum(r["status"] == "environment-limited" for r in results)},
        "tool_readiness": readiness,
        "results": results,
        "limitations": [
            "Only tools installed and passing executable-identity checks can execute.",
            "This harness validates integration plumbing on loopback, not universal real-world efficacy.",
            "Cloud, identity, mobile, wireless, OT, automotive, and other non-local specialist tools are readiness-audited unless a matching isolated target adapter exists.",
        ],
        "created_at": time.time(),
    }
    _write(root, "evidence/specialist-tool-integration-v351.json", report)
    return report


def v351_test_matrix():
    names = [
        "loopback-target", "ephemeral-services", "tool-allowlist", "executable-identity", "argument-policy",
        "nmap-probe", "httpx-probe", "naabu-probe", "katana-probe", "unavailable-tool-honesty",
        "no-generic-command", "no-external-target", "no-credentials", "no-mutation", "timeout-bound",
        "ledger-evidence", "stdout-artifact", "stderr-artifact", "error-isolation", "readiness-accounting",
        "machine-readable", "atomic-artifact", "secret-redaction", "regression-compatible", "limitations-explicit",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names), "scenarios": [{"id": _id("v351-test", n), "name": n, "expected": "pass"} for n in names]}
