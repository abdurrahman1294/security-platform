#!/usr/bin/env python3
"""Policy-aware ToolManager executor for the autonomous loop.

Maps high-level autonomy actions to allowlisted tool invocations.
Every network-facing action re-checks scope before execution.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from modules.scope import is_valid_target_format, load_scope
from modules.security import in_scope
from modules.tool_manager_v40 import ToolManager, TOOLS


class ToolExecutorError(RuntimeError):
    pass


class HardenedToolExecutor:
    """Execute R1 discovery actions through ToolManager only."""

    def __init__(self, outdir: str | Path, scope_file: str | Path | None = None):
        self.root = Path(outdir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.scope_file = Path(scope_file) if scope_file else None
        self.allowed = load_scope(str(self.scope_file)) if self.scope_file and self.scope_file.exists() else []
        if not self.allowed:
            self.allowed = []
        self.tm = ToolManager(self.root)

    def _ensure_scope(self, target: str) -> None:
        if not is_valid_target_format(target):
            raise ToolExecutorError(f"invalid target format: {target}")
        if not self.allowed:
            raise ToolExecutorError("authoritative scope is missing or empty")
        if not in_scope(target, self.allowed):
            raise ToolExecutorError(f"target out of scope: {target}")

    def _run(self, tool_id: str, argv: list[str], timeout: int = 600) -> dict[str, Any]:
        if tool_id not in TOOLS:
            raise ToolExecutorError(f"tool not allowlisted: {tool_id}")
        # ToolManager expects argv[0] style list validated by hardening layer
        full = [tool_id, *argv]
        try:
            proc = self.tm.run(tool_id, full, timeout=timeout)
        except FileNotFoundError as exc:
            return {"status": "unavailable", "tool": tool_id, "error": str(exc)}
        except ValueError as exc:
            return {"status": "rejected", "tool": tool_id, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": tool_id, "error": str(exc)}
        return {
            "status": "completed" if getattr(proc, "returncode", 1) == 0 else "failed",
            "tool": tool_id,
            "returncode": getattr(proc, "returncode", None),
            "stdout_bytes": len((getattr(proc, "stdout", None) or "").encode()),
            "stderr_bytes": len((getattr(proc, "stderr", None) or "").encode()),
        }

    def _host_only(self, target: str) -> str:
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            t = t.split("://", 1)[1]
        return t.split("/", 1)[0].split(":", 1)[0]

    def execute(self, action: str, target: str, outdir: Path) -> dict[str, Any]:
        action = (action or "").strip().lower()
        target = (target or "").strip()
        out = Path(outdir)
        recon = out / "recon"
        ports = out / "ports"
        web = out / "web"
        vulns = out / "vulns"
        for d in (recon, ports, web, vulns, out / "evidence"):
            d.mkdir(parents=True, exist_ok=True)

        # Local/non-network actions: no tool call
        if action in {
            "normalize_assets", "dedupe_evidence", "coverage_analysis", "draft_report",
            "prioritize_tasks", "load_state", "preflight", "tool_inventory",
        }:
            artifact = out / "evidence" / f"auto-{action}.json"
            artifact.write_text(
                f'{{"action":"{action}","target":{target!r},"status":"ok"}}\n',
                encoding="utf-8",
            )
            return {"status": "ok", "action": action, "artifact": str(artifact)}

        # All remaining mapped actions are active → scope required
        self._ensure_scope(target)
        host = self._host_only(target)

        if action == "subdomain_enum":
            out_file = recon / "subfinder.txt"
            result = self._run("subfinder", ["-d", host, "-silent", "-o", str(out_file)], timeout=600)
            # Optional secondary enumerator; stdout captured from ToolManager process if available.
            try:
                full = ["assetfinder", "--subs-only", host]
                proc = self.tm.run("assetfinder", full, timeout=300)
                af = recon / "assetfinder.txt"
                af.write_text(getattr(proc, "stdout", "") or "", encoding="utf-8")
            except Exception:
                pass
            subs = set()
            for f in recon.glob("*.txt"):
                for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    v = line.strip().lstrip("*.")
                    if v:
                        subs.add(v)
            merged = recon / "subdomains.txt"
            merged.write_text("\n".join(sorted(subs)) + ("\n" if subs else ""), encoding="utf-8")
            result["artifact"] = str(merged)
            return result

        if action == "http_probe":
            # Prefer list file if subdomains exist
            subs = recon / "subdomains.txt"
            live = recon / "live-hosts.txt"
            if not subs.exists() or subs.stat().st_size == 0:
                # probe the single target URL/host
                url = target if target.startswith("http") else f"https://{host}"
                result = self._run(
                    "httpx",
                    ["-u", url, "-silent", "-status-code", "-title", "-tech-detect", "-o", str(live)],
                    timeout=600,
                )
            else:
                result = self._run(
                    "httpx",
                    ["-l", str(subs), "-silent", "-status-code", "-title", "-tech-detect", "-o", str(live)],
                    timeout=900,
                )
            result["artifact"] = str(live)
            return result

        if action == "port_scan":
            out_file = ports / "naabu.txt"
            result = self._run(
                "naabu",
                ["-host", host, "-rate", "1000", "-top-ports", "100", "-silent", "-o", str(out_file)],
                timeout=900,
            )
            result["artifact"] = str(out_file)
            return result

        if action == "service_enum":
            out_base = ports / "nmap"
            # Prefer naabu list when present
            naabu = ports / "naabu.txt"
            if naabu.exists() and naabu.stat().st_size > 0:
                # Naabu emits host:port; nmap -iL expects hosts only. Normalize
                # and re-apply scope before handing the artifact across.
                nmap_targets = ports / "nmap-targets.txt"
                hosts = set()
                for line in naabu.read_text(encoding="utf-8", errors="ignore").splitlines():
                    value = line.strip()
                    if not value: continue
                    if value.startswith("[") and "]:" in value:
                        host = value.rsplit(":", 1)[0][1:]
                    elif value.count(":") == 1:
                        host = value.rsplit(":", 1)[0]
                    else:
                        host = value
                    if in_scope(host, self.allowed): hosts.add(host)
                if not hosts:
                    return {"status":"blocked","action":action,"detail":"no in-scope nmap targets"}
                nmap_targets.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")
                argv = ["-sV", "-Pn", "-T4", "--open", "-iL", str(nmap_targets), "-oA", str(out_base)]
            else:
                argv = ["-sV", "-Pn", "-T4", "--top-ports", "100", "--open", "-oA", str(out_base), host]
            result = self._run("nmap", argv, timeout=1200)
            result["artifact"] = str(out_base)
            return result

        if action == "web_crawl":
            urls = web / "urls.txt"
            if not urls.exists():
                seed = target if target.startswith("http") else f"https://{host}"
                urls.write_text(seed + "\n", encoding="utf-8")
            out_file = web / "katana.txt"
            result = self._run("katana", ["-list", str(urls), "-d", "2", "-silent", "-o", str(out_file)], timeout=900)
            result["artifact"] = str(out_file)
            return result

        if action == "vuln_candidate_scan":
            live = recon / "live-hosts.txt"
            urls = web / "urls.txt"
            target_file = urls if urls.exists() and urls.stat().st_size > 0 else live
            out_file = vulns / "findings.txt"
            json_out = vulns / "findings.json"
            if target_file.exists() and target_file.stat().st_size > 0:
                argv = [
                    "-l", str(target_file),
                    "-t", "technologies/",
                    "-t", "exposures/",
                    "-severity", "medium,high,critical",
                    "-rate-limit", "100",
                    "-silent",
                    "-o", str(out_file),
                    "-json-export", str(json_out),
                ]
            else:
                url = target if target.startswith("http") else f"https://{host}"
                argv = [
                    "-u", url,
                    "-t", "technologies/",
                    "-t", "exposures/",
                    "-severity", "medium,high,critical",
                    "-rate-limit", "100",
                    "-silent",
                    "-o", str(out_file),
                    "-json-export", str(json_out),
                ]
            result = self._run("nuclei", argv, timeout=1200)
            result["artifact"] = str(out_file)
            return result

        if action in {"api_discovery", "cloud_read_inventory", "ad_read_enum"}:
            # Reserved: require dedicated modules/flags; do not invent broad scans.
            return {
                "status": "not_implemented_in_auto_executor",
                "action": action,
                "detail": "Use dedicated engine phases/modules for this action",
            }

        if action in {
            "controlled_privilege_escalation_test",
            "controlled_persistence_test",
            "controlled_lateral_movement_test",
            "controlled_credential_access_test",
            "controlled_objective_access_test",
            "controlled_attack_chain_test",
        }:
            # R4 governance is supported, but no built-in dangerous payload is
            # shipped. An engagement-specific adapter must be registered by the
            # operator and independently enforce the approved ROE.
            return {
                "status": "adapter_required",
                "action": action,
                "detail": "R4 is ROE/approval controlled; no unrestricted high-impact payload is built in",
            }

        if action in {"header_verification", "endpoint_recheck", "tls_observation", "reflection_check"}:
            # Safe R2 observations are implemented directly here so the
            # autonomous executor does not depend on a version-specific module.
            from modules.safe_http import request as safe_request
            from modules.atomic_io import atomic_write_json
            import hashlib
            url = target if target.startswith(("http://", "https://")) else f"https://{host}"
            if action == "tls_observation":
                from modules.controlled_validation import _tls_observation
                evidence = _tls_observation(url)
            else:
                obs = safe_request(url, method="GET", headers={"User-Agent":"SecurityPlatform-Autonomy/2.0"}, timeout=10, max_body=65536)
                evidence = {"url":url,"status":obs.get("status"),"ok":obs.get("ok"),"headers":obs.get("headers",{}),"body_sha256":hashlib.sha256((obs.get("body") or "").encode()).hexdigest(),"redirects_followed":False}
                if obs.get("location"): evidence["location"] = obs["location"]
            artifact=out/"evidence"/f"auto-{action}.json"
            atomic_write_json(artifact,{"action":action,"target":target,"evidence":evidence})
            return {"status":"completed" if evidence.get("ok",True) else "failed","action":action,"artifact":str(artifact),"evidence":evidence}

        # R2/R3 and unknown are not executed here
        return {
            "status": "unsupported_by_tool_executor",
            "action": action,
            "detail": "Action is not mapped to an allowlisted tool invocation",
        }


def build_executor(outdir: str | Path, scope_file: str | Path | None = None):
    ex = HardenedToolExecutor(outdir, scope_file=scope_file)

    def _call(action: str, target: str, out: Path) -> dict[str, Any]:
        return ex.execute(action, target, out)

    return _call
