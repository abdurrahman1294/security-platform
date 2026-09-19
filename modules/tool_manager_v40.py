#!/usr/bin/env python3
"""V40 allowlisted tool execution manager with durable command ledger.

Only the tools listed in TOOLS can be executed, and only after
validate_argv() has approved the argument list -- this manager has no
path to run an arbitrary shell command. Every invocation (success,
failure, or timeout) is recorded to an on-disk ledger for auditability.
"""
from __future__ import annotations
import subprocess, uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from .tool_adapter_hardening_v162 import executable_path, sanitized_environment, validate_argv, verify_executable_identity
from .atomic_io import atomic_write_json, load_json
from .security import redact_mapping


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    executable: str
    description: str
    default_timeout: int = 600


TOOLS = {
    "subfinder": ToolSpec("subfinder", "subfinder", "Subdomain discovery"),
    "assetfinder": ToolSpec("assetfinder", "assetfinder", "Asset discovery"),
    "httpx": ToolSpec("httpx", "httpx", "HTTP probing and fingerprinting"),
    "naabu": ToolSpec("naabu", "naabu", "Port discovery"),
    "nmap": ToolSpec("nmap", "nmap", "Service enumeration"),
    "katana": ToolSpec("katana", "katana", "Web crawling"),
    "nuclei": ToolSpec("nuclei", "nuclei", "Vulnerability discovery"),
    "nxc": ToolSpec("nxc", "nxc", "Read-only Active Directory/SMB enumeration"),
    "aws": ToolSpec("aws", "aws", "Allowlisted read-only AWS inventory"),
    "az": ToolSpec("az", "az", "Allowlisted read-only Azure inventory"),
    "gcloud": ToolSpec("gcloud", "gcloud", "Allowlisted read-only GCP inventory"),
    "kubectl": ToolSpec("kubectl", "kubectl", "Allowlisted read-only Kubernetes inventory"),
}


class ToolManager:
    def __init__(self, root: Union[str, Path]):
        self.root = Path(root)
        self.path = self.root / "evidence" / "tool-execution-ledger-v40.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rows = self._load()

    def _load(self) -> list:
        rows = load_json(self.path, [])
        return rows if isinstance(rows, list) else []

    def _save(self) -> None:
        # Atomic write: a plain write_text() could leave a truncated,
        # invalid ledger behind if the process died mid-write, which then
        # made the next run's _load() silently discard the entire
        # execution history and start over from an empty ledger.
        atomic_write_json(self.path, self.rows)

    def run(self, tool_id: str, argv: List[str], *, timeout: Optional[int] = None, cwd=None):
        if tool_id not in TOOLS:
            raise ValueError(f"Tool is not allowlisted: {tool_id}")
        ok, reason = validate_argv(tool_id, argv, root=self.root)
        if not ok:
            raise ValueError(f"Invalid tool arguments: {reason}")
        if timeout is not None and (int(timeout) < 1 or int(timeout) > 3600):
            raise ValueError("timeout must be between 1 and 3600 seconds")
        if cwd is not None:
            try:
                Path(cwd).expanduser().resolve().relative_to(self.root.resolve())
            except (OSError, ValueError):
                raise ValueError("cwd must remain inside the engagement output root")
        resolved = executable_path(tool_id)
        if resolved is None:
            raise FileNotFoundError(f"Tool is not installed: {tool_id}")

        identity_ok, identity_reason = verify_executable_identity(tool_id, resolved)
        if not identity_ok:
            raise RuntimeError(f"Tool identity check failed: {identity_reason}")

        started = datetime.now(timezone.utc).isoformat()
        eid = f"TEX-{uuid.uuid4().hex[:10]}"
        try:
            proc = subprocess.run(
                [resolved, *[str(x) for x in argv[1:]]],
                shell=False, capture_output=True, text=True,
                timeout=timeout or TOOLS[tool_id].default_timeout,
                cwd=cwd, env=sanitized_environment(tool_id),
            )
            row = {
                "execution_id": eid, "tool_id": tool_id, "argv": redact_mapping(list(map(str, argv))),
                "returncode": proc.returncode,
                "stdout_bytes": len(proc.stdout.encode()), "stderr_bytes": len(proc.stderr.encode()),
                "started": started, "finished": datetime.now(timezone.utc).isoformat(),
                "status": "completed" if proc.returncode == 0 else "failed",
            }
            self.rows.append(row)
            self._save()
            return proc
        except subprocess.TimeoutExpired:
            row = {
                "execution_id": eid, "tool_id": tool_id, "argv": redact_mapping(list(map(str, argv))),
                "returncode": None, "started": started,
                "finished": datetime.now(timezone.utc).isoformat(), "status": "timeout",
            }
            self.rows.append(row)
            self._save()
            raise
        except OSError as exc:
            # e.g. the resolved binary disappeared, lost its executable
            # bit, or the platform rejected the exec call between
            # executable_path() and subprocess.run(). Previously
            # unhandled here, so it crashed the whole assessment run
            # instead of recording one failed step and letting the rest
            # of the pipeline continue.
            row = {
                "execution_id": eid, "tool_id": tool_id, "argv": redact_mapping(list(map(str, argv))),
                "returncode": None, "started": started,
                "finished": datetime.now(timezone.utc).isoformat(),
                "status": "error", "error": str(exc),
            }
            self.rows.append(row)
            self._save()
            raise


def list_tools():
    return [{"tool_id": k, "executable": v.executable, "description": v.description, "default_timeout": v.default_timeout} for k, v in TOOLS.items()]
