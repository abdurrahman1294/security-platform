"""Read-only multi-cloud and Kubernetes assessment helpers.

This module deliberately accepts offline exports and uses only read-oriented CLI
commands when a live provider CLI is explicitly available. It never mutates
cloud resources, changes IAM, executes workloads, or accesses secret values.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

VERSION = "3.2"

PROVIDERS = {
    "azure": {
        "tool": "az",
        "commands": [
            ["az", "account", "show", "--output", "json"],
            ["az", "group", "list", "--output", "json"],
            ["az", "resource", "list", "--output", "json"],
            ["az", "role", "assignment", "list", "--all", "--output", "json"],
            ["az", "network", "nsg", "list", "--output", "json"],
            ["az", "storage", "account", "list", "--output", "json"],
        ],
    },
    "gcp": {
        "tool": "gcloud",
        "commands": [
            ["gcloud", "config", "get-value", "project"],
            ["gcloud", "projects", "list", "--format", "json"],
            ["gcloud", "iam", "service-accounts", "list", "--format", "json"],
            ["gcloud", "projects", "get-iam-policy", "--format", "json"],
            ["gcloud", "compute", "networks", "list", "--format", "json"],
            ["gcloud", "compute", "firewall-rules", "list", "--format", "json"],
            ["gcloud", "storage", "buckets", "list", "--format", "json"],
        ],
    },
    "kubernetes": {
        "tool": "kubectl",
        "commands": [
            ["kubectl", "cluster-info"],
            ["kubectl", "get", "nodes", "-o", "json"],
            ["kubectl", "get", "namespaces", "-o", "json"],
            ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
            ["kubectl", "get", "roles", "--all-namespaces", "-o", "json"],
            ["kubectl", "get", "rolebindings", "--all-namespaces", "-o", "json"],
            ["kubectl", "get", "clusterroles", "-o", "json"],
            ["kubectl", "get", "clusterrolebindings", "-o", "json"],
            ["kubectl", "get", "networkpolicies", "--all-namespaces", "-o", "json"],
        ],
    },
}


def _summarize(provider: str, payloads: list[dict[str, Any]]) -> dict[str, Any]:
    findings = []
    text = json.dumps(payloads).lower()
    checks = {
        "public_exposure_review": "public" in text or "internet" in text,
        "identity_review": any(k in text for k in ("iam", "role", "principal", "serviceaccount")),
        "network_review": any(k in text for k in ("network", "firewall", "securitygroup", "nsg", "networkpolicy")),
        "storage_review": any(k in text for k in ("bucket", "storage")),
    }
    if provider == "kubernetes":
        checks.update({
            "rbac_review": any(k in text for k in ("rolebinding", "clusterrole", "clusterrolebinding")),
            "networkpolicy_review": "networkpolic" in text,
        })
    for name, present in checks.items():
        findings.append({"check": name, "status": "observed" if present else "not-observed", "confidence": "low" if present else "none"})
    return {"provider": provider, "checks": findings, "read_only": True}


def _load_export(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("export must be an existing file <= 10 MiB")
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON export required: {exc.msg}") from exc
    if isinstance(value, list):
        return [{"source": str(path), "data": value}]
    if isinstance(value, dict):
        return [{"source": str(path), "data": value}]
    raise ValueError("export must contain a JSON object or array")


def assess_export(root: str | Path, provider: str, export: str | Path) -> dict[str, Any]:
    provider = provider.lower().strip()
    if provider not in PROVIDERS:
        raise ValueError("provider must be azure, gcp, or kubernetes")
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    payloads = _load_export(Path(export))
    data = {"schema_version": VERSION, "mode": "offline-export", "provider": provider,
            "source": str(export), "payload_count": len(payloads), "analysis": _summarize(provider, payloads),
            "limitations": ["Offline exports cannot prove exploitability.", "Secret values are not requested or collected.", "Human review is required for context and impact."]}
    atomic_write_json(ev / f"cloud-{provider}-assessment-v32.json", data)
    return data


def tool_catalog() -> dict[str, Any]:
    return {k: {"tool": v["tool"], "read_only_commands": v["commands"]} for k, v in PROVIDERS.items()}


def assess_live(root: str | Path, provider: str) -> dict[str, Any]:
    """Run the provider's fixed read-only catalog through ToolManager."""
    from security_platform.core.tools import run
    provider = provider.lower().strip()
    if provider not in PROVIDERS:
        raise ValueError("provider must be azure, gcp, or kubernetes")
    root = Path(root); ev = root / "evidence"; ev.mkdir(parents=True, exist_ok=True)
    results = []
    for argv in PROVIDERS[provider]["commands"]:
        try:
            proc = run(root, PROVIDERS[provider]["tool"], argv, timeout=300)
            results.append({"argv": argv, "returncode": proc.returncode, "stdout": (proc.stdout or "")[:20000], "stderr": (proc.stderr or "")[:4000]})
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            results.append({"argv": argv, "status": "blocked", "error": str(exc)[:500]})
    successful = sum(1 for x in results if x.get("returncode") == 0)
    data = {"schema_version": VERSION, "mode": "live-read-only", "provider": provider,
            "status": "completed" if successful == len(results) else "partial" if successful else "blocked",
            "commands": len(results), "successful": successful, "results": results,
            "analysis": _summarize(provider, results),
            "safety": {"read_only": True, "mutations": False, "secret_values_requested": False}}
    atomic_write_json(ev / f"cloud-{provider}-live-v32.json", data)
    return data
