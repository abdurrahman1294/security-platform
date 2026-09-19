#!/usr/bin/env python3
"""V226-V231 Deep Operational Excellence layer.

This layer strengthens the most important operator-facing capabilities without
turning the framework into an autonomous offensive agent.

V226 Exploitation intelligence: evidence-driven exploitability assessment and
safe-proof eligibility. No arbitrary payload generation or execution.
V227 Validation: finding-aware validation plans plus guarded bounded execution
through the existing V37 proof registry when explicitly approved.
V228 Active Directory: artifact parsing plus optional read-only NetExec
enumeration. No spraying, credential dumping, lateral movement, or privilege
changes.
V229 AWS: optional read-only AWS CLI inventory, account-bound by an explicit
allowlist. No secret/key retrieval and no resource mutation.
V230 Web/API: evidence-derived coverage and prioritized validation queue.
V231 Assessment quality: cross-domain readiness, provenance, blind spots and
machine-readable operator handoff.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from modules.atomic_io import atomic_write_json
from modules.findings_io import load_findings_file
from modules.scope import load_scope, filter_in_scope
from modules.security import redact_mapping, redact_text
from modules.safe_http import request as safe_request
from modules.exploit_adapter_v33 import REGISTRY
import modules.exploit_adapters_v33  # noqa: F401 - registration side effect
import modules.exploit_adapters_v36  # noqa: F401 - registration side effect
from modules.exploit_policy_v34 import DEFAULT_POLICY, evaluate
from modules.tool_manager_v40 import ToolManager

VERSION = "231.0"
MAX_OUTPUT = 128 * 1024


def _paths(root: str | Path):
    root = Path(root)
    ev, rep = root / "evidence", root / "reports"
    ev.mkdir(parents=True, exist_ok=True)
    rep.mkdir(parents=True, exist_ok=True)
    return root, ev, rep


def _write(ev: Path, name: str, data):
    p = ev / name
    atomic_write_json(p, data)
    return p


def _read_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _finding_id(f: dict) -> str:
    supplied = str(f.get("finding_id") or f.get("id") or f.get("template-id") or "").strip()
    if supplied:
        return supplied
    host = str(f.get("matched-at") or f.get("host") or "")
    title = str((f.get("info") or {}).get("name") or f.get("title") or f.get("name") or "")
    return "F-" + hashlib.sha256((host + "|" + title).encode()).hexdigest()[:12]


def _title(f: dict) -> str:
    return str((f.get("info") or {}).get("name") or f.get("title") or f.get("name") or "Unknown finding")


def _severity(f: dict) -> str:
    return str((f.get("info") or {}).get("severity") or f.get("severity") or "unknown").lower()


def _surface(f: dict) -> str:
    return str(f.get("surface") or ("api" if "api" in json.dumps(f).lower() else "web")).lower()


def _target(f: dict) -> str:
    return str(f.get("matched-at") or f.get("endpoint") or f.get("url") or f.get("host") or "").strip()


def _kind(f: dict) -> str:
    raw = " ".join([
        str(f.get("cep_kind") or ""), str(f.get("kind") or ""), _title(f),
        " ".join(map(str, (f.get("info") or {}).get("tags", []) if isinstance(f.get("info"), dict) else [])),
    ]).lower()
    rules = [
        ("sqli", ("sql injection", "sqli", "sql-injection")),
        ("reflected_xss", ("reflected xss", "xss", "cross-site scripting")),
        ("open_redirect", ("open redirect", "url redirect")),
        ("ssrf", ("ssrf", "server-side request forgery")),
        ("lfi", ("lfi", "local file inclusion", "path traversal")),
        ("rce", ("rce", "remote code execution", "command injection")),
        ("auth-bypass", ("authentication bypass", "auth bypass")),
    ]
    for kind, needles in rules:
        if any(n in raw for n in needles):
            return kind
    return str(f.get("kind") or "unknown").lower()


def _load_all_findings(root: Path) -> list[dict]:
    paths = [
        root / "evidence" / "normalized-findings.json",
        root / "vulns" / "findings.json",
        root / "vulns" / "authenticated-findings.json",
        root / "api" / "api-findings.json",
        root / "servers" / "server-findings.json",
        root / "internal" / "internal-findings.json",
    ]
    rows, seen = [], set()
    for p in paths:
        for f in load_findings_file(p):
            if not isinstance(f, dict):
                continue
            key = _finding_id(f) + "|" + _target(f) + "|" + _title(f)
            if key not in seen:
                seen.add(key)
                rows.append(f)
    return rows


# ---------------- V226: exploitation intelligence ----------------
def v226_exploitation(root: str | Path):
    root, ev, rep = _paths(root)
    findings = _load_all_findings(root)
    rows = []
    for f in findings:
        choices = REGISTRY.select({**f, "kind": _kind(f), "surface": _surface(f)})
        adapter = choices[0] if choices else None
        sev = _severity(f)
        score = {"critical": 100, "high": 80, "medium": 55, "low": 30}.get(sev, 10)
        evidence = 0
        if _target(f): evidence += 25
        if _title(f) != "Unknown finding": evidence += 20
        if f.get("matched-at") or f.get("url") or f.get("endpoint"): evidence += 20
        if (f.get("info") or {}).get("description"): evidence += 15
        if (f.get("info") or {}).get("reference"): evidence += 10
        confidence = min(100, evidence)
        rows.append({
            "finding_id": _finding_id(f), "title": _title(f), "kind": _kind(f),
            "surface": _surface(f), "severity": sev, "target": _target(f),
            "exploitability_score": score, "evidence_score": confidence,
            "safe_adapter": adapter.adapter_id if adapter else None,
            "proof_eligible": bool(adapter and not adapter.destructive and not adapter.lab_only),
            "decision": "READY_FOR_OPERATOR_REVIEW" if adapter else "NO_SAFE_ADAPTER",
            "required_evidence": ["exact target", "finding provenance", "scope confirmation", "minimal proof observation"],
            "forbidden": ["arbitrary commands", "credential access", "persistence", "lateral movement", "exfiltration", "destructive actions"],
        })
    data = {"schema_version": "226.0", "generated": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(rows), "rows": rows, "human_approval_required": True}
    p = _write(ev, "exploitation-intelligence-v226.json", data)
    rep.joinpath("exploitation-intelligence-v226.md").write_text(
        "# Exploitation Intelligence V226\n\n" +
        "This is evidence-driven proof planning. It does not generate arbitrary exploit payloads.\n\n" +
        "\n".join(f"- `{r['finding_id']}` — **{r['severity']}** — {r['title']} — adapter: `{r['safe_adapter'] or 'none'}` — `{r['decision']}`" for r in rows) + "\n",
        encoding="utf-8")
    return p


# ---------------- V227: validation ----------------
def v227_validation_plan(root: str | Path):
    root, ev, rep = _paths(root)
    intel = _read_json(ev / "exploitation-intelligence-v226.json", {})
    rows = []
    for r in intel.get("rows", []):
        rows.append({
            "validation_id": "VAL-" + uuid.uuid4().hex[:10].upper(),
            "finding_id": r["finding_id"], "target": r["target"],
            "adapter": r["safe_adapter"], "scope_required": True,
            "operator_approval_required": True, "request_budget": DEFAULT_POLICY.max_requests,
            "body_budget": DEFAULT_POLICY.max_body_bytes,
            "state_change": False, "redirect_following": False,
            "credential_access": False, "result_states": ["confirmed", "inconclusive", "blocked", "error"],
            "preconditions": ["finding exists", "non-empty allowlist", "target is in scope", "adapter is registered", "explicit approval"],
        })
    data = {"schema_version": "227.0", "generated": datetime.now(timezone.utc).isoformat(),
            "validation_count": len(rows), "validations": rows, "execution": "operator-triggered only"}
    p = _write(ev, "validation-excellence-v227.json", data)
    rep.joinpath("validation-excellence-v227.md").write_text(
        "# Validation Excellence V227\n\n" + "\n".join(
            f"- `{x['validation_id']}` finding `{x['finding_id']}` → `{x['adapter'] or 'manual-review'}`" for x in rows) + "\n",
        encoding="utf-8")
    return p


def v227_execute(root: str | Path, finding_id: str, scope_file: str, approved: bool = False, lab_mode: bool = False):
    """Execute one already-registered safe proof adapter through V37."""
    if not approved:
        raise PermissionError("Explicit operator approval is required")
    root, ev, _ = _paths(root)
    allowed = load_scope(scope_file)
    if not allowed:
        raise PermissionError("Missing/empty scope allowlist")
    from modules.proof_execution_v37 import execute
    result = execute(root, finding_id, scope_file, approved=True, lab_mode=lab_mode)
    # Append a sanitized handoff record so V227 is traceable without duplicating
    # raw observation content.
    handoff = {"schema_version": "227.1", "finding_id": finding_id,
               "adapter_id": result.get("adapter_id"), "result": result.get("result"),
               "approved": True, "lab_mode": bool(lab_mode),
               "scope_entries": len(allowed), "timestamp": datetime.now(timezone.utc).isoformat()}
    p = ev / "validation-excellence-executions-v227.json"
    rows = _read_json(p, [])
    if not isinstance(rows, list): rows = []
    rows.append(redact_mapping(handoff)); atomic_write_json(p, rows)
    return result


# ---------------- V228: AD read-only assessment ----------------
@dataclass(frozen=True)
class ADCommand:
    id: str
    args: tuple[str, ...]
    purpose: str

AD_COMMANDS = (
    ADCommand("smb-baseline", ("smb", "{target}"), "SMB reachability and protocol baseline"),
    ADCommand("users", ("smb", "{target}", "--users"), "Read-only user enumeration"),
    ADCommand("groups", ("smb", "{target}", "--groups"), "Read-only group enumeration"),
    ADCommand("password-policy", ("smb", "{target}", "--pass-pol"), "Password-policy review"),
    ADCommand("shares", ("smb", "{target}", "--shares"), "Share enumeration"),
)


def _ad_target_in_scope(target: str, scope_file: str) -> bool:
    allowed = load_scope(scope_file)
    return bool(allowed and filter_in_scope([target], allowed=allowed))


def _run_nxc(root: Path, args: list[str], timeout: int = 60):
    try:
        proc = ToolManager(root).run("nxc", ["nxc", *args], timeout=timeout)
        out = redact_text((proc.stdout or "")[:MAX_OUTPUT])
        err = redact_text((proc.stderr or "")[:MAX_OUTPUT])
        return {"status": "completed" if proc.returncode == 0 else "failed", "returncode": proc.returncode,
                "stdout": out, "stderr": err, "stdout_sha256": hashlib.sha256(out.encode()).hexdigest()}
    except FileNotFoundError:
        return {"status": "skipped", "reason": "nxc-not-installed"}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}


def v228_ad(root: str | Path, target: str = "", scope_file: str = "", approved: bool = False, execute: bool = False):
    root, ev, rep = _paths(root)
    plan = {"schema_version": "228.0", "target": target, "commands": [asdict(x) for x in AD_COMMANDS],
            "read_only": True, "operator_approval_required": True,
            "forbidden": ["password spraying", "credential dumping", "Kerberoasting", "AS-REP roasting", "lateral movement", "privilege changes", "persistence"]}
    results = []
    if execute:
        if not approved:
            raise PermissionError("AD execution requires explicit operator approval")
        if not scope_file or not _ad_target_in_scope(target, scope_file):
            raise PermissionError("AD target is not in a valid authorized scope")
        user = os.getenv("NXC_USER", "").strip()
        password = os.getenv("NXC_PASSWORD", "")
        if not user or not password:
            raise PermissionError("Set NXC_USER and NXC_PASSWORD for authenticated read-only AD enumeration")
        domain = os.getenv("NXC_DOMAIN", "").strip()
        import tempfile
        user_fd, user_name = tempfile.mkstemp(prefix="nxc-user-", suffix=".txt", dir=ev)
        pass_fd, pass_name = tempfile.mkstemp(prefix="nxc-pass-", suffix=".txt", dir=ev)
        user_file, pass_file = Path(user_name), Path(pass_name)
        user_file.chmod(0o600); pass_file.chmod(0o600)
        try:
            with open(user_fd, "w", encoding="utf-8", closefd=True) as fh: fh.write(user + "\n")
            with open(pass_fd, "w", encoding="utf-8", closefd=True) as fh: fh.write(password + "\n")
            for c in AD_COMMANDS[1:]:
                args = [a.format(target=target) for a in c.args]
                auth = ["-u", str(user_file), "-p", str(pass_file)]
                if domain:
                    auth += ["-d", domain]
                result = _run_nxc(root, auth + args)
                result["command_id"] = c.id; result["purpose"] = c.purpose
                result["credential_source"] = "temporary-files"
                results.append(result)
        finally:
            for secret_file in (user_file, pass_file):
                try: secret_file.unlink(missing_ok=True)
                except OSError: pass
    data = {**plan, "executed": bool(execute), "results": results, "generated": datetime.now(timezone.utc).isoformat()}
    p = _write(ev, "ad-assessment-v228.json", redact_mapping(data))
    rep.joinpath("ad-assessment-v228.md").write_text(
        "# Active Directory Assessment V228\n\nRead-only enumeration and evidence planning. No credential dumping, spraying, lateral movement or privilege changes.\n\n" +
        "\n".join(f"- `{c.id}` — {c.purpose}" for c in AD_COMMANDS) + "\n",
        encoding="utf-8")
    return p


# ---------------- V229: AWS read-only assessment ----------------
AWS_COMMANDS = (
    ("caller-identity", ("sts", "get-caller-identity"), "Verify the active AWS principal/account"),
    ("account-summary", ("iam", "get-account-summary"), "Read-only IAM account posture"),
    ("users", ("iam", "list-users"), "Inventory IAM users"),
    ("roles", ("iam", "list-roles"), "Inventory IAM roles"),
    ("buckets", ("s3api", "list-buckets"), "Inventory S3 buckets"),
    ("security-groups", ("ec2", "describe-security-groups"), "Review EC2 security-group exposure"),
)


def _aws_allowed(account_id: str) -> bool:
    allowed = {x.strip() for x in os.getenv("AWS_ALLOWED_ACCOUNT_IDS", "").split(",") if x.strip()}
    return bool(account_id and allowed and account_id in allowed)


def _run_aws(args: tuple[str, ...], timeout: int = 60, root: Path | None = None):
    """Run only fixed read-only AWS calls through the shared tool boundary."""
    root = root or Path(".")
    try:
        proc = ToolManager(root).run("aws", ["aws", *args, "--output", "json"], timeout=timeout)
        out = redact_text((proc.stdout or "")[:MAX_OUTPUT])
        err = redact_text((proc.stderr or "")[:MAX_OUTPUT])
        return {"status": "completed" if proc.returncode == 0 else "failed", "returncode": proc.returncode,
                "output": out, "stderr": err, "output_sha256": hashlib.sha256(out.encode()).hexdigest()}
    except FileNotFoundError:
        return {"status": "skipped", "reason": "aws-cli-not-installed"}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}


def v229_aws(root: str | Path, account_id: str = "", approved: bool = False, execute: bool = False):
    root, ev, rep = _paths(root)
    plan = {"schema_version": "229.0", "account_id": account_id, "commands": [
        {"id": i, "purpose": p, "args": list(a)} for i, a, p in AWS_COMMANDS
    ], "read_only": True, "secrets_retrieved": False,
            "mutations": False, "operator_approval_required": True,
            "account_allowlist_required": True}
    results = []
    if execute:
        if not approved:
            raise PermissionError("AWS execution requires explicit operator approval")
        if not _aws_allowed(account_id):
            raise PermissionError("AWS account is not present in AWS_ALLOWED_ACCOUNT_IDS")
        # Confirm identity first, then run only fixed read-only calls.
        identity = _run_aws(AWS_COMMANDS[0][1], root=root)
        identity_doc = {}
        try: identity_doc = json.loads(identity.get("output", "{}")) if identity.get("status") == "completed" else {}
        except json.JSONDecodeError: identity_doc = {}
        actual_account = str(identity_doc.get("Account", ""))
        identity_ok = actual_account == account_id
        results.append({"id": "caller-identity", "status": identity.get("status"),
                        "account_match": identity_ok, "output_sha256": identity.get("output_sha256"), "stderr": identity.get("stderr", "")})
        if not identity_ok:
            results.append({"id":"inventory-blocked","reason":"caller-account-mismatch"})
        else:
            for ident, args, purpose in AWS_COMMANDS[1:]:
                r = _run_aws(args, root=root)
                results.append({"id": ident, "purpose": purpose, **r})
    data = {**plan, "executed": bool(execute), "results": redact_mapping(results),
            "generated": datetime.now(timezone.utc).isoformat()}
    p = _write(ev, "aws-assessment-v229.json", data)
    rep.joinpath("aws-assessment-v229.md").write_text(
        "# AWS Read-Only Assessment V229\n\nAccount-bound, read-only inventory. No IAM key material is retrieved and no cloud resources are modified.\n\n" +
        "\n".join(f"- `{i}` — {p}" for i, _, p in AWS_COMMANDS) + "\n",
        encoding="utf-8")
    return p


# ---------------- V230: Web/API coverage ----------------
def v230_web_api(root: str | Path):
    root, ev, rep = _paths(root)
    findings = _load_all_findings(root)
    endpoint_file = ev / "web-endpoints-v46.json"
    endpoints = _read_json(endpoint_file, {}).get("endpoints", []) if endpoint_file.exists() else []
    api_file = ev / "api-surface-v58.json"
    api = _read_json(api_file, {}) if api_file.exists() else {}
    checks = {
        "endpoint_inventory": bool(endpoints),
        "api_surface": bool(api),
        "finding_correlation": bool(findings),
        "authentication_review": any("auth" in json.dumps(x).lower() for x in endpoints),
        "object_authorization_review": any(re.search(r"(^|[^a-z])(id|uuid|user_id|account_id|order_id)([^a-z]|$)", json.dumps(x).lower()) for x in endpoints),
        "business_logic_review": any(k in json.dumps(item).lower() for item in endpoints for k in ["checkout", "payment", "approve", "transaction", "workflow"]),
    }
    queue=[]
    for name, covered in checks.items():
        if not covered:
            queue.append({"area": name, "priority": "high" if name in {"endpoint_inventory", "api_surface", "authentication_review"} else "medium", "status": "blind-spot"})
    data={"schema_version":"230.0","generated":datetime.now(timezone.utc).isoformat(),"checks":checks,
          "blind_spots":queue,"evidence_backed_only":True,"active_testing":False}
    p=_write(ev,"web-api-excellence-v230.json",data)
    rep.joinpath("web-api-excellence-v230.md").write_text("# Web/API Excellence V230\n\n"+"\n".join(f"- `{k}` — {'covered' if v else 'blind spot'}" for k,v in checks.items())+"\n",encoding="utf-8")
    return p


# ---------------- V231: final quality/handoff ----------------
def v231_quality(root: str | Path, target: str = ""):
    root, ev, rep = _paths(root)
    required=["exploitation-intelligence-v226.json","validation-excellence-v227.json","ad-assessment-v228.json","aws-assessment-v229.json","web-api-excellence-v230.json"]
    checks={x:(ev/x).exists() for x in required}
    findings=_load_all_findings(root)
    data={"schema_version":"231.0","target":target,"generated":datetime.now(timezone.utc).isoformat(),
          "checks":checks,"finding_count":len(findings),
          "decision":"PASS" if all(checks.values()) else "NOT_READY",
          "operator_handoff":["review scope","review findings","review proof eligibility","review AD/cloud authorization","review blind spots","approve any validation separately"],
          "safety": {"arbitrary_commands":False,"credential_dumping":False,"persistence":False,"lateral_movement":False,"exfiltration":False,"destructive_actions":False}}
    p=_write(ev,"deep-quality-gate-v231.json",data)
    rep.joinpath("deep-quality-gate-v231.md").write_text("# Deep Quality Gate V231\n\nDecision: **%s**\n\nHuman review remains mandatory.\n"%data["decision"],encoding="utf-8")
    return p


def build_all(root: str | Path, target: str = ""):
    v226_exploitation(root); v227_validation_plan(root); v228_ad(root,target); v229_aws(root); v230_web_api(root); return v231_quality(root,target)
