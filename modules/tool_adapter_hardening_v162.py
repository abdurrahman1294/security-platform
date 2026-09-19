from __future__ import annotations

"""Security boundary for external assessment-tool execution.

This module intentionally contains policy, executable identity checks, argument
validation and environment minimisation.  ToolManager is the only normal caller.
"""

import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

EXECUTABLES = {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "httpx": "httpx",
    "naabu": "naabu",
    "nmap": "nmap",
    "katana": "katana",
    "nuclei": "nuclei",
    "nxc": "nxc",
    "aws": "aws",
    "az": "az",
    "gcloud": "gcloud",
    "kubectl": "kubectl",
}

# Only these environment variables cross the security boundary by default.
BASE_ENV = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"}
TOOL_ENV = {
    "subfinder": {"SUBFINDER_CONFIG"},
    "assetfinder": set(),
    "httpx": {"HTTPX_CONFIG"},
    "naabu": {"NAABU_CONFIG"},
    "nmap": {"NMAPDIR"},
    "katana": {"KATANA_CONFIG"},
    "nuclei": {"NUCLEI_CONFIG", "NUCLEI_TEMPLATES_HOME"},
    "nxc": {"NXC_CONFIG"},
    "aws": {"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_CA_BUNDLE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_ENDPOINT_URL"},
    "az": {"AZURE_CONFIG_DIR", "AZURE_CORE_OUTPUT", "AZURE_DEFAULTS_GROUP", "AZURE_DEFAULTS_LOCATION", "AZURE_SUBSCRIPTION_ID"},
    "gcloud": {"CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT", "CLOUDSDK_CORE_ACCOUNT"},
    "kubectl": {"KUBECONFIG"},
}

# Deliberately narrow flags: unknown flags are rejected rather than assumed safe.
FLAGS = {
    "subfinder": {"-d", "-all", "-silent", "-o", "-dL"},
    "assetfinder": {"--subs-only"},
    "httpx": {"-l", "-u", "-silent", "-status-code", "-title", "-tech-detect", "-json", "-screenshot", "-screenshot-timeout", "-o"},
    "naabu": {"-host", "-list", "-rate", "-top-ports", "-silent", "-o"},
    "nmap": {"-sV", "-sC", "-Pn", "-T3", "-T4", "--top-ports", "--open", "-iL", "-oA", "-oN", "-p"},
    "katana": {"-list", "-u", "-d", "-silent", "-jc", "-o"},
    "nuclei": {"-l", "-u", "-t", "-tags", "-severity", "-rate-limit", "-c", "-silent", "-stats", "-include-rr", "-o", "-json-export", "-jsonl-export", "-H"},
    "nxc": {"smb", "-u", "-p", "-d", "--users", "--groups", "--pass-pol", "--shares"},
    "aws": {"sts", "iam", "s3api", "ec2", "lambda", "rds", "eks", "ecs", "ecr", "cloudtrail", "kms", "secretsmanager", "route53", "cloudfront", "apigateway", "apigatewayv2", "get-caller-identity", "get-account-summary", "list-users", "list-roles", "list-buckets", "describe-security-groups", "describe-instances", "describe-vpcs", "describe-subnets", "describe-route-tables", "list-functions", "describe-db-instances", "list-clusters", "describe-repositories", "describe-trails", "list-keys", "list-secrets", "list-hosted-zones", "list-distributions", "get-rest-apis", "get-apis", "--output"},
    "az": {"--output", "--all"},
    "gcloud": {"--format"},
    "kubectl": {"-o", "--all-namespaces"},
}
VALUE_FLAGS = {
    "subfinder": {"-d", "-o", "-dL"},
    "assetfinder": set(),
    "httpx": {"-l", "-u", "-screenshot-timeout", "-o"},
    "naabu": {"-host", "-list", "-rate", "-top-ports", "-o"},
    "nmap": {"--top-ports", "-iL", "-oA", "-oN", "-p"},
    "katana": {"-list", "-u", "-d", "-o"},
    "nuclei": {"-l", "-u", "-t", "-tags", "-severity", "-rate-limit", "-c", "-o", "-json-export", "-jsonl-export", "-H"},
    "nxc": {"-u", "-p", "-d"},
    "aws": {"--output"},
    "az": {"--output"},
    "gcloud": {"--format"},
    "kubectl": {"-o"},
}
# Nuclei templates are intentionally limited to the framework's known read-only
# discovery/assessment collections. Arbitrary workflow/template execution is not.
NUCLEI_TEMPLATE_PREFIXES = (
    "cves/", "vulnerabilities/", "misconfiguration/", "exposures/", "default-logins/",
    "technologies/", "network/", "network/detection/", "http/vulnerabilities/",
    "http/misconfiguration/", "http/exposures/",
)
IDENTITY_MARKERS = {
    "subfinder": ("projectdiscovery", "subfinder"),
    "assetfinder": ("assetfinder",),
    "httpx": ("projectdiscovery", "httpx is a fast and multi-purpose http toolkit"),
    "naabu": ("projectdiscovery", "naabu"),
    "nmap": ("nmap",),
    "katana": ("projectdiscovery", "katana"),
    "nuclei": ("projectdiscovery", "nuclei"),
    "nxc": ("netexec", "nxc"),
    "aws": ("aws", "command line interface"),
    "az": ("azure cli", "az command"),
    "gcloud": ("google cloud sdk", "gcloud"),
    "kubectl": ("kubectl", "kubernetes command-line tool"),
}

AZ_ALLOWED_COMMANDS = {
    ("account", "show"), ("group", "list"), ("resource", "list"),
    ("role", "assignment"), ("network", "nsg"), ("storage", "account"),
}
GCP_ALLOWED_COMMANDS = {
    ("config", "get-value"), ("projects", "list"), ("projects", "get-iam-policy"),
    ("iam", "service-accounts"), ("compute", "networks"), ("compute", "firewall-rules"),
    ("storage", "buckets"),
}
# Exact, side-effect-free diagnostics used to prove an installed tool can
# execute through ToolManager. Kept separate from operational allowlists.
HEALTH_CHECK_ARGV = {
    "subfinder": ("subfinder", "-version"),
    "assetfinder": ("assetfinder", "-h"),
    "httpx": ("httpx", "-version"),
    "naabu": ("naabu", "-version"),
    "nmap": ("nmap", "--version"),
    "katana": ("katana", "-version"),
    "nuclei": ("nuclei", "-version"),
    "nxc": ("nxc", "--version"),
    "aws": ("aws", "--version"),
    "az": ("az", "version"),
    "gcloud": ("gcloud", "version"),
    "kubectl": ("kubectl", "version", "--client"),
}


KUBECTL_ALLOWED_PREFIXES = {
    ("cluster-info",), ("get", "nodes"), ("get", "namespaces"), ("get", "pods"),
    ("get", "roles"), ("get", "rolebindings"), ("get", "clusterroles"),
    ("get", "clusterrolebindings"), ("get", "networkpolicies"),
}

AWS_ALLOWED_COMMANDS = {
    ("sts", "get-caller-identity"),
    ("iam", "get-account-summary"),
    ("iam", "list-users"),
    ("iam", "list-roles"),
    ("s3api", "list-buckets"),
    ("ec2", "describe-security-groups"),
    ("ec2", "describe-instances"),
    ("ec2", "describe-vpcs"),
    ("ec2", "describe-subnets"),
    ("ec2", "describe-route-tables"),
    ("lambda", "list-functions"),
    ("rds", "describe-db-instances"),
    ("eks", "list-clusters"),
    ("ecs", "list-clusters"),
    ("ecr", "describe-repositories"),
    ("cloudtrail", "describe-trails"),
    ("kms", "list-keys"),
    ("secretsmanager", "list-secrets"),
    ("route53", "list-hosted-zones"),
    ("cloudfront", "list-distributions"),
    ("apigateway", "get-rest-apis"),
    ("apigatewayv2", "get-apis"),
}


def executable_path(tool_id: str) -> str | None:
    exe = EXECUTABLES.get(tool_id)
    if not exe:
        raise ValueError("unknown tool")
    override = os.environ.get(f"PENTEST_{tool_id.upper()}_BIN", "").strip()
    candidate = override or shutil.which(exe)
    if not candidate:
        return None
    path = Path(candidate).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    # Refuse binaries from world/group-writable locations.  The check is
    # best-effort on platforms that do not expose POSIX mode bits.
    try:
        if path.parent.stat().st_mode & 0o022:
            return None
    except OSError:
        return None
    return str(path)


@lru_cache(maxsize=32)
def verify_executable_identity(tool_id: str, resolved: str) -> tuple[bool, str]:
    markers = IDENTITY_MARKERS.get(tool_id)
    if not markers:
        return False, "unknown-tool-identity-policy"
    try:
        p = subprocess.run([resolved, "-h"], capture_output=True, text=True, timeout=5, shell=False, env=sanitized_environment(tool_id))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"identity-check-failed:{type(exc).__name__}"
    text = ((p.stdout or "") + "\n" + (p.stderr or "")).lower()
    if any(marker in text for marker in markers):
        return True, "ok"
    return False, "executable-identity-mismatch"


def sanitized_environment(tool_id: str | None = None) -> dict[str, str]:
    allowed = set(BASE_ENV)
    if tool_id:
        allowed |= TOOL_ENV.get(tool_id, set())
    env = {k: v for k, v in os.environ.items() if k in allowed and k != "PATH"}
    # Never inherit an operator-controlled PATH into child tools.
    env["PATH"] = os.defpath or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return env


def _under_root(value: str, root: Path) -> bool:
    try:
        Path(value).expanduser().resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _looks_like_safe_target(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    if "\x00" in value or re.search(r"[;&|`$(){}<>\\\"'\n\r]", value):
        return False
    return True


def validate_argv(tool_id: str, argv, *, root: str | Path | None = None):
    exe = EXECUTABLES.get(tool_id)
    if not exe:
        return False, "unknown-tool"
    if not isinstance(argv, (list, tuple)) or not argv:
        return False, "argv-required"
    if str(argv[0]) != exe:
        return False, "executable-mismatch"
    if any("\x00" in str(x) for x in argv):
        return False, "nul-byte"
    if any(len(str(x)) > 4096 for x in argv):
        return False, "argument-too-long"

    # Exact-match, read-only diagnostics. These bypass provider command/flag
    # policy only for the single health-check invocation defined above.
    if tuple(str(x) for x in argv) == HEALTH_CHECK_ARGV.get(tool_id):
        return True, "health-check-allowlisted"
    if tool_id == "aws":
        command = tuple(str(x) for x in argv[1:3])
        if command not in AWS_ALLOWED_COMMANDS:
            return False, "aws-command-not-allowlisted"
    elif tool_id == "az":
        command = tuple(str(x) for x in argv[1:3])
        if command not in AZ_ALLOWED_COMMANDS:
            return False, "az-command-not-allowlisted"
        if tuple(str(x) for x in argv[1:3]) == ("role", "assignment") and "list" not in argv[3:]:
            return False, "az-role-assignment-list-only"
    elif tool_id == "gcloud":
        command = tuple(str(x) for x in argv[1:3])
        if command not in GCP_ALLOWED_COMMANDS:
            return False, "gcloud-command-not-allowlisted"
        if command == ("projects", "get-iam-policy") and any(x in {"--flatten", "--filter", "--update-mask"} for x in argv[3:]):
            return False, "gcloud-iam-policy-filtering-not-allowlisted"
    elif tool_id == "kubectl":
        command = tuple(str(x) for x in argv[1:3])
        if command not in KUBECTL_ALLOWED_PREFIXES and not (command == ("cluster-info", "")):
            # cluster-info is a one-token command; all other permitted forms start with get.
            if tuple(str(x) for x in argv[1:2]) != ("cluster-info",):
                return False, "kubectl-command-not-allowlisted"
        if any(x in {"apply", "create", "delete", "patch", "edit", "exec", "cp", "run", "replace", "scale", "rollout"} for x in argv[1:]):
            return False, "kubectl-mutating-command-rejected"

    allowed = FLAGS[tool_id]
    value_flags = VALUE_FLAGS[tool_id]
    i = 1
    root_path = Path(root).resolve() if root is not None else None
    while i < len(argv):
        token = str(argv[i])
        if token.startswith("-"):
            if token not in allowed:
                return False, f"flag-not-allowlisted:{token}"
            if token in value_flags:
                if i + 1 >= len(argv):
                    return False, f"missing-value:{token}"
                value = str(argv[i + 1])
                if value.startswith("-"):
                    return False, f"invalid-value:{token}"
                if token in {"-oA", "-oN", "-json-export", "-jsonl-export"} or (token == "-o" and tool_id != "kubectl"):
                    if root_path is not None and not _under_root(value, root_path):
                        return False, f"output-outside-root:{token}"
                if token in {"-l", "-list", "-iL", "-dL", "-u", "-p"} and tool_id != "nxc":
                    if root_path is not None and Path(value).exists() and not _under_root(value, root_path):
                        return False, f"input-outside-root:{token}"
                if tool_id == "nuclei" and token == "-t":
                    normalized=value.replace("\\", "/")
                    if Path(normalized).is_absolute():
                        resolved_template = Path(normalized).expanduser().resolve()
                        trusted_roots = (Path("/usr/share/nuclei-templates"), Path("/opt/nuclei-templates"))
                        if not any(_under_root(str(resolved_template), r) for r in trusted_roots):
                            return False, "template-not-allowlisted"
                    else:
                        normalized=normalized.lstrip("./")
                        if ".." in Path(normalized).parts or not any(normalized.startswith(prefix) for prefix in NUCLEI_TEMPLATE_PREFIXES):
                            return False, "template-not-allowlisted"
                if tool_id == "nxc" and token in {"-u", "-p"}:
                    if root_path is None or not Path(value).exists() or not _under_root(value, root_path):
                        return False, f"credential-file-outside-root:{token}"
                numeric_limits = {
                    "-rate": 5000, "-rate-limit": 500, "-c": 50,
                    "-top-ports": 2000, "--top-ports": 2000,
                    "-screenshot-timeout": 30,
                }
                # `-d` is a numeric crawl depth for katana but a DNS domain
                # value for subfinder. Keep the semantic validation tool-aware.
                if token == "-d" and tool_id == "katana":
                    numeric_limits[token] = 5
                if token in numeric_limits:
                    try:
                        n = int(value)
                    except ValueError:
                        return False, f"numeric-value-required:{token}"
                    if n < 1 or n > numeric_limits[token]:
                        return False, f"value-out-of-range:{token}"
                if tool_id == "nmap" and token == "-p":
                    if not re.fullmatch(r"[0-9,\-]+", value) or len(value) > 64:
                        return False, "invalid-nmap-port-spec"
                i += 2
                continue
            i += 1
            continue
        if not _looks_like_safe_target(token):
            return False, "unsafe-positional"
        # Absolute filesystem paths are only allowed as input files under root.
        if os.path.isabs(token) and root_path is not None and not _under_root(token, root_path):
            return False, "path-outside-root"
        i += 1
    return True, "ok"
