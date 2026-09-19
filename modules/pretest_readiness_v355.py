"""V3.55 pre-test readiness gate.

Performs only environment/repository readiness checks. It does not assess targets
or execute offensive actions. The gate is intended to be run immediately before
an engine validation campaign so test results are attributable to a clean,
well-defined environment.
"""
from __future__ import annotations

import importlib
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

VERSION = "4.1.0"
REQUIRED_MODULES = [
    "yaml",
    "PIL",
    "pytest",
]
CORE_MODULES = [
    "security_platform.core.platform",
    "security_platform.cli.securityctl",
    "modules.complete_testing_lab_v343",
    "modules.realistic_vulnerability_lab_v344",
    "modules.integration_validation_range_v345",
    "modules.multi_target_integration_v348",
    "modules.specialist_tool_integration_v351",
    "modules.tool_evidence_normalization_v352",
    "modules.tool_aware_specialist_planner_v353",
    "modules.specialist_isolated_range_v354",
]
OPTIONAL_TOOLS = [
    "nmap", "httpx", "naabu", "katana", "nuclei", "netexec", "frida", "adb",
    "qemu-system-x86_64", "docker", "podman", "terraform", "ghidra",
]


def _check(name: str, ok: bool, detail: str, severity: str = "error") -> dict:
    return {"name": name, "status": "PASS" if ok else "FAIL", "severity": severity, "detail": detail}


def run_pretest_readiness(root: str | Path, artifact_dir: str | Path | None = None) -> dict:
    root = Path(root).resolve()
    artifact = Path(artifact_dir).resolve() if artifact_dir else root / "artifacts" / "pretest-readiness"
    artifact.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []

    py_ok = (sys.version_info >= (3, 11) and sys.version_info < (3, 15))
    checks.append(_check("python-version", py_ok, f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}; required >=3.11,<3.15"))

    version_file = root / "VERSION"
    pyproject = root / "pyproject.toml"
    version = version_file.read_text(encoding="utf-8").strip() if version_file.exists() else ""
    pyproject_text = pyproject.read_text(encoding="utf-8") if pyproject.exists() else ""
    checks.append(_check("version-files", version == VERSION and f'version = "{VERSION}"' in pyproject_text,
                         f"VERSION={version!r}, pyproject contains current version={VERSION}"))

    required_files = ["pyproject.toml", "VERSION", "security_platform/core/platform.py", "security_platform/cli/securityctl.py", "tests"]
    missing = [p for p in required_files if not (root / p).exists()]
    checks.append(_check("repository-layout", not missing, f"missing={missing}"))

    for mod in REQUIRED_MODULES:
        try:
            importlib.import_module(mod)
            checks.append(_check(f"dependency:{mod}", True, "importable"))
        except Exception as exc:
            checks.append(_check(f"dependency:{mod}", False, f"{type(exc).__name__}: {exc}"))

    for mod in CORE_MODULES:
        try:
            importlib.import_module(mod)
            checks.append(_check(f"core-import:{mod}", True, "importable"))
        except Exception as exc:
            checks.append(_check(f"core-import:{mod}", False, f"{type(exc).__name__}: {exc}"))

    checks.append(_check("pytest-command", shutil.which("pytest") is not None, str(shutil.which("pytest"))))
    checks.append(_check("compileall-command", shutil.which(sys.executable) is not None, sys.executable))

    try:
        with tempfile.NamedTemporaryFile(prefix="pretest-", dir=artifact, delete=True) as fh:
            fh.write(b"readiness")
            fh.flush()
        checks.append(_check("artifact-write", True, str(artifact)))
    except Exception as exc:
        checks.append(_check("artifact-write", False, f"{type(exc).__name__}: {exc}"))

    # Verify that the loopback interface can bind without contacting an external host.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        checks.append(_check("loopback-bind", True, f"127.0.0.1:{port}"))
    except Exception as exc:
        checks.append(_check("loopback-bind", False, f"{type(exc).__name__}: {exc}"))
    finally:
        sock.close()

    # Environment guard: no external target may be supplied by this readiness gate.
    external_target = os.environ.get("PENTEST_TEST_TARGET", "").strip()
    checks.append(_check("external-target-guard", not external_target, "PENTEST_TEST_TARGET unset; local-only tests required"))

    # Use the same executable-policy inventory as the runtime, not shutil.which().
    # A binary can exist on PATH yet be rejected by the platform's executable
    # identity / writable-directory policy; reporting it as available here would
    # make the pre-test gate inconsistent with the actual execution layer.
    from security_platform.core.tools import inventory
    runtime_inventory = {row.name: row for row in inventory()}
    registered = sorted(runtime_inventory)
    available = [name for name in registered if runtime_inventory[name].status == "ready"]
    unavailable = [name for name in registered if runtime_inventory[name].status != "ready"]
    checks.append(_check("specialist-tool-inventory", True, f"runtime_policy_available={available}; runtime_policy_unavailable={unavailable}", "info"))

    failures = [c for c in checks if c["status"] == "FAIL"]
    hard_failures = [c for c in failures if c["severity"] != "info"]
    report = {
        "schema_version": VERSION,
        "status": "PASS" if not hard_failures else "FAIL",
        "purpose": "pre-test readiness only",
        "root": str(root),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passed": sum(c["status"] == "PASS" for c in checks),
            "failed": len(failures),
            "hard_failures": len(hard_failures),
            "optional_tools_available": len(available),
            "optional_tools_total": len(registered),
        },
        "safety": {
            "external_network_access": False,
            "external_target_execution": False,
            "real_credentials": False,
            "destructive_actions": False,
        },
    }
    (artifact / "pretest-readiness-v355.json").write_text(__import__("json").dumps(report, indent=2), encoding="utf-8")
    return report


def v355_test_matrix() -> dict:
    names = [
        "python-version", "version-consistency", "repository-layout", "dependency-imports",
        "core-imports", "pytest-availability", "artifact-write", "loopback-bind",
        "external-target-guard", "specialist-tool-inventory",
    ]
    return {"schema_version": VERSION, "scenario_count": len(names), "scenarios": [{"id": f"v355-test-{i+1:02d}", "name": n, "expected": "pass"} for i, n in enumerate(names)]}
