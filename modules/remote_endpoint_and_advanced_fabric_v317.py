"""V3.17 remote endpoint + advanced analysis fabric.

The module is a governed orchestration layer. It does not create an unrestricted
remote shell, persistence channel, credential-capture mechanism, or propagation
engine. Remote execution is represented as exact, auditable assessment actions
that must be implemented by an approved ToolManager adapter or an isolated lab.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

VERSION = "3.17.0"

REMOTE_COMPUTER = {
    "windows": {
        "channels": ["WinRM", "WMI/DCOM", "RDP", "SMB", "OpenSSH"],
        "evidence": ["OS/build", "installed software", "services", "local users/groups", "scheduled tasks", "firewall", "security products", "event logs", "network configuration", "patch state", "PowerShell configuration"],
        "validation": ["authenticated service assessment", "configuration review", "patch/CVE correlation", "web/API assessment", "identity/path correlation", "read-only post-compromise analysis"],
    },
    "linux": {
        "channels": ["SSH", "SFTP", "HTTPS/API", "SNMP"],
        "evidence": ["kernel/distribution", "packages", "systemd services", "users/groups", "sudo policy", "cron/timers", "firewall", "listening sockets", "logs", "mounts", "containers", "cloud metadata configuration"],
        "validation": ["authenticated service assessment", "configuration review", "patch/CVE correlation", "web/API assessment", "container exposure analysis", "read-only post-compromise analysis"],
    },
    "macos": {
        "channels": ["SSH", "Remote Management/MDM evidence", "HTTPS/API"],
        "evidence": ["OS/build", "applications", "launch agents/daemons", "users/groups", "network configuration", "firewall", "security controls", "configuration profiles", "system logs"],
        "validation": ["authenticated configuration assessment", "application/service assessment", "patch/CVE correlation", "read-only endpoint analysis"],
    },
}

REMOTE_MOBILE = {
    "android": {
        "channels": ["ADB over approved network path", "Android Enterprise/MDM evidence", "Corellium/Android emulator", "authorized debug bridge"],
        "evidence": ["build/fingerprint", "packages", "permissions", "exported components", "debuggable state", "network configuration", "logs", "processes", "files selected by policy", "SELinux/security posture", "certificate/signing evidence"],
        "analysis": ["MobSF static/dynamic", "Frida runtime observation", "network/API correlation", "native-library analysis", "IPC/component attack surface"],
    },
    "ios": {
        "channels": ["Corellium", "approved jailbroken-device SSH", "Apple management/MDM evidence", "simulator/runtime"],
        "evidence": ["OS/build", "installed app inventory", "signing/provisioning evidence", "entitlements", "network configuration", "process/runtime observations", "selected filesystem artifacts", "logs", "configuration profiles"],
        "analysis": ["MobSF static/dynamic", "Frida runtime observation", "Ghidra/native binary analysis", "network/API correlation", "Corellium virtual-device testing"],
    },
}

ADVANCED = {
    "firmware_emulation": {
        "engines": ["QEMU", "FirmAE", "EMBA", "FACT"],
        "stages": ["identify", "extract", "architecture detection", "rootfs reconstruction", "emulation preflight", "isolated boot", "service observation", "network observation", "snapshot", "finding validation", "diff/retest"],
        "architectures": ["x86", "x86_64", "ARM", "AArch64", "MIPS", "MIPS64", "PowerPC", "RISC-V", "m68k", "AVR"],
    },
    "binary_reverse_engineering": {
        "engines": ["Ghidra", "radare2/Cutter", "angr", "QEMU", "Capstone", "Keystone"],
        "stages": ["file identification", "loader/architecture", "symbols/strings", "disassembly", "decompilation", "call graph", "CFG", "data-flow", "cross-reference", "vulnerability hypothesis", "dynamic trace correlation", "patch/diff analysis", "report"],
    },
    "protocol_fuzzing": {
        "engines": ["boofuzz-style stateful fuzzing", "Scapy", "AFL++/libFuzzer-style native fuzzing", "custom protocol harnesses"],
        "domains": ["HTTP", "TLS", "DNS", "SSH", "SMB", "MQTT", "CoAP", "Modbus/TCP", "DNP3", "S7comm", "IEC-104", "OPC UA", "CAN", "UDS", "DoIP", "SOME/IP"],
        "stages": ["protocol model", "grammar/state machine", "seed corpus", "mutation strategy", "rate/budget", "oracle", "crash/hang detection", "deduplication", "reproduction", "minimization", "root-cause correlation", "retest"],
    },
    "digital_twins_testbeds": {
        "platforms": ["QEMU", "Docker/Podman", "KVM", "Android emulators", "Corellium", "ICSim/UDSim-style automotive labs", "OT/ICS testbeds", "network namespaces/virtual labs"],
        "stages": ["asset model", "topology", "state seed", "snapshot", "instrumentation", "scenario", "observation", "restore", "compare", "retest"],
    },
    "physical_interface_correlation": {
        "interfaces": ["JTAG", "SWD", "UART", "SPI", "I2C", "USB", "PCIe", "CAN/CAN-FD", "GPIO"],
        "evidence": ["interface inventory", "adapter identity", "bus captures", "logic traces", "firmware hashes", "debug-register observations", "device configuration", "timestamp alignment", "digital twin state"],
        "rule": "physical evidence is correlated with digital evidence; correlation never implies permission to write hardware or alter a live process",
    },
}

SAFETY = {
    "R0": "offline analysis",
    "R1": "read-only remote assessment",
    "R2": "bounded non-destructive validation",
    "R3": "isolated lab/testbed stateful validation",
    "R4": "operator-approved consequential action; specialist adapter required",
    "R5": "denied autonomy: destructive action, uncontrolled propagation, credential theft/capture, stealth/evasion, ransomware, unrestricted remote shell, real exfiltration",
}


def _write(root: str | Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def build_remote_computer_plan(root: str | Path, target: str, platform: str = "auto", objective: str = "full-assessment") -> dict[str, Any]:
    platforms = REMOTE_COMPUTER if platform == "auto" else {platform: REMOTE_COMPUTER[platform]}
    phases = [
        ("authorization", "verify exact target, owner authorization, ROE and remote channel", "R0"),
        ("reachability", "identify approved remote management channel", "R1"),
        ("fingerprint", "OS/service/protocol discovery", "R1"),
        ("authenticated_evidence", "collect policy-approved endpoint evidence", "R1"),
        ("surface", "correlate services, software, versions, configurations and identities", "R1"),
        ("validation", "run bounded non-destructive checks against exact findings", "R2"),
        ("attack_paths", "reason across endpoint, identity, network, cloud and application evidence", "R1"),
        ("lab_reproduction", "reproduce uncertain findings in an isolated twin when possible", "R3"),
        ("retest", "verify remediation using the same evidence contract", "R1"),
        ("report", "produce evidence-backed findings and timeline", "R0"),
    ]
    return _write(root, "remote-computer-assessment-v317.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "platforms": platforms, "phases": [{"id": _id(target, p), "phase": p, "activity": a, "risk": r} for p, a, r in phases],
        "remote_principle": "the engine can orchestrate a comprehensive authorized assessment over an approved channel, but it never turns a discovered channel into unrestricted command authority",
        "required_controls": ["scope", "authorization", "ToolManager allowlist", "exact-action approval for active checks", "rate/time budget", "kill switch", "audit ledger"],
    })


def build_remote_mobile_plan(root: str | Path, target: str, platform: str = "auto", objective: str = "full-assessment") -> dict[str, Any]:
    platforms = REMOTE_MOBILE if platform == "auto" else {platform: REMOTE_MOBILE[platform]}
    phases = [
        ("device_preflight", "identify approved device/emulator channel and device authorization", "R0"),
        ("device_inventory", "build OS, app, signing and security-control inventory", "R1"),
        ("static", "analyze supplied application artifacts", "R0"),
        ("runtime", "observe approved runtime behavior and IPC", "R2"),
        ("network", "correlate device traffic with APIs/services", "R1"),
        ("native", "queue native libraries for reverse engineering", "R0"),
        ("filesystem_process", "collect only policy-approved artifacts/process evidence", "R1"),
        ("validation", "validate exact findings in emulator/virtual device where possible", "R3"),
        ("retest", "repeat evidence contract after remediation", "R1"),
        ("report", "produce mobile assessment evidence and attack-path findings", "R0"),
    ]
    return _write(root, "remote-mobile-assessment-v317.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "platforms": platforms, "phases": [{"id": _id(target, p), "phase": p, "activity": a, "risk": r} for p, a, r in phases],
        "limitations": ["normal consumer iOS does not expose arbitrary remote inspection; use Corellium, simulator, approved management evidence, or an explicitly authorized instrumented device", "Android remote dynamic inspection requires an approved debug/emulator/management channel"],
        "required_controls": ["device authorization", "scope", "ToolManager allowlist", "exact-action approval", "artifact provenance", "kill switch", "audit ledger"],
    })


def build_advanced_analysis_fabric(root: str | Path, target: str, artifact: str = "", objective: str = "analysis") -> dict[str, Any]:
    return _write(root, "advanced-analysis-fabric-v317.json", {
        "schema_version": VERSION, "target": target, "artifact": artifact, "objective": objective,
        "capabilities": ADVANCED,
        "pipeline": [
            "artifact intake -> hash/provenance -> identify -> static analysis -> emulation/rehosting -> runtime observation -> protocol interaction -> finding hypothesis -> evidence correlation -> controlled validation -> retest",
        ],
        "isolation": ["untrusted firmware is isolated", "digital twins are preferred for stateful validation", "fuzzing uses explicit rate/budget/oracle controls", "physical interfaces require adapter and target identity verification"],
    })


def build_remote_capability_matrix(root: str | Path) -> dict[str, Any]:
    return _write(root, "remote-endpoint-capability-matrix-v317.json", {
        "schema_version": VERSION,
        "computer": REMOTE_COMPUTER,
        "mobile": REMOTE_MOBILE,
        "advanced": ADVANCED,
        "safety": SAFETY,
        "governance": ["authorization", "scope", "ROE", "exact-action approval", "ToolManager", "evidence provenance", "kill switch", "durable audit ledger"],
    })


def build_v317_fabric(root: str | Path, target: str, objective: str = "full-assessment", platform: str = "auto", artifact: str = "") -> dict[str, Any]:
    return {
        "remote_capability_matrix": build_remote_capability_matrix(root),
        "remote_computer": build_remote_computer_plan(root, target, platform, objective),
        "remote_mobile": build_remote_mobile_plan(root, target, platform if platform in {"android", "ios"} else "auto", objective),
        "advanced_analysis": build_advanced_analysis_fabric(root, target, artifact, objective),
    }
