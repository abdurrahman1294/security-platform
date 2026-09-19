"""V3.18 remote endpoint + advanced execution and cellular-perspective fabric.

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

VERSION = "3.18.0"

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
    return _write(root, "remote-computer-assessment-v318.json", {
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
    return _write(root, "remote-mobile-assessment-v318.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "platforms": platforms, "phases": [{"id": _id(target, p), "phase": p, "activity": a, "risk": r} for p, a, r in phases],
        "limitations": ["normal consumer iOS does not expose arbitrary remote inspection; use Corellium, simulator, approved management evidence, or an explicitly authorized instrumented device", "Android remote dynamic inspection requires an approved debug/emulator/management channel"],
        "required_controls": ["device authorization", "scope", "ToolManager allowlist", "exact-action approval", "artifact provenance", "kill switch", "audit ledger"],
    })


def build_advanced_analysis_fabric(root: str | Path, target: str, artifact: str = "", objective: str = "analysis") -> dict[str, Any]:
    return _write(root, "advanced-analysis-fabric-v318.json", {
        "schema_version": VERSION, "target": target, "artifact": artifact, "objective": objective,
        "capabilities": ADVANCED,
        "pipeline": [
            "artifact intake -> hash/provenance -> identify -> static analysis -> emulation/rehosting -> runtime observation -> protocol interaction -> finding hypothesis -> evidence correlation -> controlled validation -> retest",
        ],
        "isolation": ["untrusted firmware is isolated", "digital twins are preferred for stateful validation", "fuzzing uses explicit rate/budget/oracle controls", "physical interfaces require adapter and target identity verification"],
    })


def build_remote_capability_matrix(root: str | Path) -> dict[str, Any]:
    return _write(root, "remote-endpoint-capability-matrix-v318.json", {
        "schema_version": VERSION,
        "computer": REMOTE_COMPUTER,
        "mobile": REMOTE_MOBILE,
        "advanced": ADVANCED,
        "safety": SAFETY,
        "governance": ["authorization", "scope", "ROE", "exact-action approval", "ToolManager", "evidence provenance", "kill switch", "durable audit ledger"],
    })


def build_v318_fabric(root: str | Path, target: str, objective: str = "full-assessment", platform: str = "auto", artifact: str = "") -> dict[str, Any]:
    return {
        "remote_capability_matrix": build_remote_capability_matrix(root),
        "remote_computer": build_remote_computer_plan(root, target, platform, objective),
        "remote_mobile": build_remote_mobile_plan(root, target, platform if platform in {"android", "ios"} else "auto", objective),
        "advanced_analysis": build_advanced_analysis_fabric(root, target, artifact, objective),
    }


REMOTE_FILE_ACCESS = {
    "windows": {
        "read_channels": ["SMB", "SFTP", "WinRM/approved file collection"],
        "write_test": "only an operator-approved marker under an explicitly scoped test directory",
        "checks": ["share discovery", "share permission evidence", "approved-path listing", "approved-file metadata", "approved-file hash", "read-only retrieval", "controlled write marker", "cleanup verification"],
    },
    "linux": {
        "read_channels": ["SFTP", "SSH/SFTP subsystem", "NFS evidence where explicitly scoped"],
        "write_test": "only an operator-approved marker under an explicitly scoped test directory",
        "checks": ["export discovery", "path authorization", "directory listing", "file metadata", "file hash", "read-only retrieval", "controlled write marker", "cleanup verification"],
    },
    "macos": {
        "read_channels": ["SFTP/SSH", "approved management evidence"],
        "write_test": "only an operator-approved marker under an explicitly scoped test directory",
        "checks": ["channel verification", "approved-path listing", "metadata", "hash", "read-only retrieval", "controlled write marker", "cleanup verification"],
    },
    "android": {
        "read_channels": ["ADB pull from explicitly approved paths", "management/export channel", "emulator/Corellium artifact access"],
        "write_test": "only an operator-approved marker in a disposable test location",
        "checks": ["device identity", "approved-path listing", "metadata", "hash", "read-only pull", "controlled write marker", "cleanup verification"],
    },
    "ios": {
        "read_channels": ["Corellium", "approved instrumented/jailbroken SSH", "app/container export", "management evidence"],
        "write_test": "only a disposable lab/container location; no arbitrary system-file writes",
        "checks": ["device identity", "approved artifact/container listing", "metadata", "hash", "read-only retrieval", "lab-only write marker", "cleanup verification"],
    },
}

CELLULAR_PERSPECTIVE = {
    "objective": "assess an approved target from a mobile/cellular-origin network rather than assuming enterprise or home-network reachability",
    "perspectives": ["IPv4 internet", "IPv6 internet", "carrier NAT/CGNAT", "carrier DNS", "carrier filtering", "APN/private APN", "tethered mobile hotspot", "VPN/overlay path", "dual-stack behavior"],
    "phases": [
        ("source_identity", "record source IPv4/IPv6, ASN/carrier, interface and test timestamp", "R0"),
        ("egress", "verify approved outbound destinations and DNS behavior", "R1"),
        ("reachability", "test only explicitly scoped target addresses/services over cellular", "R1"),
        ("transport", "compare TCP/UDP/IPv4/IPv6 behavior, MTU/path characteristics and filtering", "R1"),
        ("nat", "classify whether the source is directly addressed, carrier-NATed or behind an overlay", "R0"),
        ("exposure", "evaluate whether the approved remote computer/phone exposes intended services to the cellular perspective", "R1"),
        ("auth", "validate approved authentication channels from the cellular origin", "R2"),
        ("file_access", "run the exact approved remote-file evidence contract", "R2"),
        ("correlate", "compare cellular findings with enterprise/home-network observations", "R0"),
        ("retest", "repeat the same measurements after remediation", "R1"),
    ],
    "limitations": ["cellular networks commonly use carrier NAT and may block inbound connections", "IPv6 availability and filtering vary by carrier/APN", "an ordinary phone cannot be assumed to expose inbound services simply because it has cellular data", "the engine must not attempt to bypass carrier controls or establish covert tunnels"],
}

EXECUTION_ADAPTERS = {
    "network_discovery": {"tools": ["nmap", "httpx", "naabu"], "mode": "allowlisted", "purpose": "service and transport discovery"},
    "windows_remote": {"channels": ["WinRM", "SMB", "RDP", "OpenSSH"], "mode": "specialist-adapter", "purpose": "authenticated endpoint evidence and approved validation"},
    "linux_remote": {"channels": ["SSH", "SFTP", "SNMP"], "mode": "specialist-adapter", "purpose": "authenticated endpoint evidence and approved validation"},
    "android_remote": {"channels": ["ADB", "MDM", "Corellium"], "mode": "specialist-adapter", "purpose": "device/app/runtime evidence"},
    "ios_remote": {"channels": ["Corellium", "approved instrumented SSH", "MDM", "simulator"], "mode": "specialist-adapter", "purpose": "device/app/runtime evidence"},
    "firmware": {"tools": ["QEMU", "EMBA", "FACT", "Binwalk/Firmware Mod Kit"], "mode": "isolated", "purpose": "firmware extraction, emulation and evidence correlation"},
    "reverse_engineering": {"tools": ["Ghidra", "radare2/Cutter", "angr", "Capstone", "QEMU"], "mode": "isolated", "purpose": "binary analysis and dynamic-trace correlation"},
    "protocol_fuzzing": {"tools": ["boofuzz", "Scapy", "AFL++", "libFuzzer"], "mode": "isolated-or-explicitly-bounded", "purpose": "stateful protocol robustness testing with crash/hang oracles"},
    "digital_twin": {"tools": ["QEMU", "KVM", "Docker/Podman", "Corellium", "network namespaces", "OT/automotive testbeds"], "mode": "isolated", "purpose": "safe reproduction and stateful validation"},
    "physical_interfaces": {"interfaces": ["JTAG", "SWD", "UART", "SPI", "I2C", "USB", "PCIe", "CAN/CAN-FD", "GPIO"], "mode": "hardware-identity-required", "purpose": "evidence acquisition and correlation; no autonomous write operations"},
}


def build_remote_file_access_plan(root: str | Path, target: str, platform: str = "auto", paths=(), write_probe: bool = False) -> dict[str, Any]:
    chosen = REMOTE_FILE_ACCESS if platform == "auto" else {platform: REMOTE_FILE_ACCESS[platform]}
    approved_paths = [str(x) for x in paths]
    phases = [
        ("channel", "verify an approved remote file channel and authenticate using operator-supplied credentials", "R1"),
        ("scope", "require every requested path to be explicitly approved; reject path traversal and unscoped roots", "R0"),
        ("enumerate", "list only approved directories/shares/containers", "R1"),
        ("metadata", "collect filename, size, timestamps, permissions and hash for approved artifacts", "R1"),
        ("read", "retrieve approved files and record provenance/hash; never silently expand the path set", "R1"),
        ("write_probe", "if explicitly enabled, create one disposable marker only in the approved test directory", "R2"),
        ("cleanup", "verify marker removal and record the result", "R1"),
        ("report", "separate accessible/readable/writable/denied outcomes with evidence", "R0"),
    ]
    if not approved_paths:
        status = "blocked"
        reason = "explicit-file-or-directory-scope-required"
    else:
        status, reason = "planned", ""
    return _write(root, "remote-file-access-v318.json", {
        "schema_version": VERSION, "target": target, "platforms": chosen,
        "approved_paths": approved_paths, "write_probe_requested": bool(write_probe),
        "status": status, "reason": reason,
        "phases": [{"id": _id(target, p), "phase": p, "activity": a, "risk": r} for p, a, r in phases],
        "verdicts": ["channel_unavailable", "denied", "listable", "metadata_readable", "file_readable", "controlled_write_confirmed", "cleanup_failed"],
        "controls": ["exact path allowlist", "credential provenance", "no path traversal", "size/time budget", "single disposable marker", "operator approval for write", "audit ledger"],
    })


def build_cellular_perspective_plan(root: str | Path, target: str, objective: str = "cellular-remote-assessment") -> dict[str, Any]:
    return _write(root, "cellular-perspective-v318.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "perspective": CELLULAR_PERSPECTIVE,
        "comparison_model": ["cellular -> target", "home/enterprise -> target", "VPN/overlay -> target"],
        "success_criteria": ["source network characterized", "IPv4/IPv6 behavior recorded", "carrier filtering/NAT characterized", "approved remote services measured", "file-access contract evaluated", "differences correlated and retestable"],
    })


def build_execution_adapter_catalog(root: str | Path) -> dict[str, Any]:
    return _write(root, "specialist-execution-adapters-v318.json", {
        "schema_version": VERSION, "adapters": EXECUTION_ADAPTERS,
        "execution_rule": "adapters consume governed actions and evidence contracts; they cannot expand scope or create authority",
        "fallback": "when a required specialist binary or device channel is absent, produce a blocked/preflight result instead of substituting an unrestricted execution path",
    })


def build_v318_fabric(root: str | Path, target: str, objective: str = "full-assessment", platform: str = "auto", artifact: str = "", approved_paths=(), write_probe: bool = False) -> dict[str, Any]:
    return {
        "execution_adapters": build_execution_adapter_catalog(root),
        "remote_capability_matrix": build_remote_capability_matrix(root),
        "remote_computer": build_remote_computer_plan(root, target, platform, objective),
        "remote_mobile": build_remote_mobile_plan(root, target, platform if platform in {"android", "ios"} else "auto", objective),
        "remote_file_access": build_remote_file_access_plan(root, target, platform, approved_paths, write_probe),
        "cellular_perspective": build_cellular_perspective_plan(root, target, objective),
        "advanced_analysis": build_advanced_analysis_fabric(root, target, artifact, objective),
    }
