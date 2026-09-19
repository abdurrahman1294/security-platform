"""V3.16 embedded/OT/automotive/hardware security fabric.

The platform becomes a governed control plane for specialist embedded and
cyber-physical security tooling. It plans and normalizes evidence; specialist
executors remain responsible for domain-specific mechanics.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

VERSION = "3.16.0"

SOURCES = {
    "firmware": ["Binwalk", "EMBA", "FACT", "FirmAE"],
    "hardware_platform": ["CHIPSEC", "OpenOCD", "Ghidra"],
    "iot_network": ["Nmap", "Nuclei", "Wireshark", "Kismet"],
    "ot_ics": ["Nmap", "ICSForge", "OT/ICS protocol analyzers", "MITRE ATT&CK for ICS"],
    "automotive": ["can-utils", "Caring Caribou", "SavvyCAN", "ICSim", "UDSim"],
    "network_devices": ["Nmap", "NetExec", "RouterSploit-style device assessment", "SNMP tooling"],
}

CAPABILITIES = {
    "firmware": {
        "image_fingerprinting": "identify containers, filesystems, architectures and entropy characteristics",
        "extraction_inventory": "normalize extracted files, binaries, scripts, certificates and configuration artifacts",
        "sbom_component_analysis": "map packages/components to versions and vulnerability evidence",
        "static_hardening": "identify insecure services, permissions, credentials-in-code indicators and weak update patterns",
        "emulation_contract": "represent isolated firmware re-hosting/emulation as a lab-only validation stage",
        "binary_reverse_engineering": "queue Ghidra-style binary analysis with provenance and analyst notes",
        "firmware_diffing": "compare versions and highlight changed security-relevant components",
        "update_chain_review": "model signing, rollback, transport and verification controls without deploying firmware",
    },
    "hardware_platform": {
        "platform_security_inventory": "model firmware, boot, TPM/secure-boot and low-level platform evidence",
        "debug_interface_inventory": "record JTAG/SWD/UART/debug exposure observations",
        "hardware_prerequisite_assurance": "verify adapter, permissions and test-bench prerequisites before hardware access",
        "read_only_hardware_assessment": "plan bounded read-only checks of exposed platform controls",
        "forensic_artifact_acquisition": "track firmware/device artifacts with hashes and provenance",
        "lab_debug_contract": "represent approved lab-only debug operations without embedding arbitrary device control",
    },
    "iot_network": {
        "device_discovery": "correlate IP, MAC, service, vendor and protocol observations",
        "management_surface": "identify web, SSH, SNMP, APIs and update-management surfaces",
        "protocol_fingerprint": "normalize IoT protocols and service banners",
        "configuration_review": "correlate observed exposure with hardening expectations",
        "device_to_cloud": "link local device evidence to supplied cloud/API observations",
        "segmentation_analysis": "reason about trust zones and reachable management paths",
    },
    "ot_ics": {
        "asset_inventory": "model Purdue-zone-aware assets and roles",
        "protocol_matrix": "represent Modbus, DNP3, S7comm, IEC-104, OPC UA, EtherNet/IP, BACnet, IEC 61850 and related traffic",
        "read_only_protocol_assessment": "plan non-disruptive identification and evidence collection",
        "safety_boundary": "classify operations by process-safety consequence before approval",
        "ics_attack_path_mapping": "map evidence to ATT&CK for ICS tactics/techniques without granting execution authority",
        "detection_validation": "link controlled lab/testbed observations to defensive telemetry and control validation",
    },
    "automotive": {
        "can_interface_inventory": "record SocketCAN adapters, channels and bus configuration",
        "can_passive_analysis": "normalize arbitration IDs, timing, DBC-derived signals and ECU relationships from supplied captures",
        "uds_diagnostic_model": "model UDS/ISO-TP diagnostic evidence and prerequisites",
        "ecu_attack_surface": "correlate ECU, gateway, infotainment, telematics and diagnostic surfaces",
        "vehicle_lab_simulation": "use ICSim/UDSim-style virtual targets for controlled validation",
        "active_can_validation": "represent exact approved test cases with bus-state and safety preconditions",
    },
    "network_devices": {
        "device_fingerprinting": "identify switches, routers, firewalls, APs and management planes",
        "management_protocols": "assess SSH, HTTPS, SNMP, NETCONF/RESTCONF and vendor management surfaces",
        "configuration_evidence": "normalize supplied configs, backups and read-only command outputs",
        "firmware_lifecycle": "correlate device firmware versions with vendor advisories and component evidence",
        "segmentation_and_acl": "derive bounded reachability and trust-zone hypotheses",
        "device_path_correlation": "connect network-device findings to identity, cloud, IoT and OT attack paths",
    },
}

SAFETY_CLASSES = {
    "S0": "offline artifact analysis / passive evidence",
    "S1": "read-only discovery and configuration assessment",
    "S2": "non-disruptive validation with exact target and bounded rate",
    "S3": "lab/testbed stateful validation requiring explicit approval",
    "S4": "process-impacting or hardware-writing operation; external specialist/lab only and never autonomous",
}

PROTOCOLS = {
    "iot": ["MQTT", "CoAP", "UPnP", "HTTP", "HTTPS", "DNS", "mDNS", "SNMP", "SSH"],
    "ot": ["Modbus/TCP", "DNP3", "S7comm", "IEC-104", "OPC UA", "EtherNet/IP", "BACnet/IP", "IEC 61850", "PROFINET", "MQTT"],
    "automotive": ["CAN", "CAN-FD", "ISO-TP", "UDS", "DoIP", "SOME/IP", "LIN", "FlexRay"],
    "network_device": ["SSH", "HTTPS", "SNMP", "NETCONF", "RESTCONF", "TACACS+", "RADIUS", "LLDP"],
}


def _write(root: str | Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def capability_matrix(root: str | Path) -> dict[str, Any]:
    return _write(root, "embedded-ot-automotive-capability-matrix-v316.json", {
        "schema_version": VERSION,
        "sources": SOURCES,
        "domains": CAPABILITIES,
        "safety_classes": SAFETY_CLASSES,
        "protocols": PROTOCOLS,
        "governance": ["authorization", "scope", "ROE", "safety boundary", "exact-action approval", "ToolManager", "evidence provenance", "kill switch"],
    })


def build_firmware_pipeline(root: str | Path, target: str, artifact: str = "") -> dict[str, Any]:
    stages = [
        ("artifact", "hash_and_identify", "S0"),
        ("structure", "extract_and_inventory", "S0"),
        ("components", "sbom_and_version_analysis", "S0"),
        ("hardening", "static_security_analysis", "S0"),
        ("binary", "reverse_engineering_queue", "S0"),
        ("emulation", "isolated_rehost_observation", "S3"),
        ("diff", "compare_against_baseline", "S0"),
        ("update", "firmware_update_chain_review", "S1"),
        ("verdict", "evidence_correlation_and_retest_contract", "S1"),
    ]
    return _write(root, "firmware-security-pipeline-v316.json", {
        "schema_version": VERSION, "target": target, "artifact": artifact,
        "stages": [{"id": _id(target, name), "phase": name, "capability": cap, "safety_class": cls} for name, cap, cls in stages],
        "lab_rule": "untrusted firmware must be isolated; emulation never runs on the host production environment",
    })


def build_ot_ics_plan(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    stages = [
        ("zone_model", "Purdue/asset-role inventory", "S0"),
        ("passive_discovery", "protocol and service observation", "S0"),
        ("read_only", "non-disruptive protocol assessment", "S1"),
        ("control_validation", "detection/control validation in designated testbed", "S3"),
        ("attack_path", "ATT&CK for ICS evidence mapping", "S0"),
        ("retest", "same-evidence remediation verification", "S1"),
    ]
    return _write(root, "ot-ics-assessment-plan-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "protocols": PROTOCOLS["ot"],
        "stages": [{"id": _id(target, phase), "phase": phase, "activity": activity, "safety_class": cls} for phase, activity, cls in stages],
        "hard_stop_conditions": ["process instability", "loss of safety telemetry", "unexpected controller state", "scope mismatch", "authorization mismatch", "operator kill switch"],
        "mapping": "MITRE ATT&CK for ICS is used as a reasoning/reporting taxonomy, not an execution permission system",
    })


def build_automotive_plan(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    stages = [
        ("bench", "identify isolated bench/simulator target", "S0"),
        ("interface", "inventory CAN/diagnostic interfaces", "S0"),
        ("capture", "passive CAN/diagnostic evidence analysis", "S0"),
        ("model", "ECU/gateway/protocol relationship graph", "S0"),
        ("diagnostic", "UDS/ISO-TP evidence and prerequisite analysis", "S1"),
        ("simulation", "ICSim/UDSim-style virtual validation", "S3"),
        ("active", "exact approved lab validation case", "S3"),
        ("safety", "restore and verify bench state", "S1"),
    ]
    return _write(root, "automotive-security-plan-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "protocols": PROTOCOLS["automotive"],
        "stages": [{"id": _id(target, phase), "phase": phase, "activity": activity, "safety_class": cls} for phase, activity, cls in stages],
        "default_target": "simulator or isolated vehicle-security bench",
        "physical_vehicle_rule": "no live-vehicle active operation is inferred from application authorization; exact vehicle/bench authorization and safety prerequisites are mandatory",
    })


def build_hardware_plan(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    interfaces = ["JTAG", "SWD", "UART", "SPI", "I2C", "USB", "PCIe", "TPM", "UEFI/firmware interfaces"]
    return _write(root, "hardware-platform-plan-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "interfaces": [{"interface": x, "inventory": True, "read_only_assessment": True, "write_or_debug": "approval_required"} for x in interfaces],
        "stages": ["asset_identification", "debug_interface_inventory", "boot_and_platform_controls", "firmware_artifact_acquisition", "read_only_security_checks", "lab_validation", "evidence_and_restore"],
        "rule": "hardware-access tooling must run only on designated test systems; low-level drivers and debug interfaces are never assumed safe on production endpoints",
    })


def build_iot_network_plan(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    return _write(root, "iot-network-plan-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "protocols": PROTOCOLS["iot"],
        "stages": ["asset_discovery", "service_fingerprinting", "management_surface", "configuration_evidence", "device_cloud_correlation", "segmentation_analysis", "controlled_validation", "retest"],
        "validation_rule": "device discovery and configuration evidence do not authorize state-changing device operations",
    })


def build_network_device_plan(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    return _write(root, "network-device-security-plan-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "protocols": PROTOCOLS["network_device"],
        "stages": ["device_fingerprint", "management_plane", "configuration_review", "firmware_lifecycle", "ACL_segmentation", "identity_correlation", "path_analysis", "retest"],
        "configuration_sources": ["operator-supplied config", "approved read-only output", "vendor documentation/advisories", "firmware artifact"],
        "rule": "configuration evidence is immutable input; the fabric does not silently modify network-device configuration",
    })


def build_embedded_fusion(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    edges = [
        ("firmware", "iot_network", "firmware component/service -> exposed device surface"),
        ("firmware", "hardware_platform", "firmware -> boot/debug/platform control"),
        ("iot_network", "cloud", "device -> backend/API/cloud dependency"),
        ("iot_network", "ot_ics", "device/service -> industrial zone/protocol relationship"),
        ("ot_ics", "identity", "engineering/workstation/controller -> identity relationship"),
        ("automotive", "firmware", "ECU artifact -> firmware/component evidence"),
        ("automotive", "iot_network", "telematics/infotainment -> IP/cloud exposure"),
        ("network_devices", "ot_ics", "router/switch/firewall -> OT segmentation/control path"),
        ("hardware_platform", "attack_path", "platform control weakness -> bounded path hypothesis"),
    ]
    return _write(root, "embedded-domain-fusion-v316.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "edges": [{"from": a, "to": b, "relationship": rel} for a, b, rel in edges],
        "principle": "prefer evidence that connects physical/embedded artifacts to network, identity, cloud and application layers; never infer physical impact from digital reachability alone",
    })


def build_v316_fabric(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    return {
        "capability_matrix": capability_matrix(root),
        "firmware": build_firmware_pipeline(root, target),
        "hardware_platform": build_hardware_plan(root, target, objective),
        "iot_network": build_iot_network_plan(root, target, objective),
        "ot_ics": build_ot_ics_plan(root, target, objective),
        "automotive": build_automotive_plan(root, target, objective),
        "network_devices": build_network_device_plan(root, target, objective),
        "fusion": build_embedded_fusion(root, target, objective),
    }
