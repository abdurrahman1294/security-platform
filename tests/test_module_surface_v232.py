"""Import-surface regression test for modules that historically lacked tests.

Import coverage is intentionally separate from behavioral coverage: this test
only proves that these modules remain importable. Higher-risk adapters receive
focused behavior tests in test_v232_audit_hardening.py.
"""
import importlib

UNTESTED_SURFACE = [
    "ad_advanced", "ad_command_generator", "ad_guidance", "ad_intelligence_v65",
    "api_scanner", "atomic_io", "auth_scanner", "cloud_intelligence_v64",
    "complete_platform_v70", "control_center", "coverage_report", "final_report_v69",
    "finding_tracker", "infrastructure_intelligence_v63", "internal_scan", "journal",
    "lab_mode", "master_operator_v91", "menu", "platform_controller_v67", "post_exploit",
    "proof_execution_v37", "report_pack", "screenshot", "server_enum", "session_tester",
    "smart_report", "unified_attack_surface_v66", "vuln_knowledge", "evidence_quality_v68",
    "production_layer_v211_v225", "deep_excellence_v226_v231",
]


def test_historically_uncovered_modules_import():
    for name in UNTESTED_SURFACE:
        importlib.import_module(f"modules.{name}")
