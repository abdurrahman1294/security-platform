from modules.tool_adapter_hardening_v162 import validate_argv, TOOL_ENV
from modules.scope import is_valid_target_format


def test_aws_endpoint_is_allowed_through_tool_environment():
    assert "AWS_ENDPOINT_URL" in TOOL_ENV["aws"]


def test_subfinder_d_is_domain_value_not_numeric():
    ok, reason = validate_argv("subfinder", ["subfinder", "-d", "example.test", "-all", "-silent", "-o", "/tmp/out.txt"], root="/tmp")
    assert ok, reason


def test_katana_d_is_numeric():
    ok, reason = validate_argv("katana", ["katana", "-u", "http://127.0.0.1:8091", "-d", "3", "-silent"], root="/tmp")
    assert ok, reason


def test_loopback_url_scope_format_is_supported():
    assert is_valid_target_format("http://127.0.0.1:3000")


def test_bundled_lab_template_exists():
    from pathlib import Path
    assert (Path(__file__).resolve().parents[1] / "lab_templates" / "cves" / "lab-header-check.yaml").is_file()
