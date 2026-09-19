from pathlib import Path
from modules.tool_adapter_hardening_v162 import validate_argv
from modules.scope import is_valid_target_format


def test_loopback_url_is_valid():
    assert is_valid_target_format("http://127.0.0.1:8091")


def test_subfinder_domain_argument_remains_valid():
    ok, reason = validate_argv("subfinder", ["subfinder", "-d", "example.test", "-all", "-silent", "-o", "/tmp/out.txt"], root="/tmp")
    assert ok, reason


def test_katana_depth_requires_numeric_value():
    ok, reason = validate_argv("katana", ["katana", "-u", "http://127.0.0.1:8091", "-d", "3", "-silent"], root="/tmp")
    assert ok, reason
