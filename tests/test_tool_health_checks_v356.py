from modules.tool_adapter_hardening_v162 import HEALTH_CHECK_ARGV, validate_argv


def test_v356_health_checks_are_allowlisted():
    for tool_id, argv in HEALTH_CHECK_ARGV.items():
        assert validate_argv(tool_id, list(argv))[0], tool_id


def test_v356_health_checks_are_exact_matches():
    assert not validate_argv("aws", ["aws", "version"])[0]
    assert not validate_argv("gcloud", ["gcloud", "version", "--quiet"])[0]
    assert not validate_argv("kubectl", ["kubectl", "version"])[0]
    assert not validate_argv("httpx", ["httpx", "-version", "example.com"])[0]
    assert not validate_argv("nmap", ["nmap", "--version", "example.com"])[0]
