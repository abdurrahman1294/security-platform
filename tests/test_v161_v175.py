import json, tempfile
from pathlib import Path
from modules.hardening_v161_v175 import atomic_write_json, validate_public_url, build_hardening, build_osint_source_registry
from modules.tool_adapter_hardening_v162 import validate_argv, sanitized_environment

def test_atomic_and_redaction():
    with tempfile.TemporaryDirectory() as d:
        p=atomic_write_json(Path(d)/"x.json", {"authorization":"Bearer abc123","ok":True})
        x=json.loads(p.read_text()); assert "REDACTED" in x["authorization"]

def test_public_url_policy():
    assert validate_public_url("https://crt.sh/", allowed_hosts={"crt.sh"})[0]
    assert not validate_public_url("http://127.0.0.1/", allowed_hosts={"127.0.0.1"})[0]
    assert not validate_public_url("https://evil.example/", allowed_hosts={"crt.sh"})[0]

def test_hardening_artifact():
    with tempfile.TemporaryDirectory() as d:
        p=build_hardening(d,"example.com"); assert p.exists()
        build_osint_source_registry(d); assert (Path(d)/"evidence/osint-source-registry-v161.json").exists()

def test_argv_validation():
    assert validate_argv("httpx", ["httpx","-silent"])[0]
    assert not validate_argv("httpx", ["nmap"])[0]

def test_secret_env_filtered():
    assert "OPENAI_API_KEY" not in sanitized_environment()
