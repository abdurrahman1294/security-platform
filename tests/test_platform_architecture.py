import json
from pathlib import Path
from security_platform.core.engagement import safe_name
from security_platform.engines import OSINTEngine, BugBountyEngine

def test_safe_name():
    assert safe_name("Acme Corp / prod") == "Acme_Corp_prod"

def test_specialist_engines_are_importable():
    assert OSINTEngine.name == "osint"
    assert BugBountyEngine.name == "bounty"

def test_cli_help_is_independent():
    from security_platform.cli.securityctl import parser
    p=parser(); assert {x for x in p._subparsers._group_actions[0].choices} >= {"pentest","osint","bounty","tools"}
