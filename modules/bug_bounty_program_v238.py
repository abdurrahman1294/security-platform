"""Bug-bounty program policy parser. Policy scope is authoritative and fail-closed."""
from __future__ import annotations
import json, re
try:
    import yaml
except ImportError:
    yaml = None
from pathlib import Path
from .atomic_io import atomic_write_json

def _host(v):
    return re.sub(r'^https?://','',str(v).strip()).split('/')[0].lower().strip('.')

def _list(value):
    if isinstance(value, str):
        value = [value]
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return []

def build(root, program="", policy_file="", targets=None, exclusions=None):
    root=Path(root); ev=root/'evidence'; ev.mkdir(parents=True,exist_ok=True)
    raw={}
    parse_error=None
    if policy_file:
        path=Path(policy_file)
        if not path.is_file():
            parse_error='policy-file-missing'
        else:
            try:
                text=path.read_text(encoding='utf-8')
                if path.suffix.lower() in {'.yaml','.yml'}:
                    if yaml is None: raise ValueError('PyYAML is required for YAML policies')
                    raw=yaml.safe_load(text) or {}
                else:
                    raw=json.loads(text)
                if not isinstance(raw, dict):
                    raise ValueError('policy root must be an object')
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                raw={}; parse_error=f'{type(exc).__name__}: {exc}'
    # `targets` are candidate assets supplied by the caller, never an implicit
    # expansion of the program's authoritative policy scope.
    policy_scope=sorted({_host(x) for x in _list(raw.get('scope')) if _host(x)})
    candidate_targets=sorted({_host(x) for x in _list(targets) if _host(x)})
    excluded=sorted({_host(x) for x in (_list(exclusions) + _list(raw.get('exclusions'))) if _host(x)})
    rules={
        'scope':policy_scope, 'exclusions':excluded,
        'allowed_testing':_list(raw.get('allowed_testing',[])),
        'forbidden':_list(raw.get('forbidden',[])),
        'rate_limit':raw.get('rate_limit'), 'auth_requirements':raw.get('auth_requirements',[]),
        'submission_rules':raw.get('submission_rules',[]), 'bounty_eligibility':raw.get('bounty_eligibility',{})}
    out={'schema_version':'238.1','program':program or raw.get('program','unspecified'),'rules':rules,
         'candidate_assets':candidate_targets,'policy_loaded':bool(raw) and parse_error is None,
         'policy_parse_error':parse_error,'fail_closed':True,'submission':'manual-only','state_change':'operator-approved-only'}
    atomic_write_json(ev/'bug-bounty-program-v238.json',out); return out
