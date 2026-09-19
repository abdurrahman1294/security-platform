"""Deterministic evidence reasoner for controlled assessment planning.

This is deliberately transparent rather than pretending to be an LLM. It maps
confirmed evidence to the next justified lab action and records why that action
was selected.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

RULES = [
    ("path_traversal", "CONFIRMED", "credential_discovery", "A local file-disclosure primitive can justify bounded credential discovery."),
    ("config_exposure", "CONFIRMED", "credential_discovery", "Exposed configuration can justify credential artifact analysis."),
    ("session_cookie_flags", "CONFIRMED", "session_security_review", "Weak cookie flags justify session-security validation."),
    ("xss_reflection", "CONFIRMED", "xss_impact_review", "Reflected input requires bounded impact review."),
    ("sqli_boolean", "CONFIRMED", "database_exposure_review", "Boolean response difference justifies non-destructive SQLi evidence review."),
    ("idor", "CONFIRMED", "authorization_review", "Cross-object access justifies authorization-boundary review."),
    ("open_redirect", "CONFIRMED", "redirect_validation_review", "Redirect control should be reviewed for trust-boundary impact."),
    ("ssrf", "CONFIRMED", "server_request_review", "A server-side request primitive justifies bounded trust-boundary review."),
    ("command_injection", "CONFIRMED", "execution_boundary_review", "An execution-boundary signal justifies controlled validation review."),
    ("ssti", "CONFIRMED", "template_execution_review", "Template execution signals justify bounded template-security review."),
    ("xxe", "CONFIRMED", "xml_parser_review", "XML parser behavior justifies parser-hardening review."),
    ("file_upload", "CONFIRMED", "upload_boundary_review", "Upload handling signals justify file-type and execution-boundary review."),
    ("csrf", "CONFIRMED", "request_integrity_review", "Missing request-integrity controls justify CSRF review."),
    ("cors", "CONFIRMED", "cross_origin_review", "Permissive CORS signals justify cross-origin trust review."),
    ("host_header_injection", "CONFIRMED", "host_trust_review", "Host-derived behavior justifies trusted-host review."),
    ("crlf_injection", "CONFIRMED", "header_injection_review", "Header injection signals justify response-header boundary review."),
    ("jwt_weakness", "CONFIRMED", "token_validation_review", "Weak token-validation signals justify bounded JWT policy review."),
    ("graphql_exposure", "CONFIRMED", "graphql_schema_review", "GraphQL exposure signals justify schema and authorization review."),
    ("websocket_auth", "CONFIRMED", "websocket_auth_review", "WebSocket auth signals justify channel authorization review."),
    ("insecure_deserialization", "CONFIRMED", "serialization_review", "Unsafe deserialization signals justify parser and object-boundary review."),
    ("ldap_injection", "CONFIRMED", "directory_query_review", "Directory-query signals justify input and query-boundary review."),
    ("nosql_injection", "CONFIRMED", "document_query_review", "Document-query signals justify operator/input-boundary review."),
    ("prototype_pollution", "CONFIRMED", "object_merge_review", "Object-merge signals justify prototype-boundary review."),
    ("request_smuggling", "CONFIRMED", "parser_differential_review", "Parser differential signals justify HTTP parser alignment review."),
    ("cache_poisoning", "CONFIRMED", "cache_key_review", "Cache-key signals justify cache isolation review."),
    ("oauth_misconfiguration", "CONFIRMED", "oauth_flow_review", "OAuth flow signals justify redirect and token-boundary review."),
    ("race_condition", "CONFIRMED", "concurrency_review", "Concurrency signals justify state-transition and idempotency review."),
]

def reason(root: str | Path) -> dict[str, Any]:
    p = Path(root) / "evidence" / "controlled-validation-v21.json"
    data = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"results": []}
    confirmed = {x.get("technique") for x in data.get("results", []) if x.get("status") == "CONFIRMED"}
    p22 = Path(root) / "evidence" / "exploitation-catalog-v22.json"
    if p22.is_file():
        d22 = json.loads(p22.read_text(encoding="utf-8"))
        confirmed |= {x.get("capability") for x in d22.get("results", []) if x.get("status") == "CONFIRMED"}
    decisions = []
    for evidence, status, action, rationale in RULES:
        if evidence in confirmed and status == "CONFIRMED":
            decisions.append({"action": action, "reason": rationale, "trigger": evidence, "risk": "R2"})
    # Attack-chain progression is only proposed when its prerequisites are visible.
    if "path_traversal" in confirmed or "config_exposure" in confirmed:
        decisions.append({"action": "credential_verification", "reason": "Credential-bearing evidence exists; verify one selected lab credential.", "trigger": "credential-bearing-disclosure", "risk": "R2"})
    out = {"schema_version": "22.0", "evidence_count": len(confirmed), "decisions": decisions,
           "decision_policy": "evidence-before-action; no blind chaining"}
    atomic_write_json(Path(root) / "evidence" / "reasoning-v21.json", out)
    return out
