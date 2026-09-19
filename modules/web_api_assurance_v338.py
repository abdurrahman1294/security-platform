"""V3.38 web/API assurance catalog and safe validation planning."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import hashlib, time
from modules.reliability_execution_integrity_v331 import atomic_write, redact
VERSION="3.38.0"
TESTS=("transport-security","security-headers","cookie-attributes","cors-policy","cache-policy","method-surface","content-type","redirect-policy","input-validation","output-encoding","authentication-boundary","authorization-boundary","rate-limit-observation","error-handling","graphql-introspection-exposure","api-version-drift","openapi-drift","websocket-surface","file-upload-controls","path-normalization")
DENIED_PAYLOADS={"credential-theft","session-theft","destructive","unrestricted-rce","persistence","covert-c2"}
def _id(*p): return hashlib.sha256("|".join(map(str,p)).encode()).hexdigest()[:20]
def _write(root,name,obj): p=Path(root)/"evidence"/name; atomic_write(p,obj); return p
def build_test_catalog():
    return [{"test_id":_id("web",x),"name":x,"class":"safe-observation","requires_operator_approval":x in {"authorization-boundary","rate-limit-observation","file-upload-controls"},"payload":"non-mutating-marker-or-observation","denied_payload_classes":sorted(DENIED_PAYLOADS)} for x in TESTS]
def build_v338_fabric(root, *, target="", endpoints=None, objective="web-api-assurance"):
    eps=[redact(x) for x in (endpoints or []) if isinstance(x,dict)]
    result={"schema_version":VERSION,"target":target,"objective":objective,"test_catalog":build_test_catalog(),"endpoint_count":len(eps),"endpoints":eps[:1000],"coverage":{"test_classes":len(TESTS),"broad_corpus_is_catalogued":True,"exploit_generation":False,"credential_capture":False},"governance":{"scope_locked":True,"authorization_required_for_active_validation":True,"operator_confirmation_for_sensitive_tests":True,"no_destructive_tests":True},"created_at":time.time()}
    _write(root,"web-api-assurance-v338.json",result); return result
def v338_test_matrix():
    names=["20-test-classes","endpoint-redaction","catalog-deterministic","safe-observation","approval-boundary","authorization-boundary","no-credential-capture","no-session-theft","no-rce","no-destructive","no-persistence","no-covert-c2","scope-lock","operator-visible","machine-readable","atomic-write","api-drift","graphql","websocket","upload-controls","error-handling","input-validation","output-encoding","rate-limit-observation","transport-controls"]
    return {"schema_version":VERSION,"scenario_count":len(names),"scenarios":[{"id":_id(x),"name":x,"expected":"safe-web-assurance"} for x in names]}
