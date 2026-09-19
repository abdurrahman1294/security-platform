#!/usr/bin/env python3
"""
Authentication & Session Testing Helpers
Checks common session, cookie, and JWT issues.
"""

import base64
import json
import re
from pathlib import Path
from datetime import datetime
from modules.security import redact_text

def analyze_jwt(token: str) -> dict:
    """Basic JWT analysis (header + payload decoding)."""
    result = {"valid_format": False, "header": {}, "payload": {}, "issues": []}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            result["issues"].append("Invalid JWT format (expected 3 parts)")
            return result

        def decode_part(part):
            part += "=" * ((4 - len(part) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(part))

        result["header"] = decode_part(parts[0])
        result["payload"] = decode_part(parts[1])
        result["valid_format"] = True

        # Common issues
        alg = result["header"].get("alg", "").upper()
        if alg == "NONE":
            result["issues"].append("Algorithm set to 'none' – critical")
        if alg in ("HS256", "HS384", "HS512"):
            result["issues"].append("Symmetric algorithm used – check for weak secret")

        payload = result["payload"]
        if "exp" not in payload:
            result["issues"].append("No expiration claim (exp) found")
        if payload.get("iat") and payload.get("exp"):
            if payload["exp"] - payload["iat"] > 86400 * 7:
                result["issues"].append("Token validity period is very long (> 7 days)")

    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as e:
        result["issues"].append(f"Failed to decode JWT: {type(e).__name__}: {str(e)}")
    return result


def check_cookie_security(cookie_header: str) -> list:
    """Check Set-Cookie / Cookie attributes."""
    issues = []
    cookie_lower = cookie_header.lower()

    if "httponly" not in cookie_lower:
        issues.append("Missing HttpOnly flag – JavaScript can access the cookie")
    if "secure" not in cookie_lower:
        issues.append("Missing Secure flag – cookie can be sent over HTTP")
    if "samesite" not in cookie_lower:
        issues.append("Missing SameSite attribute – CSRF risk")
    elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
        issues.append("SameSite=None without Secure flag")

    return issues


def generate_session_report(output_dir: str, cookies: str = "", jwt: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_file = out / "session-auth-analysis.md"

    content = f"""# Authentication & Session Analysis
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Cookie Security Analysis
"""
    if cookies:
        cookie_issues = check_cookie_security(cookies)
        content += "```\n[REDACTED: session cookie omitted from report]\n```\n\n"
        if cookie_issues:
            content += "### Issues Found\n"
            for i in cookie_issues:
                content += f"- {i}\n"
        else:
            content += "No obvious cookie flag issues detected.\n"
    else:
        content += "No cookie data provided.\n"

    content += "\n## JWT Analysis\n"
    if jwt:
        jwt_result = analyze_jwt(jwt)
        content += f"- Valid Format: {jwt_result['valid_format']}\n"
        content += f"- Header: `{redact_text(json.dumps(jwt_result['header']))}`\n"
        content += "- Payload: `[REDACTED: JWT claims omitted from report]`\n\n"
        if jwt_result["issues"]:
            content += "### Issues Found\n"
            for i in jwt_result["issues"]:
                content += f"- {i}\n"
        else:
            content += "No obvious JWT issues detected in basic analysis.\n"
    else:
        content += "No JWT provided.\n"

    content += """
## Recommended Manual Checks
- Session fixation
- Concurrent session handling
- Password reset token strength & expiration
- Logout functionality (does it invalidate the session?)
- Privilege escalation via parameter manipulation (role, user_id, etc.)
- Insecure direct object references (IDOR)
"""

    report_file.write_text(content, encoding="utf-8")
    print(f"[+] Session/Auth analysis written → {report_file}")
    return str(report_file)
