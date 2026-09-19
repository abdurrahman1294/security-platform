#!/usr/bin/env python3
"""
Vulnerability Knowledge Base
Generates detailed professional explanations + remediation guidance.
"""

from datetime import datetime

# Knowledge base for common vulnerability classes
VULN_DB = {
    "lfi": {
        "title": "Local File Inclusion (LFI) / Path Traversal",
        "description": "The application allows an attacker to include or read files from the local filesystem by manipulating user-controlled input (often parameters like file=, page=, path=, etc.).",
        "risks": [
            "Reading sensitive files (configuration files, source code, /etc/passwd, environment files)",
            "Exposure of credentials, API keys, database passwords",
            "In some cases, escalation to Remote Code Execution (via log poisoning or PHP wrappers)",
            "Full compromise of application confidentiality"
        ],
        "what_can_be_harmed": [
            "Application source code and business logic",
            "User data and personal information",
            "System configuration and credentials",
            "Reputation and regulatory compliance (GDPR, etc.)"
        ],
        "exploitation_techniques": [
            "Basic path traversal using ../ sequences",
            "URL encoding / double encoding bypasses",
            "PHP wrappers (php://filter, php://input, data://)",
            "Log file poisoning + inclusion",
            "Null byte injection (older systems)"
        ],
        "exploitation_steps_high_level": [
            "1. Identify a parameter that appears to load files or pages",
            "2. Test with simple traversal payloads (../../../etc/passwd)",
            "3. If blocked, try encoding techniques or wrappers",
            "4. Confirm by reading a known file",
            "5. Search for sensitive files (config, .env, id_rsa, etc.)"
        ],
        "remediation": [
            "Never use user input directly in file system operations",
            "Use a strict whitelist of allowed files/pages",
            "Sanitize and normalize all user input (remove ../, null bytes, etc.)",
            "Run the application with the least privileges necessary",
            "Disable dangerous PHP wrappers if not needed",
            "Implement proper input validation and output encoding"
        ],
        "prevention": [
            "Secure coding training for developers",
            "Use frameworks that handle file operations safely",
            "Regular code reviews focusing on file handling",
            "Automated SAST tools in CI/CD pipeline",
            "Web Application Firewall (WAF) rules for path traversal patterns"
        ],
        "patch_example": '''# Example secure pattern (PHP)
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) {
    http_response_code(400);
    exit('Invalid page');
}
include "pages/{$page}.php";
'''
    },

    "sqli": {
        "title": "SQL Injection",
        "description": "User input is unsafely concatenated into SQL queries, allowing an attacker to modify the query structure and interact directly with the database.",
        "risks": [
            "Authentication bypass",
            "Extraction of the entire database (users, passwords, credit cards, etc.)",
            "Modification or deletion of data",
            "In some cases, remote code execution on the database server",
            "Complete compromise of the application's data layer"
        ],
        "what_can_be_harmed": [
            "All data stored in the database",
            "User accounts and credentials",
            "Business records, financial data, personal data",
            "Application integrity and availability"
        ],
        "exploitation_techniques": [
            "Union-based SQL injection",
            "Error-based SQL injection",
            "Boolean-based blind SQL injection",
            "Time-based blind SQL injection",
            "Stacked queries (when supported)"
        ],
        "exploitation_steps_high_level": [
            "1. Identify input points that interact with the database",
            "2. Test with basic payloads (' OR '1'='1, etc.)",
            "3. Determine database type and injection technique",
            "4. Extract data carefully (prefer read-only techniques during engagements)",
            "5. Document the exact vulnerable parameter and payload"
        ],
        "remediation": [
            "Use parameterized queries (prepared statements) exclusively",
            "Never concatenate user input into SQL strings",
            "Apply least-privilege database accounts",
            "Validate and sanitize input as a secondary defense",
            "Hide detailed database errors from users"
        ],
        "prevention": [
            "Mandatory use of ORM or prepared statements in coding standards",
            "Code review checklist for database interactions",
            "SAST and DAST tools in the development pipeline",
            "Regular developer training on injection attacks",
            "Database activity monitoring"
        ],
        "patch_example": '''# Example secure pattern (Python)
cursor.execute("SELECT * FROM users WHERE email = %s AND active = %s", (email, True))

# Example secure pattern (PHP PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND active = ?");
$stmt->execute([$email, 1]);
'''
    },

    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "description": "User input is reflected or stored in a page without proper output encoding, allowing attackers to execute JavaScript in the context of other users' browsers.",
        "risks": [
            "Session hijacking / account takeover",
            "Credential theft via fake login forms",
            "Malware distribution",
            "Defacement",
            "Performing actions on behalf of the victim"
        ],
        "what_can_be_harmed": [
            "End-user accounts and sessions",
            "User trust and brand reputation",
            "Sensitive actions the user is authorized to perform"
        ],
        "exploitation_techniques": [
            "Reflected XSS",
            "Stored XSS",
            "DOM-based XSS",
            "Bypassing weak filters with encoding or alternative event handlers"
        ],
        "exploitation_steps_high_level": [
            "1. Identify reflection points of user input",
            "2. Test basic payloads and observe encoding behavior",
            "3. Craft context-aware payloads (HTML, attribute, JavaScript context)",
            "4. Demonstrate impact with a non-destructive proof (e.g. alert or console log)"
        ],
        "remediation": [
            "Apply context-aware output encoding (HTML, JavaScript, URL, CSS)",
            "Use modern frameworks that auto-escape by default",
            "Implement Content-Security-Policy (CSP) headers",
            "Sanitize HTML with a proven library if rich content is required",
            "Set HttpOnly and Secure flags on session cookies"
        ],
        "prevention": [
            "Adopt frameworks with automatic escaping",
            "Security training focused on output encoding",
            "CSP as a strong mitigating control",
            "Regular scanning for XSS in CI/CD"
        ],
        "patch_example": '''# Content-Security-Policy example
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';

# Always encode output in the correct context
'''
    },

    "rce": {
        "title": "Remote Code Execution / Command Injection",
        "description": "User input is passed to a system shell or code evaluation function without proper sanitization, allowing arbitrary command or code execution on the server.",
        "risks": [
            "Complete server compromise",
            "Data theft, ransomware, lateral movement",
            "Persistence and backdoors",
            "Full breach of confidentiality, integrity, and availability"
        ],
        "what_can_be_harmed": [
            "The entire server and any connected systems",
            "All application and customer data",
            "Internal network (if the server can reach it)"
        ],
        "exploitation_techniques": [
            "OS command injection via shell metacharacters",
            "Code injection (eval, unsanitized template engines, etc.)",
            "Deserialization attacks",
            "Insecure file uploads leading to code execution"
        ],
        "exploitation_steps_high_level": [
            "1. Identify input that may reach system calls or evaluators",
            "2. Test with harmless commands (id, whoami, hostname)",
            "3. Confirm execution context and privileges",
            "4. Stop at proof-of-concept during professional engagements unless further access is explicitly authorized"
        ],
        "remediation": [
            "Avoid system/shell calls whenever possible",
            "If unavoidable, use strict allow-lists and escape arguments properly",
            "Never pass raw user input to eval, exec, system, etc.",
            "Run services with least privilege",
            "Apply input validation and strong output handling"
        ],
        "prevention": [
            "Secure coding standards prohibiting dangerous functions",
            "Regular code review and SAST",
            "Runtime protection (e.g. disable dangerous PHP functions)",
            "Principle of least privilege on all service accounts"
        ],
        "patch_example": '''# Bad: concatenating untrusted input into a shell command can cause command injection.
# Better: invoke the program without a shell and validate the input first.
import subprocess
subprocess.run(["ping", "-c", "1", validated_host], check=True)
'''
    },

    "default-login": {
        "title": "Default or Weak Credentials",
        "description": "The application or service is accessible using well-known default usernames and passwords, or extremely weak credentials.",
        "risks": [
            "Unauthorized administrative access",
            "Full compromise of the affected system or application",
            "Data breach and lateral movement"
        ],
        "what_can_be_harmed": [
            "Administrative interfaces",
            "Customer and business data",
            "Entire application or infrastructure component"
        ],
        "exploitation_techniques": [
            "Trying common default credential pairs",
            "Password spraying with known defaults",
            "Checking vendor documentation for default accounts"
        ],
        "exploitation_steps_high_level": [
            "1. Identify login interfaces",
            "2. Attempt known default credentials for the detected technology",
            "3. Document successful access and immediately recommend credential change"
        ],
        "remediation": [
            "Force password change on first login",
            "Disable or remove default accounts",
            "Implement strong password policies and multi-factor authentication",
            "Regularly audit accounts for weak or default credentials"
        ],
        "prevention": [
            "Hardening guides applied during deployment",
            "Configuration management that enforces secure baselines",
            "Automated scanning for default credentials",
            "MFA on all administrative interfaces"
        ],
        "patch_example": "# Immediately change all default passwords and disable unnecessary default accounts.\n# Enforce MFA for administrative access."
    },

    "exposure": {
        "title": "Sensitive Information Exposure",
        "description": "Sensitive data (credentials, configuration, debug information, personal data, source code) is exposed to unauthorized users.",
        "risks": [
            "Credential theft and account takeover",
            "Further exploitation using leaked secrets",
            "Privacy violations and regulatory penalties"
        ],
        "what_can_be_harmed": [
            "User privacy",
            "Application secrets and infrastructure credentials",
            "Intellectual property"
        ],
        "exploitation_techniques": [
            "Browsing to known sensitive paths (.env, .git, backup files, debug endpoints)",
            "Reviewing JavaScript files and API responses for secrets",
            "Checking error messages and stack traces"
        ],
        "exploitation_steps_high_level": [
            "1. Discover exposed files or endpoints",
            "2. Confirm the sensitivity of the data",
            "3. Record evidence without unnecessary downloading of large personal datasets"
        ],
        "remediation": [
            "Remove sensitive files from web-accessible locations",
            "Block access via web server configuration",
            "Remove debug modes and detailed errors in production",
            "Rotate any exposed credentials immediately"
        ],
        "prevention": [
            "Secret scanning in repositories and CI/CD",
            "Proper .gitignore and deployment hygiene",
            "Regular external surface scanning",
            "Security headers and access controls"
        ],
        "patch_example": '''# Example nginx rule
location ~ /\\.(env|git|bak|old|swp) {
    deny all;
    return 404;
}
'''
    }
}


def detect_vuln_type(finding: dict) -> str:
    """Simple heuristic to map a nuclei finding to a knowledge base key."""
    name = finding.get("info", {}).get("name", "").lower()
    tags = [t.lower() for t in finding.get("info", {}).get("tags", [])]
    combined = name + " " + " ".join(tags)

    if any(x in combined for x in ["lfi", "local-file", "path-traversal", "file-read"]):
        return "lfi"
    if any(x in combined for x in ["sqli", "sql-injection", "sql injection"]):
        return "sqli"
    if any(x in combined for x in ["xss", "cross-site-scripting"]):
        return "xss"
    if any(x in combined for x in ["rce", "command-injection", "code-injection", "remote-code"]):
        return "rce"
    if any(x in combined for x in ["default-login", "default-credentials", "weak-password"]):
        return "default-login"
    if any(x in combined for x in ["exposure", "exposed", "disclosure", "sensitive"]):
        return "exposure"
    return "generic"


def generate_detailed_explanation(finding: dict, output_path: str):
    """Generate a full professional explanation file for a finding."""
    vuln_type = detect_vuln_type(finding)
    info = finding.get("info", {})
    name = info.get("name", "Unknown Vulnerability")
    severity = info.get("severity", "unknown").upper()
    host = finding.get("host") or finding.get("matched-at") or "N/A"
    matched = finding.get("matched-at") or host
    description = info.get("description", "No description provided by scanner.")

    kb = VULN_DB.get(vuln_type, None)

    content = f"""# Detailed Vulnerability Explanation
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Finding Summary
- **Title:** {name}
- **Severity:** {severity}
- **Affected Asset:** {host}
- **Matched Location:** {matched}
- **Scanner Description:** {description}

"""

    if kb:
        content += f"""## Vulnerability Class: {kb['title']}

### What is this vulnerability?
{kb['description']}

### Risks and Business Impact
"""
        for r in kb["risks"]:
            content += f"- {r}\n"

        content += "\n### What can be harmed / exploited?\n"
        for w in kb["what_can_be_harmed"]:
            content += f"- {w}\n"

        content += "\n### Common Exploitation Techniques\n"
        for t in kb["exploitation_techniques"]:
            content += f"- {t}\n"

        content += "\n### High-level Exploitation Steps (Educational / Authorized Testing Only)\n"
        for s in kb["exploitation_steps_high_level"]:
            content += f"{s}\n"

        content += "\n### Remediation Steps (What should be done now)\n"
        for r in kb["remediation"]:
            content += f"- {r}\n"

        content += "\n### Prevention (How to stop this in the future)\n"
        for p in kb["prevention"]:
            content += f"- {p}\n"

        content += f"""
### Example Secure Code / Configuration Pattern
``` 
{kb['patch_example']}
```
"""
    else:
        content += """## General Guidance
This finding did not match a detailed knowledge base entry.
Treat it according to its severity and the scanner description.
Perform manual analysis and apply least-privilege and secure-coding principles.
"""

    content += """
---
**Important Notes**
- This document is intended for authorized security assessments and remediation planning only.
- Exploitation steps are provided at a high level for educational and defensive purposes.
- Always obtain proper written authorization before testing any system.
- Prefer safe proof-of-concept verification over aggressive exploitation during professional engagements.
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path
