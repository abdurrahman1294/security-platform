#!/usr/bin/env python3
"""
Business Logic Testing Checklist Generator
Creates targeted manual test cases based on application type.
"""

from pathlib import Path
from datetime import datetime

CHECKLISTS = {
    "ecommerce": [
        "Price manipulation (modify price in request)",
        "Negative quantity / high quantity orders",
        "Coupon / discount stacking",
        "Race condition on limited stock / coupon redemption",
        "Order status manipulation",
        "Payment amount tampering",
        "Shipping fee manipulation",
        "Reusing gift cards or promo codes",
        "Cart / wishlist IDOR",
        "Unauthorized access to other users' orders"
    ],
    "saas": [
        "Horizontal privilege escalation (access other users' data)",
        "Vertical privilege escalation (user → admin)",
        "Subscription / plan bypass",
        "Feature access control testing",
        "API rate limit bypass",
        "Multi-tenancy isolation issues",
        "Trial abuse / unlimited free tier",
        "Webhook / callback validation"
    ],
    "banking": [
        "Transaction amount manipulation",
        "Race conditions on transfers",
        "Unauthorized fund transfers",
        "Account enumeration",
        "Session management under concurrent logins",
        "Transaction replay",
        "Limit bypass"
    ],
    "general": [
        "IDOR on all object references (user_id, document_id, etc.)",
        "Mass assignment / hidden field manipulation",
        "Step skipping in multi-step processes",
        "Race conditions on critical actions",
        "Business limit bypass (rate, amount, quantity)",
        "Workflow bypass (skip verification steps)",
        "Parameter pollution",
        "HTTP Verb tampering"
    ]
}

def generate_business_logic_checklist(app_type: str, output_dir: str, target: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    app_type = app_type.lower() if app_type else "general"
    items = CHECKLISTS.get(app_type, []) + CHECKLISTS["general"]
    # Remove duplicates while preserving order
    seen = set()
    unique_items = []
    for i in items:
        if i not in seen:
            seen.add(i)
            unique_items.append(i)

    content = f"""# Business Logic Testing Checklist
Target: {target or 'N/A'}
Application Type: {app_type}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

This checklist is intended for **manual testing**. Automation cannot reliably detect most business logic flaws.

## Test Cases

"""
    for idx, item in enumerate(unique_items, 1):
        content += f"- [ ] **BL-{idx:02d}**: {item}\n"

    content += """
## How to Use
1. Go through each item systematically.
2. Mark as completed and note evidence (request/response, screenshots).
3. For every confirmed issue, create a finding in the main report.
4. Focus especially on flows that involve money, privileges, or sensitive data.

## Tips
- Always test both horizontal and vertical access controls.
- Replay requests from lower-privileged users against higher-privileged functions.
- Use two different accounts in parallel when testing IDOR and race conditions.
"""

    report_file = out / f"business-logic-checklist-{app_type}.md"
    report_file.write_text(content, encoding="utf-8")
    print(f"[+] Business logic checklist generated → {report_file}")
    return str(report_file)
