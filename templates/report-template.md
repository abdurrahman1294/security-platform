# Vulnerability Assessment Report

**Client:** {{CLIENT_NAME}}  
**Target:** {{TARGET}}  
**Assessment Date:** {{DATE}}  
**Assessor:** {{YOUR_NAME}}  
**Authorization Reference:** {{AUTH_REF}}

---

## 1. Executive Summary

This report presents the findings of an authorized vulnerability assessment conducted against **{{TARGET}}**.

| Severity | Count |
|----------|-------|
| Critical | {{CRITICAL_COUNT}} |
| High     | {{HIGH_COUNT}} |
| Medium   | {{MEDIUM_COUNT}} |
| Low      | {{LOW_COUNT}} |
| Informational | {{INFO_COUNT}} |

**Key Takeaways:**
- {{KEY_TAKEAWAY_1}}
- {{KEY_TAKEAWAY_2}}
- {{KEY_TAKEAWAY_3}}

---

## 2. Scope

**In Scope:**
- {{IN_SCOPE}}

**Out of Scope:**
- {{OUT_OF_SCOPE}}

**Testing Window:** {{START_DATE}} → {{END_DATE}}

---

## 3. Methodology

The assessment followed a structured approach:

1. **Passive & Active Reconnaissance** – Subdomain discovery, technology fingerprinting, live host identification.
2. **Port & Service Enumeration** – TCP port scanning and service version detection.
3. **Web Application Enumeration** – Content discovery, crawling, endpoint mapping.
4. **Vulnerability Discovery** – Automated scanning with curated high-signal templates + manual validation.
5. **Reporting** – Only validated findings are included.

Tools used include ProjectDiscovery suite (subfinder, httpx, naabu, katana, nuclei), nmap, and ffuf.

---

## 4. Findings

### 4.1 Critical Findings

{{CRITICAL_FINDINGS}}

### 4.2 High Findings

{{HIGH_FINDINGS}}

### 4.3 Medium Findings

{{MEDIUM_FINDINGS}}

---

## 5. Detailed Finding Template (copy per issue)

### [SEVERITY] – {{FINDING_TITLE}}

- **Asset:** {{AFFECTED_URL_OR_HOST}}
- **CVSS / Severity:** {{SCORE}}
- **Description:**  
  {{DESCRIPTION}}

- **Evidence:**  
  ```
  {{REQUEST_RESPONSE_OR_SCREENSHOT_REF}}
  ```

- **Impact:**  
  {{IMPACT}}

- **Recommendation:**  
  {{RECOMMENDATION}}

- **References:**  
  {{REFERENCES}}

---

## 6. Positive Observations

- {{POSITIVE_1}}
- {{POSITIVE_2}}

---

## 7. Remediation Roadmap

| Priority | Finding | Recommended Action | Suggested Timeline |
|----------|---------|--------------------|--------------------|
| P1 | {{FINDING}} | {{ACTION}} | Immediate |
| P2 | {{FINDING}} | {{ACTION}} | 7–14 days |
| P3 | {{FINDING}} | {{ACTION}} | 30 days |

---

## 8. Conclusion

{{CONCLUSION_PARAGRAPH}}

---

## 9. Appendix

- Raw tool output is available on request.
- This assessment was performed under authorized scope only.
- Retest availability: {{RETEST_INFO}}

---

*Report generated with assistance of automated enumeration pipeline. All findings manually validated.*
