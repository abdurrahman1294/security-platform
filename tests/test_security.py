import json
import tempfile
import unittest
from pathlib import Path

from modules.security import in_scope, safe_client_name, redact_mapping
from modules.scope import validate_target_or_exit
from modules.html_report import generate_html_report


class SecurityTests(unittest.TestCase):
    def test_scope_wildcard_and_exact(self):
        allowed = ["example.com", "*.example.com", "10.10.10.0/24"]
        self.assertTrue(in_scope("example.com", allowed))
        self.assertTrue(in_scope("api.example.com", allowed))
        self.assertFalse(in_scope("evil-example.com", allowed))
        self.assertTrue(in_scope("10.10.10.25", allowed))
        self.assertFalse(in_scope("10.10.11.25", allowed))

    def test_client_name_cannot_escape_output_root(self):
        self.assertEqual(safe_client_name("../../evil/client"), "evil-client")
        self.assertNotIn("/", safe_client_name("../../evil/client"))

    def test_secret_redaction(self):
        value = redact_mapping({"token": "abc", "nested": {"password": "xyz"}, "name": "ok"})
        self.assertEqual(value["token"], "[REDACTED]")
        self.assertEqual(value["nested"]["password"], "[REDACTED]")
        self.assertEqual(value["name"], "ok")

    def test_empty_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Path(d) / "scope.txt"
            scope.write_text("# empty\n")
            with self.assertRaises(SystemExit):
                validate_target_or_exit("example.com", str(scope))

    def test_html_escapes_scanner_content(self):
        with tempfile.TemporaryDirectory() as d:
            findings = Path(d) / "findings.json"
            out = Path(d) / "report.html"
            finding = {"info": {"severity": "high", "name": "<script>alert(1)</script>", "description": "<img src=x onerror=alert(1)>"}, "host": "https://example.com"}
            findings.write_text(json.dumps(finding) + "\n")
            generate_html_report(str(findings), "<client>", "example.com", str(out))
            content = out.read_text()
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertNotIn("<img src=x onerror=alert(1)>", content)
            self.assertIn("&lt;script&gt;", content)


if __name__ == "__main__":
    unittest.main()
