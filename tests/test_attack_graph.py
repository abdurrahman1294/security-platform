import json
import tempfile
import unittest
from pathlib import Path

from modules.attack_graph import build_attack_graph, generate_attack_graph


class AttackGraphTests(unittest.TestCase):
    def _fixture(self, root: Path):
        (root / "vulns").mkdir(parents=True)
        (root / "api").mkdir(parents=True)
        (root / "evidence").mkdir(parents=True)
        web = {"template-id": "web-rce", "info": {"name": "Remote Code Execution", "severity": "critical", "tags": ["rce"]}, "host": "https://app.example.com"}
        api = {"template-id": "api-secret", "info": {"name": "API Secret Exposure", "severity": "high", "tags": ["api", "secret"]}, "host": "https://api.example.com"}
        (root / "vulns" / "findings.json").write_text(json.dumps(web) + "\n")
        (root / "api" / "api-findings.json").write_text(json.dumps(api) + "\n")
        (root / "evidence" / "finding-status.json").write_text(json.dumps({"web-rce": {"status": "confirmed"}}))

    def test_graph_is_evidence_aware_and_cross_surface(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._fixture(root)
            graph = build_attack_graph(root)
            self.assertEqual(graph["finding_count"], 2)
            self.assertTrue(any(n["type"] == "surface" and n["label"] == "Api" for n in graph["nodes"]))
            self.assertTrue(any(e["status"] == "hypothesis" for e in graph["edges"]))
            finding = next(n for n in graph["nodes"] if n["finding_id"] == n["id"] and n["type"] == "finding" and n["metadata"].get("surface") == "web")
            self.assertEqual(finding["status"], "confirmed")

    def test_generation_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._fixture(root)
            json_path, md_path = generate_attack_graph(root)
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertIn("Evidence-Aware Attack Graph", md_path.read_text())
            self.assertIn("mermaid", md_path.read_text())


if __name__ == "__main__":
    unittest.main()

class AttackIntelligenceTests(unittest.TestCase):
    def test_finding_model_has_capabilities_impacts_prerequisites_and_evidence_quality(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "vulns").mkdir(parents=True)
            finding = {"template-id": "rce", "info": {"name": "Remote Code Execution", "severity": "critical", "tags": ["rce"]}, "host": "https://app.example.com", "curl-command": "curl https://app.example.com/test"}
            (root / "vulns" / "findings.json").write_text(json.dumps(finding) + "\n")
            (root / "evidence").mkdir()
            (root / "evidence" / "finding-status.json").write_text(json.dumps({"rce": {"status": "confirmed"}}))
            graph = build_attack_graph(root)
            node = next(n for n in graph["nodes"] if n["type"] == "finding")
            meta = node["metadata"]
            self.assertIn("initial-access", meta["capabilities_gained"])
            self.assertIn("integrity", meta["impacts"])
            self.assertTrue(meta["prerequisites"])
            self.assertEqual(meta["evidence_quality"], 1.0)
            self.assertEqual(graph["schema_version"], "2.0")

    def test_same_parent_domain_is_only_a_hypothesis(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "vulns").mkdir(parents=True)
            a = {"template-id": "a", "info": {"name": "RCE", "severity": "high", "tags": ["rce"]}, "host": "https://app.example.com"}
            b = {"template-id": "b", "info": {"name": "Secret Exposure", "severity": "high", "tags": ["secret"]}, "host": "https://api.example.com"}
            (root / "vulns" / "findings.json").write_text(json.dumps(a) + "\n" + json.dumps(b) + "\n")
            graph = build_attack_graph(root)
            self.assertTrue(any(e["relation"] == "same-parent-domain" and e["status"] == "hypothesis" for e in graph["edges"]))
