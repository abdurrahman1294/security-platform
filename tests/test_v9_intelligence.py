import json
import tempfile
import unittest
from pathlib import Path

from modules.asset_inventory import build_asset_inventory
from modules.evidence_manager import build_evidence_index
from modules.timeline import build_timeline
from modules.next_investigation import recommend
from modules.dashboard import generate_dashboard
from modules.engagement import init_engagement, update_artifacts
from modules.attack_graph import generate_attack_graph

class V9IntelligenceTests(unittest.TestCase):
    def fixture(self, root):
        for d in ["recon","vulns","api","evidence","reports"]: (root/d).mkdir()
        (root/"recon"/"subdomains.txt").write_text("app.example.com\napi.example.com\n")
        findings=[
            {"template-id":"rce-1","info":{"name":"Remote Code Execution","severity":"critical","tags":["rce"]},"host":"https://app.example.com"},
            {"template-id":"secret-1","info":{"name":"API Secret Exposure","severity":"high","tags":["secret"]},"host":"https://api.example.com"},
        ]
        (root/"vulns"/"findings.json").write_text("\n".join(json.dumps(x) for x in findings)+"\n")
        (root/"evidence"/"finding-status.json").write_text(json.dumps({"rce-1":{"status":"confirmed"}}))

    def test_full_intelligence_chain(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); self.fixture(root)
            init_engagement(root,"Acme","example.com","scope.txt")
            build_asset_inventory(root); build_evidence_index(root); build_timeline(root); generate_attack_graph(root); recommend(root); generate_dashboard(root,"Acme","example.com"); update_artifacts(root)
            for rel in ["evidence/assets.json","evidence/evidence-index.json","evidence/timeline.json","evidence/attack-graph.json","evidence/next-investigation.json","reports/next-investigation.md","reports/dashboard.html","reports/timeline.md","evidence/engagement.json"]:
                self.assertTrue((root/rel).exists(), rel)
            rec=json.loads((root/"evidence/next-investigation.json").read_text())
            self.assertTrue(rec["recommendations"])
            self.assertEqual(rec["recommendations"][0]["finding_id"], "F-" + "".join(rec["recommendations"][0]["finding_id"].split("F-")[1:]))

if __name__ == "__main__": unittest.main()
