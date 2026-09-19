import json, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from modules.bug_bounty_v71 import build as bb
from modules.bounty_triage_v72 import build as tri
from modules.bounty_report_v73 import build as rep
from modules.osint_v74 import build as op
from modules.osint_graph_v75 import build as og
from modules.intelligence_modes_v76 import build as mode

class T(unittest.TestCase):
 def setUp(self): self.d=Path(tempfile.mkdtemp()); (self.d/'vulns').mkdir()
 def test_stack(self):
  bb(self.d,'Example Program'); tri(self.d); rep(self.d); op(self.d,'example.com','attack-surface'); og(self.d); mode(self.d,'auto','example.com')
  for f in ['bug-bounty-program-v71.json','bounty-triage-v72.json','osint-plan-v74.json','osint-graph-v75.json','intelligence-mode-v76.json']:
   self.assertTrue((self.d/'evidence'/f).exists())
  self.assertTrue((self.d/'reports'/'bug-bounty-report-pack-v73.md').exists())
  self.assertTrue(json.loads((self.d/'evidence'/'intelligence-mode-v76.json').read_text())['operator_approval_required'])

if __name__=='__main__': unittest.main()
