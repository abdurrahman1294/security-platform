import json, tempfile, unittest
from pathlib import Path
from modules.ai_reasoning_v83 import build as ai
from modules.target_profile_v84 import build as profile
from modules.web_intelligence_v85 import build as web
from modules.osint_collection_v86 import build as osint
from modules.cross_engagement_memory_v87 import build as memory
from modules.bounty_prioritization_v88 import build as bounty
from modules.reporting_monitoring_v89 import build as reporting
from modules.security_training_v90 import build as training

class V83V90Tests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.o=Path(self.t.name); (self.o/'evidence').mkdir(); (self.o/'reports').mkdir()
        (self.o/'evidence'/'sample.json').write_text(json.dumps({'api':['/api/users/{id}'],'auth':['login'],'technology':['React'],'severity':'high'}))
    def tearDown(self): self.t.cleanup()
    def test_all_layers(self):
        for fn,args in [(ai,('pentest','example.com','general')),(profile,('example.com',)),(web,()),(osint,('example.com',False)),(memory,('example.com',)),(bounty,()),(reporting,('example.com',)),(training,('api security',))]:
            p=fn(self.o,*args); self.assertTrue(Path(p).exists())
        self.assertEqual(json.loads((self.o/'evidence'/'ai-reasoning-v83.json').read_text())['human_approval_required'],True)
        self.assertTrue(json.loads((self.o/'evidence'/'osint-collection-v86.json').read_text())['passive_only'])
        self.assertFalse(json.loads((self.o/'evidence'/'bounty-prioritization-v88.json').read_text())['auto_submission'])
        self.assertFalse(json.loads((self.o/'evidence'/'security-training-v90.json').read_text())['real_target_execution'])

if __name__=='__main__': unittest.main()
