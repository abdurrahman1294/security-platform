import json,tempfile
from pathlib import Path
from modules.osint_engine_v146_v159 import build_osint_engine
from modules.tool_catalog_v160 import build
def test_osint():
 with tempfile.TemporaryDirectory() as d:
  x=json.loads(Path(build_osint_engine(d,'example.com',username='alice')).read_text());assert 'no phone-number tracking' in x['restrictions'] and 'no private-account access' in x['restrictions']
def test_catalog():
 with tempfile.TemporaryDirectory() as d:
  x=json.loads(Path(build(d)).read_text());assert x['tool_count']>=15