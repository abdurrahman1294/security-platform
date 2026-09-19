#!/usr/bin/env python3
"""Static pre-test audit for the framework itself.

This is deliberately conservative: it flags architecture smells for human
review; it does not claim that a flagged construct is automatically unsafe.
"""
from __future__ import annotations
import ast
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MODULES=ROOT/'modules'; TESTS=ROOT/'tests'

def audit():
    py=list(MODULES.glob('*.py'))
    test_text='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in TESTS.glob('*.py')) if TESTS.exists() else ''
    rows=[]; direct=[]; broad=[]; no_branch=[]; untested=[]
    for p in sorted(py):
        text=p.read_text(encoding='utf-8',errors='ignore')
        try: tree=ast.parse(text,filename=str(p))
        except SyntaxError as exc:
            rows.append({'module':p.name,'status':'syntax-error','error':str(exc)}); continue
        cond=sum(isinstance(n,(ast.If,ast.IfExp,ast.For,ast.While,ast.Try,ast.Match,ast.BoolOp,ast.comprehension)) for n in ast.walk(tree))
        if cond==0: no_branch.append(p.name)
        if 'subprocess.' in text or 'os.system(' in text or 'os.popen(' in text: direct.append(p.name)
        if re.search(r'except\s+Exception\s*:|except\s*:',text): broad.append(p.name)
        if p.stem not in test_text: untested.append(p.name)
        rows.append({'module':p.name,'status':'parsed','conditional_nodes':cond,'direct_process_execution':p.name in direct,'broad_exception_pattern':p.name in broad,'referenced_by_tests':p.stem in test_text})
    return {'module_count':len(py),'no_branch_modules':no_branch,'direct_process_modules':direct,'broad_exception_modules':broad,'modules_not_named_in_tests':untested,'rows':rows}

if __name__=='__main__':
    print(json.dumps(audit(),indent=2))
