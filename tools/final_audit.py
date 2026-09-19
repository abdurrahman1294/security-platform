#!/usr/bin/env python3
"""Offline final quality gate for the Security Platform distribution."""
from __future__ import annotations
import importlib
import pathlib
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def main():
    tests=subprocess.run([sys.executable,"-m","pytest","-q"],cwd=ROOT)
    if tests.returncode: return tests.returncode
    compile_result=subprocess.run([sys.executable,"-m","compileall","-q","."],cwd=ROOT)
    if compile_result.returncode: return compile_result.returncode
    failures=[]
    for base,prefix in ((ROOT/"modules","modules."),(ROOT/"security_platform","")):
        for p in base.rglob("*.py"):
            if p.name in {"__init__.py","__main__.py"}: continue
            rel=p.relative_to(ROOT).with_suffix("")
            name=".".join(rel.parts) if prefix=="" else prefix+p.stem
            try: importlib.import_module(name)
            except Exception as exc: failures.append((name,type(exc).__name__,str(exc)))
    total=sum(1 for p in (ROOT/'modules').glob('*.py') if p.name not in {'__init__.py','__main__.py'})+sum(1 for p in (ROOT/'security_platform').rglob('*.py') if p.name not in {'__init__.py','__main__.py'})
    print(f"imported={total-len(failures)} total={total} failures={len(failures)}")
    for row in failures: print(row)
    return 1 if failures else 0

if __name__ == "__main__": raise SystemExit(main())
