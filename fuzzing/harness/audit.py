#!/usr/bin/env python3
from __future__ import annotations
import argparse, ast, json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def audit(path: Path)->dict:
    text=path.read_text(errors='replace'); findings=[]; score=100
    def add(level,msg):
        nonlocal score; findings.append({'level':level,'message':msg}); score-= {'info':2,'warn':10,'fail':25}[level]
    if 'atheris' not in text.lower() and 'jazzer' not in text.lower() and 'fuzz' not in text.lower(): add('warn','Harness does not clearly reference a fuzzing engine or fuzz entry point.')
    if re.search(r'except\s+Exception\s*:\s*(pass|return)', text): add('fail','Broad exception handler appears to suppress crashes.')
    if 'subprocess' in text or 'os.system' in text: add('fail','Harness appears to execute subprocess commands.')
    if 'requests.' in text or 'urllib.request' in text or 'socket.' in text: add('fail','Harness appears to make network calls.')
    if re.search(r'open\([^\)]*,\s*["\']w', text): add('warn','Harness writes files; prefer temporary isolated directories.')
    if len(text) < 100: add('warn','Harness is very small and may not exercise meaningful code paths.')
    try: ast.parse(text)
    except SyntaxError as e: add('fail',f'Syntax error: {e}')
    return {'harness':str(path),'score':max(score,0),'findings':findings,'passed':score>=70 and not any(f['level']=='fail' for f in findings)}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Audit fuzz harness safety and quality'); ap.add_argument('harness'); ap.add_argument('--out', default='reports/fuzzing/harness-audit.json'); ns=ap.parse_args(argv)
    p=ROOT/ns.harness if not Path(ns.harness).is_absolute() else Path(ns.harness); result=audit(p)
    out=ROOT/ns.out; out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result, indent=2)); return 0 if result['passed'] else 1
if __name__=='__main__': raise SystemExit(main())
