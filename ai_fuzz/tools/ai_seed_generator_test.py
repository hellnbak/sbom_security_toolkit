#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main(argv=None):
    ap=argparse.ArgumentParser(description='Test an AI-generated seed generator draft'); ap.add_argument('--generator', required=True); ap.add_argument('--out', default='reports/fuzzing/ai-seed-generator-test.json'); ns=ap.parse_args(argv)
    gen=ROOT/ns.generator if not Path(ns.generator).is_absolute() else Path(ns.generator)
    with tempfile.TemporaryDirectory() as td:
        proc=subprocess.run([sys.executable,str(gen),'--count','3','--out',td],cwd=ROOT,text=True,capture_output=True,timeout=30); files=list(Path(td).glob('*.json')); valid=0
        for f in files:
            try: json.loads(f.read_text()); valid+=1
            except Exception: pass
    result={'generator':str(gen),'returncode':proc.returncode,'files_generated':len(files),'valid_json':valid,'passed':proc.returncode==0 and valid>0,'stderr':proc.stderr[-2000:]}
    out=ROOT/ns.out; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result, indent=2)); return 0 if result['passed'] else 1
if __name__=='__main__': raise SystemExit(main())
