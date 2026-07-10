#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--corpus",default="fuzzing/regression/corpus"); ap.add_argument("--out",default="fuzzing/reports/regression-report.json"); args=ap.parse_args()
    corpus=Path(args.corpus); corpus.mkdir(parents=True,exist_ok=True)
    results=[]
    for p in sorted(corpus.glob("*.json")):
        proc=subprocess.run(["python3","fuzzing/oracles/semantic_oracles.py",str(p)],capture_output=True,text=True)
        results.append({"file":str(p),"returncode":proc.returncode,"stdout":proc.stdout[-2000:],"stderr":proc.stderr[-1000:],"passed":proc.returncode==0})
    report={"corpus":str(corpus),"count":len(results),"passed":all(r["passed"] for r in results),"results":results}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(json.dumps(report,indent=2)+"\n"); print(json.dumps(report,indent=2)); sys.exit(0 if report["passed"] else 1)
if __name__=="__main__": main()
