#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main(argv=None):
    ap=argparse.ArgumentParser(description='Import ClusterFuzzLite result artifacts into local reports'); ap.add_argument('--input-dir', default='fuzzing/clusterfuzzlite/results'); ap.add_argument('--out', default='reports/fuzzing/clusterfuzzlite-results.json'); ns=ap.parse_args(argv)
    inp=ROOT/ns.input_dir; artifacts=[]
    if inp.exists():
        for f in inp.rglob('*'):
            if f.is_file(): artifacts.append({'path':str(f.relative_to(ROOT)),'size':f.stat().st_size})
    report={'input_dir':str(inp.relative_to(ROOT)) if inp.exists() and inp.is_relative_to(ROOT) else str(inp),'artifacts':artifacts,'artifact_count':len(artifacts)}; out=ROOT/ns.out; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(report, indent=2))
if __name__=='__main__': main()
