#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main(argv=None):
    ap=argparse.ArgumentParser(description='Create local CI fuzzing dashboard'); ap.add_argument('--results', default='reports/fuzzing/clusterfuzzlite-results.json'); ap.add_argument('--out', default='reports/fuzzing/ci-dashboard.html'); ns=ap.parse_args(argv)
    data={}; p=ROOT/ns.results
    if p.exists(): data=json.loads(p.read_text())
    html=f"""<!doctype html><title>Fuzz CI Dashboard</title><h1>Fuzz CI Dashboard</h1><p>Artifacts imported: {len(data.get('artifacts',[]))}</p><pre>{json.dumps(data,indent=2)}</pre>"""
    out=ROOT/ns.out; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(html); print(out)
if __name__=='__main__': main()
