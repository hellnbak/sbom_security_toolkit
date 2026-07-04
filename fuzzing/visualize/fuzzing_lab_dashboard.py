#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(path):
    p=ROOT/path
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: return {'raw':p.read_text(errors='replace')[:1000]}
    return {}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Generate static Fuzzing Lab dashboard'); ap.add_argument('--out', default='reports/fuzzing/lab-dashboard.html'); ns=ap.parse_args(argv)
    intelligence=load(Path('reports/fuzzing/intelligence/intelligence.json')); compat=load(Path('reports/fuzzing/scanner-compatibility.json')); evals=load(Path('reports/ai-fuzz-redteam.json'))
    html = "<!doctype html><html><head><title>Fuzzing Lab Dashboard</title><style>body{font-family:Arial;margin:30px}pre{background:#f4f4f4;padding:12px;border-radius:8px;overflow:auto}</style></head><body>"
    html += "<h1>Fuzzing Lab Dashboard</h1><h2>Intelligence Summary</h2><pre>" + json.dumps(intelligence.get('summary', intelligence), indent=2) + "</pre>"
    html += "<h2>Compatibility</h2><pre>" + json.dumps(compat, indent=2)[:5000] + "</pre>"
    html += "<h2>AI Red-Team</h2><pre>" + json.dumps(evals, indent=2)[:5000] + "</pre></body></html>"
    out=ROOT/ns.out; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(html); print(out)
if __name__=='__main__': main()
