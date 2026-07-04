#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('base'); ap.add_argument('new'); ap.add_argument('--out', default='reports/fuzzing/benchmarks/compare.md')
    args=ap.parse_args(); b=json.loads(Path(args.base).read_text()); n=json.loads(Path(args.new).read_text())
    md=['# Fuzz Benchmark Comparison','',f"Base runtime: {b.get('runtime_seconds')}s",f"New runtime: {n.get('runtime_seconds')}s",'',f"Base targets: {b.get('targets_tested')}",f"New targets: {n.get('targets_tested')}"]
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text('\n'.join(md)+'\n'); print(out)
if __name__=='__main__': main()
