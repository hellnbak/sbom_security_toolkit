#!/usr/bin/env python3
from __future__ import annotations
import argparse
from .common import parse_components, write_csv, write_json, component_stats

def main():
    ap=argparse.ArgumentParser(description='Export SBOM component inventory as CSV/JSON.'); ap.add_argument('sbom'); ap.add_argument('--out-dir',default='reports/sbom-experience/inventory')
    a=ap.parse_args(); fmt, comps, meta=parse_components(a.sbom); rows=[c.__dict__ for c in comps]
    write_csv(f'{a.out_dir}/components.csv',rows); write_json(f'{a.out_dir}/components.json',rows); write_json(f'{a.out_dir}/summary.json',component_stats(comps,meta)); print(f'wrote {a.out_dir}')
if __name__=='__main__': main()
