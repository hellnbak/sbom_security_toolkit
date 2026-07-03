#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from .common import parse_components, write_json, component_stats

def normalized_doc(sbom):
    fmt, comps, meta=parse_components(sbom)
    comps_sorted=sorted(comps,key=lambda c:(c.ecosystem,c.name.lower(),c.version,c.purl))
    return {'input':str(sbom),'format':fmt,'metadata':meta,'stats':component_stats(comps,meta),'components':[c.__dict__ for c in comps_sorted]}

def main():
    ap=argparse.ArgumentParser(description='Normalize an SBOM into toolkit canonical JSON for easier review/diffing.'); ap.add_argument('sbom'); ap.add_argument('--out',default='reports/sbom-experience/normalized.json')
    a=ap.parse_args(); write_json(a.out, normalized_doc(a.sbom)); print(f'wrote {a.out}')
if __name__=='__main__': main()
