#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_components, write_json

def main():
    ap=argparse.ArgumentParser(description='Export lightweight GUAC-friendly component graph metadata.')
    ap.add_argument('sbom'); ap.add_argument('--out', default='reports/guac/guac-export.json')
    args=ap.parse_args(); fmt, comps, meta=parse_components(args.sbom)
    graph={'format':fmt,'metadata':meta,'nodes':[{'id':c.bom_ref or c.key(),'name':c.name,'version':c.version,'purl':c.purl,'ecosystem':c.ecosystem} for c in comps], 'edges': [], 'note':'This is a lightweight export scaffold. Use GUAC ingestion tooling for production graph analysis.'}
    write_json(args.out, graph); print(args.out)
if __name__=='__main__': main()
