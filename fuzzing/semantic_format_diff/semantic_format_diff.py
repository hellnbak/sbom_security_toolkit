#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sbomops.common import parse_components
def norm(path):
    fmt, comps, meta=parse_components(path); return {'format':fmt,'component_keys':sorted(c.key() for c in comps),'purls':sorted(c.purl for c in comps if c.purl),'licenses':sorted(set(c.license for c in comps if c.license)),'dependency_graph_present':bool(meta.get('dependency_graph_present'))}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Compare semantic meaning across SBOM formats'); ap.add_argument('sboms', nargs='+'); ap.add_argument('--out', default='reports/fuzzing/semantic-format-diff.json'); ns=ap.parse_args(argv)
    items=[norm(ROOT/s if not Path(s).is_absolute() else Path(s)) for s in ns.sboms]; base=items[0] if items else {}; diffs=[]
    for i,item in enumerate(items[1:], start=1):
        for field in ['component_keys','purls','licenses','dependency_graph_present']:
            if item.get(field)!=base.get(field): diffs.append({'index':i,'field':field,'base':base.get(field),'other':item.get(field)})
    report={'inputs':ns.sboms,'items':items,'diffs':diffs,'passed':not diffs}; out=ROOT/ns.out; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps({'diffs':len(diffs),'passed':not diffs}, indent=2)); return 0 if not diffs else 1
if __name__=='__main__': raise SystemExit(main())
