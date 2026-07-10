#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def vex(case):
    vuln={'id':'CVE-2099-0001','source':{'name':'demo'},'analysis':{}}
    if case=='contradiction': return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'vulnerabilities':[{'id':'CVE-2099-0001','analysis':{'state':'affected'}},{'id':'CVE-2099-0001','analysis':{'state':'not_affected','justification':'code_not_present'}}]}
    if case=='not-affected-no-justification': vuln['analysis']={'state':'not_affected'}
    elif case=='fixed-no-version': vuln['analysis']={'state':'fixed'}
    elif case=='target-missing': vuln.update({'affects':[{'ref':'pkg:pypi/not-in-sbom@1.0.0'}], 'analysis':{'state':'affected'}})
    else: vuln['analysis']={'state':'under_investigation'}
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[],'vulnerabilities':[vuln]}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Generate VEX contradiction and logic edge cases'); ap.add_argument('--out-dir', default='fuzzing/generated-corpus/vex-logic'); ns=ap.parse_args(argv); out=ROOT/ns.out_dir; out.mkdir(parents=True,exist_ok=True)
    cases=['contradiction','not-affected-no-justification','fixed-no-version','target-missing','under-investigation']
    for c in cases: (out/f'{c}.cdx.json').write_text(json.dumps(vex(c),indent=2)+'\n')
    (out/'manifest.json').write_text(json.dumps({'cases':cases},indent=2)+'\n'); print(json.dumps({'cases':len(cases),'out':str(out.relative_to(ROOT))}, indent=2))
if __name__=='__main__': main()
