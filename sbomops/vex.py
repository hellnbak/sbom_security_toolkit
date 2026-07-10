#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, datetime
from pathlib import Path
from .common import write_json
ALLOWED={'affected','not_affected','fixed','under_investigation'}

def template(args):
    state=args.state
    doc={
      'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
      'metadata': {'timestamp': datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z', 'tools': [{'name':'sbom-security-toolkit','version':'1.2.0'}]},
      'vulnerabilities': [{
        'id': args.cve,
        'source': {'name':'manual-review'},
        'ratings': [{'method':'other','severity': args.severity}],
        'affects': [{'ref': args.component}],
        'analysis': {'state': state, 'justification': args.justification, 'response': [args.response], 'detail': args.detail}
      }]
    }
    write_json(args.output, doc); print(args.output)

def validate(args):
    data=json.loads(Path(args.vex).read_text())
    problems=[]
    vulns=data.get('vulnerabilities',[]) if isinstance(data,dict) else []
    if not vulns: problems.append('No vulnerabilities array found.')
    for idx,v in enumerate(vulns):
        a=v.get('analysis',{}) if isinstance(v,dict) else {}
        st=a.get('state')
        if st not in ALLOWED: problems.append(f'vulnerabilities[{idx}] has invalid or missing analysis.state: {st}')
        if st=='not_affected' and not a.get('justification'): problems.append(f'vulnerabilities[{idx}] not_affected requires justification')
        if not v.get('affects'): problems.append(f'vulnerabilities[{idx}] has no affects refs')
    print('VEX validation:', 'PASS' if not problems else 'FAIL')
    for p in problems: print('-',p)
    return 1 if problems else 0

def merge(args):
    sbom=json.loads(Path(args.sbom).read_text())
    vex=json.loads(Path(args.vex).read_text())
    sbom.setdefault('vulnerabilities',[])
    sbom['vulnerabilities'].extend(vex.get('vulnerabilities',[]))
    write_json(args.output, sbom); print(args.output)

def explain(args):
    data=json.loads(Path(args.vex).read_text())
    for v in data.get('vulnerabilities',[]):
        a=v.get('analysis',{})
        refs=', '.join(x.get('ref','') for x in v.get('affects',[]))
        print(f"{v.get('id','UNKNOWN')}: {a.get('state','unknown')} for {refs}")
        if a.get('justification'): print(f"  justification: {a['justification']}")
        if a.get('detail'): print(f"  detail: {a['detail']}")

def main():
    ap=argparse.ArgumentParser(description='CycloneDX VEX helper commands.')
    sp=ap.add_subparsers(dest='cmd', required=True)
    t=sp.add_parser('template'); t.add_argument('--cve',required=True); t.add_argument('--component',required=True); t.add_argument('--state',choices=sorted(ALLOWED),default='under_investigation'); t.add_argument('--severity',default='unknown'); t.add_argument('--justification',default='code_not_present'); t.add_argument('--response',default='will_not_fix'); t.add_argument('--detail',default='Generated template. Human review required before use.'); t.add_argument('--output',default='vex/generated-vex.cdx.json'); t.set_defaults(func=template)
    v=sp.add_parser('validate'); v.add_argument('vex'); v.set_defaults(func=validate)
    m=sp.add_parser('merge'); m.add_argument('--sbom',required=True); m.add_argument('--vex',required=True); m.add_argument('--output',default='reports/vex/merged-sbom.cdx.json'); m.set_defaults(func=merge)
    e=sp.add_parser('explain'); e.add_argument('vex'); e.set_defaults(func=explain)
    args = ap.parse_args()
    raise SystemExit(args.func(args) or 0)
if __name__=='__main__': main()
