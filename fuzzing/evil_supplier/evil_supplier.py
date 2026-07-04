#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SCENARIOS={'component-omission':['declares application but no components'],'dependency-graph-omission':['components present but no dependencies'],'license-laundering':['permissive declared license with suspicious metadata'],'unicode-confusable':['component name uses confusable unicode'],'duplicate-identities':['same purl with different versions'],'vex-overclaiming':['not_affected without adequate justification']}
def sbom(name):
    comps=[{'type':'library','name':'example','version':'1.0.0','bom-ref':'pkg:pypi/example@1.0.0','purl':'pkg:pypi/example@1.0.0','licenses':[{'license':{'id':'MIT'}}]}]
    if name=='component-omission': comps=[]
    if name=='unicode-confusable': comps[0]['name']='exаmple'
    if name=='duplicate-identities': comps.append(dict(comps[0], version='2.0.0'))
    data={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'component':{'type':'application','name':'supplier-demo','version':'1.0.0'}},'components':comps}
    if name!='dependency-graph-omission': data['dependencies']=[{'ref':c.get('bom-ref'),'dependsOn':[]} for c in comps]
    if name=='vex-overclaiming': data['vulnerabilities']=[{'id':'CVE-2099-0001','analysis':{'state':'not_affected'}}]
    return data
def main(argv=None):
    ap=argparse.ArgumentParser(description='Generate evil-supplier SBOM scenario suite'); ap.add_argument('--out-dir', default='test-sboms/evil-supplier'); ns=ap.parse_args(argv); out=ROOT/ns.out_dir; out.mkdir(parents=True,exist_ok=True); report=[]
    for name, notes in SCENARIOS.items():
        path=out/f'{name}.json'; path.write_text(json.dumps(sbom(name),indent=2)+'\n'); report.append({'scenario':name,'path':str(path.relative_to(ROOT)),'concerns':notes})
    (out/'evil-supplier-report.json').write_text(json.dumps({'scenarios':report},indent=2)+'\n')
    md=['# Evil Supplier SBOM Scenario Suite','','Synthetic local-only scenarios for testing supplier intake and policy behavior.','','| Scenario | Concern | File |','|---|---|---|']
    for r in report: md.append(f"| {r['scenario']} | {', '.join(r['concerns'])} | `{r['path']}` |")
    (out/'evil-supplier-report.md').write_text('\n'.join(md)+'\n'); print(json.dumps({'scenarios':len(report),'out':str(out.relative_to(ROOT))}, indent=2))
if __name__=='__main__': main()
