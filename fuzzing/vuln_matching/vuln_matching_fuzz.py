#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CASES=[('purl-only','pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',''),('cpe-only','','cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*'),('purl-cpe-conflict','pkg:npm/lodash@4.17.20','cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*'),('python-normalized','pkg:pypi/Django@3.2.0',''),('npm-scoped','pkg:npm/%40scope/name@1.0.0','')]
def main(argv=None):
    ap=argparse.ArgumentParser(description='Generate vulnerability matching edge-case SBOMs'); ap.add_argument('--out-dir', default='fuzzing/generated-corpus/vuln-matching'); ns=ap.parse_args(argv)
    out=ROOT/ns.out_dir; out.mkdir(parents=True,exist_ok=True); results=[]
    for i,(name,purl,cpe) in enumerate(CASES):
        comp={'type':'library','name':name,'version':'1.0.0','bom-ref':purl or cpe or name}
        if purl: comp['purl']=purl
        if cpe: comp['cpe']=cpe
        sbom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[comp]}; path=out/f'{i:02d}-{name}.json'; path.write_text(json.dumps(sbom,indent=2)+'\n'); results.append({'case':name,'path':str(path.relative_to(ROOT)),'expected':'scanner behavior may differ; inspect identity-matching evidence'})
    (out/'vuln-matching-manifest.json').write_text(json.dumps({'cases':results},indent=2)+'\n'); print(json.dumps({'cases':len(results),'out':str(out.relative_to(ROOT))}, indent=2))
if __name__=='__main__': main()
