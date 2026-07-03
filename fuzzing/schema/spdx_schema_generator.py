#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,random,uuid
from pathlib import Path

def make_doc(count:int, edge:str):
    pkgs=[]; rel=[]
    for i in range(count):
        spdx=f'SPDXRef-Package-{i}'
        name=('pkg-' + str(i)) if edge!='unicode' else 'pkg-раураl-'+str(i)
        v='' if edge=='missing-version' and i%3==0 else '1.0.'+str(i)
        p={"name":name,"SPDXID":spdx,"versionInfo":v,"downloadLocation":"NOASSERTION","filesAnalyzed":False,"licenseConcluded":"MIT","licenseDeclared":"MIT","supplier":"Organization: Example Supplier","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":f"pkg:pypi/{name}@{v or 'unknown'}"}]}
        if edge=='invalid-license': p['licenseDeclared']='MIT AND OR Apache-2.0'
        pkgs.append(p)
        if i>0: rel.append({"spdxElementId":f'SPDXRef-Package-{i-1}',"relationshipType":"DEPENDS_ON","relatedSpdxElement":spdx})
    if edge=='dependency-cycle' and count>2: rel.append({"spdxElementId":pkgs[-1]['SPDXID'],"relationshipType":"DEPENDS_ON","relatedSpdxElement":pkgs[0]['SPDXID']})
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"generated-spdx-edge","documentNamespace":"https://example.invalid/spdx/"+str(uuid.uuid4()),"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: SBOM Security Toolkit"]},"packages":pkgs,"relationships":rel}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='fuzzing/generated-corpus/schema/spdx'); ap.add_argument('--count',type=int,default=25); ap.add_argument('--packages',type=int,default=8); ap.add_argument('--edge',default='valid-edge',choices=['valid-edge','dependency-cycle','missing-version','unicode','invalid-license'])
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(a.count): (out/f'spdx-{a.edge}-{i:04d}.json').write_text(json.dumps(make_doc(a.packages,a.edge),indent=2)+"\n")
    print(f'wrote {a.count} SPDX seeds to {out}')
if __name__=='__main__': main()
