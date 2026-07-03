#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, random, uuid
from pathlib import Path
ECOS=[('npm','left-pad'),('pypi','requests'),('maven','org.example/app'),('golang','github.com/example/lib'),('cargo','serde')]

def component(i:int, edge:str):
    eco,name=random.choice(ECOS)
    bom=f"{name.replace('/','-')}@{i}"
    version = "1.0."+str(i)
    if edge=='huge-version': version='1.'+'0'*512+'.'+str(i)
    if edge=='unicode': name='lib-'+'ρаураӏ-'+str(i)
    c={"type":"library","bom-ref":bom,"name":name,"version":version,"purl":f"pkg:{eco}/{name}@{version}","licenses":[{"license":{"id":"MIT"}}]}
    if edge=='conflicting-identities': c['cpe']='cpe:2.3:a:other:other:9.9:*:*:*:*:*:*:*'
    if edge=='missing-version': c.pop('version',None)
    return c

def make_bom(count:int, edge:str):
    comps=[component(i, edge) for i in range(count)]
    deps=[]
    for i,c in enumerate(comps):
        children=[]
        if i+1 < len(comps): children.append(comps[i+1]['bom-ref'])
        deps.append({'ref':c['bom-ref'],'dependsOn':children})
    if edge=='dependency-cycle' and len(comps)>2:
        deps[-1]['dependsOn']=[comps[0]['bom-ref']]
    if edge=='duplicate-bom-ref' and len(comps)>1:
        comps[1]['bom-ref']=comps[0]['bom-ref']
    return {"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:"+str(uuid.uuid4()),"version":1,"metadata":{"timestamp":"2026-01-01T00:00:00Z","tools":[{"vendor":"SBOM Security Toolkit","name":"schema-generator"}]},"components":comps,"dependencies":deps}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',default='fuzzing/generated-corpus/schema/cyclonedx')
    ap.add_argument('--count',type=int,default=25)
    ap.add_argument('--components',type=int,default=8)
    ap.add_argument('--edge',default='valid-edge',choices=['valid-edge','dependency-cycle','duplicate-bom-ref','conflicting-identities','missing-version','huge-version','unicode'])
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(a.count): (out/f'cyclonedx-{a.edge}-{i:04d}.json').write_text(json.dumps(make_bom(a.components,a.edge),indent=2)+"\n")
    print(f'wrote {a.count} CycloneDX seeds to {out}')
if __name__=='__main__': main()
