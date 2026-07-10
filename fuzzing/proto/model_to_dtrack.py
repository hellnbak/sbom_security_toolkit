#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, time
from pathlib import Path

def load_model(path: str):
    p=Path(path)
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: pass
    return {'components':[{'name':'example-lib','version':'1.0.0','purl':'pkg:pypi/example-lib@1.0.0'}], 'dependencies':[]}

def cyclonedx(model):
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),'component':{'type':'application','name':'fuzz-model','version':'0.0.0'}},'components':[{'type':'library','name':c.get('name','component'),'version':c.get('version','0'), 'purl':c.get('purl','')} for c in model.get('components',[])]}

def spdx(model):
    return {'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'fuzz-model','documentNamespace':'https://example.invalid/spdx/fuzz-model','creationInfo':{'created':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),'creators':['Tool: SBOM Security Toolkit']},'packages':[{'SPDXID':f'SPDXRef-Package-{i}','name':c.get('name','component'),'versionInfo':c.get('version','0')} for i,c in enumerate(model.get('components',[]),1)]}

def vex(model):
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'vulnerabilities':[{'id':'CVE-2099-0001','analysis':{'state':'under_investigation','detail':'Generated from fuzz model for testing.'}}]}

def dtrack(model):
    import base64
    bom=json.dumps(cyclonedx(model)).encode()
    return {'projectName':'fuzz-model','autoCreate':True,'bom':base64.b64encode(bom).decode()}

def main(fmt):
    ap=argparse.ArgumentParser(); ap.add_argument('model', nargs='?', default=''); ap.add_argument('--out', default='-')
    args=ap.parse_args(); m=load_model(args.model)
    data={'cyclonedx':cyclonedx,'spdx':spdx,'vex':vex,'dtrack':dtrack}[fmt](m)
    text=json.dumps(data, indent=2)+'\n'
    if args.out=='-': print(text,end='')
    else: Path(args.out).write_text(text)

if __name__=='__main__': main('dtrack')
