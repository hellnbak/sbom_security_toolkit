#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sbomops.common import parse_components, write_json

def to_cdx(comps):
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','bom-ref':c.bom_ref or c.key(),'name':c.name,'version':c.version,'purl':c.purl,'licenses':[{'license':{'id':c.license}}] if c.license else []} for c in comps]}
def to_spdx(comps):
    return {'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'converted-sbom','creationInfo':{'created':'2026-01-01T00:00:00Z','creators':['Tool: SBOM Security Toolkit']},'packages':[{'name':c.name,'SPDXID':c.bom_ref or 'SPDXRef-'+c.name.replace(' ','-'),'versionInfo':c.version or 'NOASSERTION','downloadLocation':'NOASSERTION','filesAnalyzed':False,'licenseConcluded':c.license or 'NOASSERTION','licenseDeclared':c.license or 'NOASSERTION','externalRefs':[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl','referenceLocator':c.purl}] if c.purl else []} for c in comps]}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--format',choices=['cyclonedx-json','spdx-json'],default='cyclonedx-json'); ap.add_argument('--out',default='fuzzing/reports/conversion/converted.json')
    a=ap.parse_args(); fmt, comps, meta=parse_components(a.sbom); data=to_cdx(comps) if a.format=='cyclonedx-json' else to_spdx(comps); data['x-converted-from']=fmt; write_json(a.out,data); print(f'wrote {a.out}')
if __name__=='__main__': main()
