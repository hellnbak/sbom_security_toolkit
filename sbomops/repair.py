#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from .common import detect_format, load_json, write_json, parse_components, PURL_RE

def repair_cdx(data):
    data.setdefault('bomFormat','CycloneDX'); data.setdefault('specVersion','1.5'); data.setdefault('version',1); data.setdefault('components',[])
    seen=set(); notes=[]
    for i,c in enumerate(data.get('components') or []):
        if not isinstance(c,dict): continue
        c.setdefault('type','library')
        if not c.get('bom-ref'):
            c['bom-ref']=f"{c.get('name','component')}@{c.get('version','unknown')}"; notes.append('added missing bom-ref')
        if c['bom-ref'] in seen:
            c['bom-ref']=f"{c['bom-ref']}#duplicate-{i}"; notes.append('made duplicate bom-ref unique')
        seen.add(c['bom-ref'])
        if not c.get('version'): c['version']='NOASSERTION'; notes.append('filled missing version with NOASSERTION')
        if c.get('purl') and not PURL_RE.match(c['purl']): notes.append(f"invalid purl retained for review: {c.get('name')}")
    return data, notes

def main():
    ap=argparse.ArgumentParser(description='Create a best-effort repaired SBOM and repair notes.'); ap.add_argument('sbom'); ap.add_argument('--out',default='reports/sbom-experience/repaired-sbom.json'); ap.add_argument('--notes',default='reports/sbom-experience/repair-notes.md')
    a=ap.parse_args(); fmt=detect_format(a.sbom); notes=[]
    if fmt=='cyclonedx-json': data,notes=repair_cdx(load_json(a.sbom))
    else:
        _, comps, _=parse_components(a.sbom); data={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','bom-ref':c.bom_ref or c.key(),'name':c.name,'version':c.version or 'NOASSERTION','purl':c.purl} for c in comps]}; notes.append(f'converted {fmt} to best-effort CycloneDX JSON')
    write_json(a.out,data); Path(a.notes).parent.mkdir(parents=True,exist_ok=True); Path(a.notes).write_text('# SBOM Repair Notes\n\n'+'\n'.join(f'- {n}' for n in notes or ['No repair actions were needed.'])+'\n'); print(f'wrote {a.out} and {a.notes}')
if __name__=='__main__': main()
