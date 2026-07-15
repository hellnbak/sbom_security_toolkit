#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess
from pathlib import Path
from typing import Any
from .release_common import load_data, now, sha256, write_json

def _subjects(doc:Any):
    if not isinstance(doc,dict): return []
    if isinstance(doc.get('subject'),list): return doc['subject']
    pred=doc.get('predicate') or {}
    return pred.get('subject') if isinstance(pred.get('subject'),list) else []
def _matches(subjects,name,digest):
    for s in subjects:
        d=s.get('digest') or {}
        if d.get('sha256')==digest and (not name or Path(str(s.get('name',''))).name==Path(name).name): return True
    return False

def verify(a):
    out={'generated_at':now(),'artifact':None,'sbom':None,'provenance':a.provenance,'builder_identity':'','status':'PASS','checks':[]}
    doc=load_data(a.provenance,{}) if a.provenance else {}; subs=_subjects(doc)
    pred=(doc or {}).get('predicate') or {}; out['builder_identity']=str((pred.get('builder') or {}).get('id') or (doc or {}).get('builder',''))
    for label,path in [('artifact',a.artifact),('sbom',a.sbom)]:
        if not path: continue
        p=Path(path); digest=sha256(p); matched=_matches(subs,p.name,digest) if a.provenance else None
        rec={'path':str(p),'sha256':digest,'subject_match':matched};out[label]=rec
        if a.provenance and not matched: out['status']='FAIL';out['checks'].append(f'{label}_digest_mismatch')
    if a.require_builder and not out['builder_identity']: out['status']='FAIL';out['checks'].append('builder_identity_missing')
    if a.signature and a.key:
        cmd=['cosign','verify-blob','--key',a.key,'--signature',a.signature,a.artifact or a.sbom]
        try:
            cp=subprocess.run(cmd,text=True,capture_output=True,timeout=60)
            out['cosign']={'returncode':cp.returncode,'stdout':cp.stdout[-2000:],'stderr':cp.stderr[-2000:]}
            if cp.returncode: out['status']='FAIL';out['checks'].append('cosign_verification_failed')
        except Exception as e:
            out['cosign']={'error':str(e)};out['status']='ERROR';out['checks'].append('cosign_unavailable')
    if not out['checks']: out['checks']=['digests_computed'+('_and_matched' if a.provenance else '')]
    write_json(Path(a.out_dir)/'provenance-verification.json',out)
    return out

def main(argv=None):
    ap=argparse.ArgumentParser(description='Verify artifact, SBOM, and provenance integrity')
    ap.add_argument('--artifact');ap.add_argument('--sbom');ap.add_argument('--provenance');ap.add_argument('--signature');ap.add_argument('--key');ap.add_argument('--require-builder',action='store_true');ap.add_argument('--out-dir',default='reports/provenance')
    a=ap.parse_args(argv);r=verify(a);print(json.dumps(r,indent=2));return 0 if r['status']=='PASS' else 4
if __name__=='__main__': raise SystemExit(main())
