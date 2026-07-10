#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

def digest(p):
 h=hashlib.sha256();
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def run(cmd):
 try: return subprocess.run(cmd,capture_output=True,text=True,timeout=30)
 except Exception: return None
def main(argv=None):
 ap=argparse.ArgumentParser(description='Verify artifact/SBOM integrity, cosign signatures, and SLSA-style provenance.'); ap.add_argument('--artifact',required=True); ap.add_argument('--sbom',required=True); ap.add_argument('--provenance'); ap.add_argument('--cosign-key'); ap.add_argument('--out',default='reports/provenance/provenance-verification.json'); a=ap.parse_args(argv)
 result={'verified_at':datetime.now(timezone.utc).isoformat(),'artifact':str(a.artifact),'artifact_sha256':digest(a.artifact),'sbom':str(a.sbom),'sbom_sha256':digest(a.sbom),'artifact_signature_verified':False,'sbom_signature_verified':False,'builder_identity':'','provenance_valid':False,'checks':[]}
 if a.provenance and Path(a.provenance).exists():
  p=json.loads(Path(a.provenance).read_text()); result['builder_identity']=p.get('builder',{}).get('id') or p.get('predicate',{}).get('builder',{}).get('id') or ''; subjects=p.get('subject') or p.get('predicate',{}).get('subject') or []; expected=result['artifact_sha256']; result['provenance_valid']=any((s.get('digest') or {}).get('sha256')==expected for s in subjects if isinstance(s,dict)); result['checks'].append({'name':'artifact matches provenance subject','passed':result['provenance_valid']})
 if shutil.which('cosign') and a.cosign_key:
  for kind,path in [('artifact',a.artifact),('sbom',a.sbom)]:
   sig=str(path)+'.sig'; r=run(['cosign','verify-blob','--key',a.cosign_key,'--signature',sig,str(path)]) if Path(sig).exists() else None; ok=bool(r and r.returncode==0); result[f'{kind}_signature_verified']=ok; result['checks'].append({'name':f'{kind} signature','passed':ok,'detail':(r.stderr[-500:] if r else 'signature or cosign unavailable')})
 Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps(result,indent=2)+'\n'); print(a.out); return 0 if result['provenance_valid'] else 2
if __name__=='__main__': raise SystemExit(main())
