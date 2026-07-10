#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main(argv=None):
 ap=argparse.ArgumentParser(description='Create independently verifiable release evidence bundles.'); ap.add_argument('--release',required=True); ap.add_argument('--output',default='dist/release-evidence'); ap.add_argument('--include',action='append',default=[]); ap.add_argument('--sign',action='store_true'); a=ap.parse_args(argv)
 out=Path(a.output)/a.release; out.mkdir(parents=True,exist_ok=True); copied=[]
 for pattern in a.include:
  matches=list(Path('.').glob(pattern)) if any(x in pattern for x in '*?[') else [Path(pattern)]
  for src in matches:
   if not src.is_file(): continue
   dst=out/src.name; shutil.copy2(src,dst); copied.append(dst)
 manifest={'schema_version':'1.0','release':a.release,'created_at':datetime.now(timezone.utc).isoformat(),'files':[{'path':p.name,'sha256':sha(p),'size':p.stat().st_size} for p in sorted(copied)]}
 mp=out/'manifest.json'; mp.write_text(json.dumps(manifest,indent=2)+'\n'); (out/'checksums.txt').write_text('\n'.join(f"{x['sha256']}  {x['path']}" for x in manifest['files'])+'\n')
 if a.sign and shutil.which('cosign'): subprocess.run(['cosign','sign-blob','--yes','--output-signature',str(mp)+'.sig',str(mp)],check=False)
 print(out); return 0
if __name__=='__main__': raise SystemExit(main())
