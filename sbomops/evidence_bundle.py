#!/usr/bin/env python3
from __future__ import annotations
import argparse, glob, json, os, shutil, subprocess, zipfile
from pathlib import Path
from .release_common import now, sha256, write_json

def build(a):
    root=Path.cwd().resolve(); out=Path(a.out_dir)/a.release; stage=out/'evidence'; stage.mkdir(parents=True,exist_ok=True)
    selected=[]
    for pattern in a.include or ['reports/**/*.json','reports/**/*.md']:
        for name in glob.glob(pattern,recursive=True):
            p=Path(name)
            if not p.is_file(): continue
            rp=p.resolve()
            try: rel=rp.relative_to(root)
            except ValueError: continue
            if any(part in {'.git','.venv','__pycache__'} for part in rel.parts): continue
            if rel not in selected:selected.append(rel)
    records=[]
    for rel in sorted(selected):
        src=root/rel;dst=stage/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
        records.append({'path':rel.as_posix(),'sha256':sha256(src),'size':src.stat().st_size})
    manifest={'schema':'sst-release-evidence/v1','release':a.release,'generated_at':now(),'file_count':len(records),'files':records}
    mp=write_json(out/'manifest.json',manifest)
    (out/'checksums.txt').write_text(''.join(f"{x['sha256']}  {x['path']}\n" for x in records),encoding='utf-8')
    archive=Path(a.archive or str(out)+'.zip');archive.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in out.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(out.parent))
    result={'release':a.release,'manifest':str(mp),'archive':str(archive),'file_count':len(records),'sha256':sha256(archive)}
    if a.sign_key:
        try:
            cp=subprocess.run(['cosign','sign-blob','--key',a.sign_key,'--output-signature',str(mp)+'.sig',str(mp)],capture_output=True,text=True,timeout=60)
            result['signing']={'returncode':cp.returncode,'stderr':cp.stderr[-1000:]}
        except Exception as e: result['signing']={'error':str(e)}
    return result

def main(argv=None):
    ap=argparse.ArgumentParser(description='Build hash-manifested release evidence')
    ap.add_argument('--release',required=True);ap.add_argument('--include',action='append');ap.add_argument('--out-dir',default='release-evidence');ap.add_argument('--archive');ap.add_argument('--sign-key')
    a=ap.parse_args(argv);r=build(a);print(json.dumps(r,indent=2));return 0
if __name__=='__main__': raise SystemExit(main())
