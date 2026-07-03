#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,json,os,urllib.request,urllib.error
from pathlib import Path
PRIVATE_PREFIXES=('http://127.0.0.1','http://localhost','https://127.0.0.1','https://localhost')
def local_only(url):
    return any(url.startswith(p) for p in PRIVATE_PREFIXES)
def request(method,url,token=None,data=None):
    req=urllib.request.Request(url,method=method,data=data)
    if token: req.add_header('X-Api-Key',token)
    if data: req.add_header('Content-Type','application/json')
    with urllib.request.urlopen(req,timeout=10) as r:
        return r.status,r.read().decode('utf-8','replace')
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--url',default='http://127.0.0.1:8081'); ap.add_argument('--token',default=os.getenv('DTRACK_API_KEY','')); ap.add_argument('--sbom',default='test-sboms/clean/minimal-cyclonedx.json'); ap.add_argument('--dry-run',action='store_true'); ap.add_argument('--out',default='fuzzing/reports/stateful/dependency-track-state-machine.json')
    a=ap.parse_args(); steps=[]
    if not local_only(a.url): raise SystemExit('Refusing non-local Dependency-Track URL. Use localhost or 127.0.0.1.')
    raw=Path(a.sbom).read_bytes(); payload={'projectName':'sst-stateful-fuzz','projectVersion':'1.0.0','autoCreate':True,'bom':base64.b64encode(raw).decode()}
    steps.append({'step':'prepare-upload','bytes':len(raw),'url':a.url,'dry_run':a.dry_run})
    if not a.dry_run:
        try:
            status,body=request('PUT',a.url.rstrip()+'/api/v1/bom',a.token,json.dumps(payload).encode())
            steps.append({'step':'upload-bom','status':status,'body_tail':body[-500:]})
        except Exception as e:
            steps.append({'step':'upload-bom','error':str(e)})
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps({'steps':steps},indent=2)+"\n"); print(f'wrote {a.out}')
if __name__=='__main__': main()
