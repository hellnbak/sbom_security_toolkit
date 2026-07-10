#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,shutil,subprocess,time
from pathlib import Path
TOOLS=[('trivy',['trivy','sbom']),('grype',['grype']),('osv-scanner',['osv-scanner','--sbom']),('syft',['syft','scan'])]
def run(tool,cmd,sbom,timeout):
    if shutil.which(cmd[0]) is None:
        return {'tool':tool,'available':False,'status':'missing'}
    start=time.time()
    try:
        p=subprocess.run([*cmd,str(sbom)],text=True,capture_output=True,timeout=timeout)
        return {'tool':tool,'available':True,'status':'ok' if p.returncode==0 else 'error','exit_code':p.returncode,'duration_sec':round(time.time()-start,3),'stdout_bytes':len(p.stdout),'stderr_tail':p.stderr[-1000:]}
    except subprocess.TimeoutExpired:
        return {'tool':tool,'available':True,'status':'timeout','duration_sec':timeout}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--out',default='fuzzing/reports/toolchain/toolchain-fuzz.json'); ap.add_argument('--timeout',type=int,default=30)
    a=ap.parse_args(); results=[run(t,c,a.sbom,a.timeout) for t,c in TOOLS]
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps({'input':a.sbom,'results':results},indent=2)+"\n"); print(f'wrote {a.out}')
if __name__=='__main__': main()
