#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,subprocess,shutil,tempfile
from pathlib import Path

def variants(sbom:Path,out:Path):
    data=json.loads(sbom.read_text())
    outs=[]
    for name,indent,sort in [('pretty',2,True),('minified',None,False),('reordered',2,False)]:
        d=json.loads(json.dumps(data))
        if name=='reordered' and isinstance(d.get('components'),list): d['components']=list(reversed(d['components']))
        p=out/f'{name}.json'; p.write_text(json.dumps(d,indent=indent,sort_keys=sort)+"\n"); outs.append(p)
    return outs

def run_tool(tool,sbom):
    exe=shutil.which(tool)
    if not exe: return {'tool':tool,'available':False}
    cmd={'trivy':['trivy','sbom','--format','json',str(sbom)],'grype':['grype',str(sbom),'-o','json']}.get(tool)
    try:
        p=subprocess.run(cmd,text=True,capture_output=True,timeout=45)
        return {'tool':tool,'available':True,'exit_code':p.returncode,'stdout_bytes':len(p.stdout),'stderr_tail':p.stderr[-500:]}
    except Exception as e: return {'tool':tool,'available':True,'error':str(e)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--out-dir',default='fuzzing/reports/scanner-metamorphic')
    a=ap.parse_args(); out=Path(a.out_dir); out.mkdir(parents=True,exist_ok=True)
    variant_dir=out/'variants'; variant_dir.mkdir(parents=True,exist_ok=True); files=variants(Path(a.sbom),variant_dir)
    res={str(p):[run_tool(t,p) for t in ['trivy','grype']] for p in files}
    (out/'scanner-metamorphic.json').write_text(json.dumps(res,indent=2)+"\n"); print(f'wrote {out}/scanner-metamorphic.json')
if __name__=='__main__': main()
