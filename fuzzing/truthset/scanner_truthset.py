#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, subprocess
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(description='Run curated SBOM truth-set through available scanners and compare basic expectations.')
    ap.add_argument('--truthset', default='test-sboms/truthset'); ap.add_argument('--out', default='reports/fuzzing/truthset/results.json')
    args=ap.parse_args(); base=Path(args.truthset); manifest=json.loads((base/'manifest.json').read_text())
    tools=[t for t in ['trivy','grype','osv-scanner'] if shutil.which(t)]
    results=[]
    for case in manifest['cases']:
        f=base/case['file']; item={'file':case['file'],'expected':case,'tools':{}}
        for t in tools:
            cmd=[t, 'sbom', str(f)] if t=='trivy' else ([t,str(f)] if t=='grype' else [t,'--sbom',str(f)])
            try:
                p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
                item['tools'][t]={'returncode':p.returncode,'stdout_len':len(p.stdout),'stderr_tail':p.stderr[-500:]}
            except subprocess.TimeoutExpired: item['tools'][t]={'timeout':True}
        results.append(item)
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps({'tools':tools,'results':results},indent=2)+'\n'); print(out)
if __name__=='__main__': main()
