#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, subprocess, time
from pathlib import Path
TOOLS={'trivy':['trivy','sbom'], 'grype':['grype'], 'osv-scanner':['osv-scanner','--sbom'], 'syft':['syft','scan']}

def main():
    ap=argparse.ArgumentParser(description='Generate local SBOM tool compatibility matrix.')
    ap.add_argument('--corpus', default='test-sboms'); ap.add_argument('--out', default='reports/fuzzing/scanner-compatibility.json')
    args=ap.parse_args(); files=[p for p in Path(args.corpus).rglob('*') if p.suffix.lower() in {'.json','.xml','.spdx','.txt'}][:25]
    rows=[]
    for tool,base in TOOLS.items():
        available=bool(shutil.which(base[0])); row={'tool':tool,'available':available,'inputs':len(files),'ok':0,'failed':0,'timeouts':0,'component_drop_suspicions':0}
        if available:
            for f in files:
                try:
                    p=subprocess.run([*base,str(f)], capture_output=True, text=True, timeout=15)
                    row['ok' if p.returncode==0 else 'failed']+=1
                except subprocess.TimeoutExpired: row['timeouts']+=1
        rows.append(row)
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps({'matrix':rows}, indent=2)+'\n')
    md=out.with_suffix('.md'); md.write_text('# Scanner Compatibility Matrix\n\n'+'\n'.join(f"- {r['tool']}: available={r['available']} ok={r['ok']} failed={r['failed']} timeouts={r['timeouts']}" for r in rows)+'\n')
    print(out)
if __name__=='__main__': main()
