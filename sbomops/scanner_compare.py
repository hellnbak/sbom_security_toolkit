#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, subprocess
from pathlib import Path
from .common import write_json, write_markdown

def run(cmd):
    try:
        p=subprocess.run(cmd, text=True, capture_output=True, timeout=180)
        return {'cmd':' '.join(cmd),'returncode':p.returncode,'stdout':p.stdout[-20000:],'stderr':p.stderr[-20000:]}
    except Exception as e:
        return {'cmd':' '.join(cmd),'returncode':999,'stdout':'','stderr':str(e)}

def extract_ids(result):
    text=(result.get('stdout','')+'\n'+result.get('stderr',''))
    import re
    return sorted(set(m.group(0).upper() for m in re.finditer(r'CVE-\d{4}-\d{4,}', text, re.I)))

def main():
    ap=argparse.ArgumentParser(description='Compare scanner output for a single SBOM.')
    ap.add_argument('sbom'); ap.add_argument('--out-dir', default='reports/scanner-compare'); ap.add_argument('--execute', action='store_true', help='Actually run installed scanners. Default only reports availability.')
    args=ap.parse_args(); out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    scanners={
      'trivy':['trivy','sbom','--format','json',args.sbom],
      'grype':['grype',args.sbom,'-o','json'],
      'osv-scanner':['osv-scanner','--sbom',args.sbom,'--format','json']
    }
    results={}
    for name,cmd in scanners.items():
        available=shutil.which(cmd[0]) is not None
        if args.execute and available: results[name]=run(cmd)
        else: results[name]={'available':available,'cmd':' '.join(cmd),'returncode':None,'stdout':'','stderr':'not executed'}
        results[name]['cves']=extract_ids(results[name])
    all_cves=sorted({c for r in results.values() for c in r.get('cves',[])})
    result={'sbom':args.sbom,'scanner_results':results,'all_cves':all_cves,'agreement':{c:[n for n,r in results.items() if c in r.get('cves',[])] for c in all_cves}}
    write_json(out/'scanner-compare.json', result); write_markdown(out/'scanner-compare.md', render(result)); print(f"Wrote {out/'scanner-compare.md'}")

def render(r):
    lines=['# Scanner Comparison Report','',f"SBOM: `{r['sbom']}`",'', '| Scanner | Available | CVEs found |','|---|---:|---:|']
    for n,v in r['scanner_results'].items(): lines.append(f"| {n} | {v.get('available','executed')} | {len(v.get('cves',[]))} |")
    lines += ['','## Scanner Agreement','']
    lines += [f"- {c}: {', '.join(names)}" for c,names in r['agreement'].items()] or ['- No CVEs extracted from scanner output.']
    lines += ['','> Tip: run with `--execute` on a host where Trivy, Grype, and/or OSV-Scanner are installed.','']
    return '\n'.join(lines)
if __name__=='__main__': main()
