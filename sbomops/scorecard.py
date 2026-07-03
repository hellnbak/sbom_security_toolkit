#!/usr/bin/env python3
from __future__ import annotations
import argparse, shutil, subprocess, json
from pathlib import Path
from .common import write_json, write_markdown

def main():
    ap=argparse.ArgumentParser(description='OpenSSF Scorecard wrapper/scaffold.')
    ap.add_argument('--repo', required=True); ap.add_argument('--out-dir', default='reports/openssf-scorecard'); ap.add_argument('--execute', action='store_true')
    args=ap.parse_args(); out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    available=shutil.which('scorecard') is not None
    result={'repo':args.repo,'scorecard_available':available,'executed':False,'note':'Install OpenSSF Scorecard and re-run with --execute to collect live results.'}
    if args.execute and available:
        p=subprocess.run(['scorecard','--repo',args.repo,'--format','json'],capture_output=True,text=True,timeout=240)
        result.update({'executed':True,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    write_json(out/'openssf-scorecard.json',result); write_markdown(out/'openssf-scorecard.md',f"# OpenSSF Scorecard\n\nRepo: `{args.repo}`\n\nAvailable: `{available}`\n\nExecuted: `{result['executed']}`\n\n")
    print(f"Wrote {out/'openssf-scorecard.md'}")
if __name__=='__main__': main()
