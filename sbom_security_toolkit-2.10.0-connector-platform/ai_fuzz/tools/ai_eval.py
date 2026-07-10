#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(description='Evaluate AI fuzz providers in safe prompt/review mode.')
    ap.add_argument('--providers', default='none'); ap.add_argument('--out', default='reports/ai-fuzz/provider-eval.json')
    args=ap.parse_args(); rows=[]
    for provider in [x.strip() for x in args.providers.split(',') if x.strip()]:
        p=subprocess.run([sys.executable,'-m','ai_fuzz.tools.provider_test','--provider',provider], capture_output=True, text=True, timeout=30)
        rows.append({'provider':provider,'provider_test_exit':p.returncode,'prompt_only_safe': provider in {'none','prompt-only'} or p.returncode in {0,2},'stdout_tail':p.stdout[-500:],'stderr_tail':p.stderr[-500:]})
    report={'providers':rows,'scoring_notes':['valid JSON rate and human acceptance rate require reviewed outputs','unsafe suggestions must be rejected manually']}
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report,indent=2)+'\n'); print(out)
if __name__=='__main__': main()
