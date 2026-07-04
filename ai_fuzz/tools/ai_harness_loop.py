#!/usr/bin/env python3
from __future__ import annotations
import argparse, subprocess, sys
from pathlib import Path
from .ai_fuzz import write_artifact, call_or_prompt, prompt_header


def main():
    ap=argparse.ArgumentParser(description='Draft an AI fuzz harness and capture syntax/build feedback for review.')
    ap.add_argument('--target', required=True); ap.add_argument('--provider', default='none'); ap.add_argument('--model', default='')
    args=ap.parse_args()
    target=Path(args.target)
    excerpt=target.read_text(errors='replace')[:8000] if target.exists() else f'Missing target: {target}'
    prompt=prompt_header('Iterative fuzz harness generation and repair') + f"\n\nTarget: {target}\n\nCode excerpt:\n```\n{excerpt}\n```\nDraft a safe fuzz harness, smoke command, and repair checklist. Do not execute generated code automatically."
    result=call_or_prompt(prompt, provider=args.provider, model=args.model)
    feedback='No automatic generated-code build executed. Human review required.'
    if target.suffix=='.py' and target.exists():
        proc=subprocess.run([sys.executable,'-m','py_compile',str(target)], capture_output=True, text=True)
        feedback=f'py_compile returncode={proc.returncode}\nSTDERR:\n{proc.stderr[-4000:]}'
    files={'prompt.md':prompt+'\n','build-feedback.txt':feedback+'\n'}
    if result.get('text'): files['model-output.md']=result['text']
    out=write_artifact('harness-loop', files, {'kind':'ai-harness-loop','provider':result,'target':str(target)})
    print(out)
    return 0
if __name__=='__main__': raise SystemExit(main())
