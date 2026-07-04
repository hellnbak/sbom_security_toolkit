#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path
from ai_fuzz.tools.providers import render_or_call
ROOT=Path(__file__).resolve().parents[2]
def main(argv=None):
    ap=argparse.ArgumentParser(description='Generate, audit, and repair fuzz harness drafts with review gates')
    ap.add_argument('--target', required=True); ap.add_argument('--provider', default='none'); ap.add_argument('--model', default=''); ap.add_argument('--out-dir', default='ai_fuzz/review/incoming/harness-quality-loop'); ns=ap.parse_args(argv)
    target=ROOT/ns.target; out=ROOT/ns.out_dir; out.mkdir(parents=True, exist_ok=True); code=target.read_text(errors='replace')[:12000] if target.exists() else ''
    prompt=f"Create a safe fuzz harness draft for {ns.target}. Rules: no network, no subprocesses, do not suppress unexpected exceptions, write only to temp dirs. Target excerpt:\n```\n{code}\n```"
    response=render_or_call(ns.provider, prompt, model=ns.model); draft=out/(Path(ns.target).stem+'_harness_draft.py'); draft.write_text(response+'\n')
    audit_out=out/'audit.json'; proc=subprocess.run([sys.executable,'fuzzing/harness/audit.py',str(draft),'--out',str(audit_out)],cwd=ROOT,text=True,capture_output=True)
    repair_prompt=f"Review this fuzz harness audit and suggest a minimal repair. Do not execute code.\nAudit:\n{audit_out.read_text(errors='replace') if audit_out.exists() else proc.stdout+proc.stderr}\nHarness:\n{draft.read_text(errors='replace')[:12000]}"
    (out/'repair_prompt.md').write_text(repair_prompt+'\n')
    summary={'draft':str(draft.relative_to(ROOT)),'audit_returncode':proc.returncode,'audit':json.loads(audit_out.read_text()) if audit_out.exists() else {}}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(json.dumps(summary, indent=2))
if __name__=='__main__': main()
