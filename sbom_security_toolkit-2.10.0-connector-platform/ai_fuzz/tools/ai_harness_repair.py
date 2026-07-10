#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--target',required=True); ap.add_argument('--log',default=''); ap.add_argument('--out',default='ai_fuzz/review/incoming/harness-repair-suggestion.md')
    a=ap.parse_args(); target=Path(a.target); code=target.read_text(errors='replace')[:4000] if target.exists() else ''; log=Path(a.log).read_text(errors='replace')[:4000] if a.log and Path(a.log).exists() else ''
    md=f"# AI Harness Repair Prompt\n\nTarget: `{a.target}`\n\n## Instructions\n\nSuggest a minimal patch to make this fuzz harness build and run. Do not add network access or execute untrusted inputs outside the harness boundary. Return a unified diff and a short explanation.\n\n## Harness excerpt\n\n```\n{code}\n```\n\n## Build/test log excerpt\n\n```\n{log or 'No log supplied.'}\n```\n"
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(md); print(f'wrote {a.out}')
if __name__=='__main__': main()
