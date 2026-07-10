#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
def count(path, pattern='*'):
    p=Path(path); return len([x for x in p.rglob(pattern) if x.is_file()]) if p.exists() else 0
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='reports/fuzzing/status.md'); a=ap.parse_args()
    targets=count('fuzzing/engines','*.py')+count('fuzzing/engines','*.js')+count('fuzzing/engines','*.php')
    md=f"# Fuzzing Status\n\n- Targets/harness files: {targets}\n- Regression seeds: {count('fuzzing/regression/corpus')}\n- AI incoming items: {count('ai_fuzz/review/incoming')}\n- Dictionaries: {count('fuzzing/dictionaries','*.dict')}\n- Campaign profiles: {count('fuzzing/campaigns','*.yml')}\n- Budget profiles: {count('fuzzing/budgets','*.yml')}\n\nGenerated locally by SBOM Security Toolkit.\n"
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(md); print(f'wrote {a.out}')
if __name__=='__main__': main()
