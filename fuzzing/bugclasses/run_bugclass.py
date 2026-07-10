#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
BUGS={
'parser-dos':['huge-version','dependency-cycle'],
'silent-component-drop':['duplicate-bom-ref','missing-version'],
'scanner-disagreement':['conflicting-identities','unicode'],
'vex-logic-error':['mixed-vex-state','contradictory-analysis'],
'license-policy-bypass':['invalid-license','NOASSERTION'],
'redaction-breakage':['internal-paths','repository-url-tricks']}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--bugclass',default='parser-dos'); ap.add_argument('--out',default='fuzzing/reports/bugclass/bugclass-plan.json')
    a=ap.parse_args(); data={'bugclass':a.bugclass,'seed_strategies':BUGS.get(a.bugclass,[]),'recommended_commands':['make fuzz-generate-cyclonedx EDGE=dependency-cycle','make fuzz-oracles','make fuzz-toolchain']}
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps(data,indent=2)+"\n"); print(f'wrote {a.out}')
if __name__=='__main__': main()
