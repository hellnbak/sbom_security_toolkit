#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,uuid
from pathlib import Path
STATES=['affected','not_affected','fixed','under_investigation']
JUST=['component_not_present','vulnerable_code_not_present','vulnerable_code_not_in_execute_path','protected_by_compiler','protected_at_runtime']
def make_vex(i:int,state:str):
    return {"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:"+str(uuid.uuid4()),"version":1,"metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"application","name":"example-product","version":"1.0.0"}},"vulnerabilities":[{"id":f"CVE-2099-{1000+i}","source":{"name":"NVD"},"affects":[{"ref":"pkg:pypi/example@1.0.0"}],"analysis":{"state":state,"justification":JUST[i%len(JUST)] if state=='not_affected' else None,"response":["will_not_fix" if state=='not_affected' else "update"],"detail":"Generated VEX fuzz seed for semantic testing."}}]}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='fuzzing/generated-corpus/schema/vex'); ap.add_argument('--count',type=int,default=16); ap.add_argument('--state',default='mixed')
    a=ap.parse_args(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(a.count):
        state = STATES[i%len(STATES)] if a.state=='mixed' else a.state
        (out/f'vex-{state}-{i:04d}.json').write_text(json.dumps(make_vex(i,state),indent=2)+"\n")
    print(f'wrote {a.count} VEX seeds to {out}')
if __name__=='__main__': main()
