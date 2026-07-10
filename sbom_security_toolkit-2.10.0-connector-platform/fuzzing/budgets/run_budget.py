#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re,subprocess
from pathlib import Path

def parse_simple_yaml(p:Path):
    data={}; current=None
    for line in p.read_text().splitlines():
        if not line.strip() or line.strip().startswith('#'): continue
        if re.match(r'^[A-Za-z_].*:',line):
            k,v=line.split(':',1); k=k.strip(); v=v.strip();
            if v: data[k]=int(v) if v.isdigit() else v
            else: data[k]=[]; current=k
        elif line.strip().startswith('-') and current:
            data[current].append(line.strip()[1:].strip())
    return data

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('profile'); ap.add_argument('--out',default='fuzzing/reports/budget-run.json')
    a=ap.parse_args(); prof=parse_simple_yaml(Path(a.profile)); results=[]
    for t in prof.get('targets',[]):
        results.append({'target':t,'planned_duration_seconds':prof.get('duration_seconds'),'status':'planned'})
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps({'profile':prof,'results':results},indent=2)+"\n"); print(f'wrote {a.out}')
if __name__=='__main__': main()
