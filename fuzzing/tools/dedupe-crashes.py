#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

def fingerprint(path: Path):
    data=path.read_bytes()
    text=data.decode(errors="replace")
    norm=re.sub(r"0x[0-9a-fA-F]+","0xADDR",text)
    norm=re.sub(r"line \d+","line N",norm)
    return hashlib.sha256(norm[:4000].encode()).hexdigest()[:16]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="fuzzing/findings"); ap.add_argument("--out",default="fuzzing/reports/crash-dedupe.json"); args=ap.parse_args()
    root=Path(args.root); groups={}
    for p in root.rglob("*") if root.exists() else []:
        if p.is_file() and any(x in p.name.lower() for x in ["crash","stack","stderr","trace"]):
            fp=fingerprint(p); groups.setdefault(fp,[]).append(str(p))
    report={"root":str(root),"unique_crashes":len(groups),"total_artifacts":sum(len(v) for v in groups.values()),"groups":[{"fingerprint":k,"artifacts":v} for k,v in sorted(groups.items())]}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(json.dumps(report,indent=2)+"\n"); print(json.dumps(report,indent=2))
if __name__=="__main__": main()
