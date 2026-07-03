#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path

def classify(p:Path):
    raw=p.read_bytes(); txt=raw.decode('utf-8','ignore')
    score=sum(txt.count(x) for x in ['components','dependencies','purl','SPDXID','vulnerabilities','analysis'])
    label='keep' if score>=2 else 'review'
    if len(raw)>2_000_000: label='reject-large'
    return {'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'signal_score':score,'recommendation':label,'reason':'SBOM tokens present' if score>=2 else 'low SBOM structure signal'}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--corpus',default='fuzzing/corpus/ai/incoming'); ap.add_argument('--out',default='ai_fuzz/review/incoming/corpus-review.json')
    a=ap.parse_args(); root=Path(a.corpus); items=[classify(p) for p in root.rglob('*') if p.is_file()] if root.exists() else []
    Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps({'corpus':str(root),'items':items},indent=2)+"\n"); print(f'wrote {a.out}')
if __name__=='__main__': main()
