#!/usr/bin/env python3
from __future__ import annotations
import argparse, random
from pathlib import Path
BASE=["MIT","Apache-2.0","GPL-2.0-only OR MIT","(MIT OR Apache-2.0) AND BSD-3-Clause","LicenseRef-Internal","NOASSERTION"]
def mutate_expr(seed):
    r=random.Random(seed); e=r.choice(BASE); ops=[lambda x:f"({x}",lambda x:f"{x} AND",lambda x:x.replace("OR","AND OR"),lambda x:"("*20+x+")"*5,lambda x:x+" WITH Classpath-exception-2.0",lambda x:x+"\u0000"]
    return r.choice(ops)(e)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",required=True); ap.add_argument("--count",type=int,default=100); args=ap.parse_args(); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(args.count): (out/f"license-{i:04d}.txt").write_text(mutate_expr(i)+"\n")
    print(f"wrote license corpus to {out}")
if __name__=="__main__": main()
