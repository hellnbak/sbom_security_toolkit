#!/usr/bin/env python3
from __future__ import annotations
import argparse, random
from pathlib import Path
CASES=["pkg:npm/lodash@4.17.21","pkg:npm/%40scope/name@1.0.0","pkg:pypi/requests@2.31.0","pkg:deb/debian/openssl@1.1.1?arch=amd64","pkg:maven/group/artifact@1.0.0","pkg:generic/name@version#subpath","pkg:npm/name@","pkg:/missing/type","pkg:npm/%zz@1.0.0","pkg:npm/name@1.0.0?download_url=https://example.invalid/a b"]
def mutate_purl(s, seed=0):
    r=random.Random(seed); ops=[lambda x:x.upper(), lambda x:x.replace("/","//",1), lambda x:x+"?"+"a="+"x"*500, lambda x:x.replace("@","%40",1), lambda x:x+"#"+"../"*20, lambda x:r.choice(CASES)]
    return r.choice(ops)(s)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",required=True); ap.add_argument("--count",type=int,default=100); args=ap.parse_args(); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(args.count): (out/f"purl-{i:04d}.txt").write_text(mutate_purl(random.choice(CASES),i)+"\n")
    print(f"wrote purl corpus to {out}")
if __name__=="__main__": main()
