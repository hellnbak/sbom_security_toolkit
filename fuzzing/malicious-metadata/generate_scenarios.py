#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
SCENARIOS=[
 {"name":"typosquat-lodash","purl":"pkg:npm/l0dash@4.17.21","risk":"typosquatting"},
 {"name":"dependency-confusion-placeholder-name","purl":"pkg:npm/internal-build-utils@99.99.99","risk":"dependency-confusion"},
 {"name":"unicode-homoglyph","purl":"pkg:pypi/reqυests@2.31.0","risk":"homoglyph"},
 {"name":"repo-url-trick","purl":"pkg:npm/example@1.0.0?repository_url=https://github.com/example/%2e%2e/private","risk":"repository-url-trick"},
 {"name":"license-spoof","purl":"pkg:pypi/package@1.0.0","license":"MIT OR GPL-3.0-only AND","risk":"license-expression-edge"}
]
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",default="fuzzing/generated-corpus/malicious-metadata"); args=ap.parse_args(); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    for i,s in enumerate(SCENARIOS):
        bom={"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":s["name"],"version":"1.0.0","purl":s["purl"],"licenses":[{"license":{"id":s.get("license","MIT")}}],"properties":[{"name":"scenario","value":s["risk"]}]}]}
        (out/f"scenario-{i:02d}-{s['risk']}.json").write_text(json.dumps(bom,indent=2)+"\n")
    print(f"wrote {len(SCENARIOS)} scenarios to {out}")
if __name__=="__main__": main()
