#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,json
from pathlib import Path
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('sbom',nargs='?',default='test-sboms/clean/minimal-cyclonedx.json'); ap.add_argument('--out',default='fuzzing/generated-corpus/schema/dependency-track-payloads'); ap.add_argument('--count',type=int,default=5)
    a=ap.parse_args(); raw=Path(a.sbom).read_bytes(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(a.count):
        payload={"projectName":f"fuzz-project-{i}","projectVersion":"1.0.0","autoCreate":True,"bom":base64.b64encode(raw + (b" "*i)).decode()}
        (out/f'dtrack-upload-{i:04d}.json').write_text(json.dumps(payload,indent=2)+"\n")
    print(f'wrote {a.count} Dependency-Track payloads to {out}')
if __name__=='__main__': main()
