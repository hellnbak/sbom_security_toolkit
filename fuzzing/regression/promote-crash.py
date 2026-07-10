#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, shutil
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("crash"); ap.add_argument("--corpus",default="fuzzing/regression/corpus"); args=ap.parse_args(); src=Path(args.crash)
    if not src.exists(): raise SystemExit(f"not found: {src}")
    data=src.read_bytes(); suffix=src.suffix or ".bin"; dst=Path(args.corpus)/("regression-"+hashlib.sha256(data).hexdigest()[:12]+suffix); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dst); print(dst)
if __name__=="__main__": main()
