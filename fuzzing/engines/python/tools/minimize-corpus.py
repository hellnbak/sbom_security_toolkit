#!/usr/bin/env python3
"""Simple corpus deduplicator by SHA-256. Engine-native minimization is still preferred."""
from __future__ import annotations
import argparse, hashlib, shutil
from pathlib import Path

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('corpus'); ap.add_argument('--out', required=True); args = ap.parse_args()
    src = Path(args.corpus); out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    seen = set(); copied = 0
    for p in sorted(src.rglob('*')):
        if not p.is_file(): continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        if h in seen: continue
        seen.add(h); shutil.copy2(p, out / f'{p.stem}-{h[:12]}{p.suffix or ".seed"}'); copied += 1
    print(f'copied {copied} unique files to {out}')
    return 0
if __name__ == '__main__': raise SystemExit(main())
