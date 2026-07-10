#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, zipfile, hashlib
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(description='Create a portable replay pack for a fuzzing finding/crash/input.')
    ap.add_argument('finding'); ap.add_argument('--out-dir', default='reports/fuzzing/replay-pack')
    args=ap.parse_args(); src=Path(args.finding); out=Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    if src.exists() and src.is_file(): shutil.copy2(src,out/'input.sbom')
    meta={'source':str(src),'sha256':hashlib.sha256(src.read_bytes()).hexdigest() if src.exists() and src.is_file() else '', 'note':'Human review required before disclosure.'}
    (out/'expected-result.json').write_text(json.dumps(meta,indent=2)+'\n')
    (out/'README.md').write_text('# Fuzz Replay Pack\n\nRun `./reproduce.sh` from the repository root after reviewing the input.\n')
    (out/'reproduce.sh').write_text('#!/usr/bin/env bash\nset -euo pipefail\npython3 fuzzing/oracles/semantic_oracles.py "$(dirname "$0")/input.sbom" --out replay-oracles.json\n')
    (out/'reproduce.sh').chmod(0o755)
    z=out.with_suffix('.zip')
    with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as pack:
        for f in out.rglob('*'):
            if f.is_file(): pack.write(f, f.relative_to(out))
    print(z)
if __name__=='__main__': main()
