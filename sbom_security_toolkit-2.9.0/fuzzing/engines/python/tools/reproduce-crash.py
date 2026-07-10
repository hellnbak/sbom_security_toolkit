#!/usr/bin/env python3
"""Print the best reproducer command for a saved crash artifact."""
from __future__ import annotations
import argparse, json
from pathlib import Path

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('crash'); args = ap.parse_args()
    crash = Path(args.crash); meta_path = crash.parent / 'metadata.json'
    if not meta_path.exists():
        print(f'No metadata.json next to {crash}. Run the matching engine replay command manually.'); return 2
    meta = json.loads(meta_path.read_text()); target = meta.get('target'); engine = meta.get('engine')
    print(f'Target: {target}\nEngine: {engine}\nCrash:  {crash}')
    if engine == 'python':
        print(f'docker run --rm -v "$PWD/fuzzing/findings:/fuzz/findings" --entrypoint python3 sbom-fuzzer-python /fuzz/targets/{target}.py /fuzz/findings/{target}/{crash.name}')
    elif engine == 'javascript':
        print(f'docker run --rm -v "$PWD/fuzzing/findings:/fuzz/findings" --entrypoint npx sbom-fuzzer-javascript jazzer --reproduce=/fuzz/findings/{target}/{crash.name} /fuzz/targets/{target}.js')
    elif engine == 'php':
        print(f'docker run --rm -v "$PWD/fuzzing/findings:/fuzz/findings" --entrypoint php-fuzzer sbom-fuzzer-php run-single /fuzz/targets/{target}.php /fuzz/findings/{target}/{crash.name}')
    else:
        print('Unknown engine; inspect reproducer.sh in the crash directory.')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
