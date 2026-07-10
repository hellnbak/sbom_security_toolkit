#!/usr/bin/env python3
"""Normalize fuzzer crash artifacts into a consistent metadata + reproducer layout."""
from __future__ import annotations
import argparse, hashlib, json, stat, time
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--engine', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--target-file', required=True)
    ap.add_argument('--crash-dir', required=True)
    args = ap.parse_args()
    crash_dir = Path(args.crash_dir)
    crashes = sorted([p for p in crash_dir.glob('crash-*') if p.is_file()])
    for crash in crashes:
        digest = sha256(crash)
        meta = {
            'target': args.target,
            'engine': args.engine,
            'target_file': args.target_file,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'input_file': crash.name,
            'input_sha256': digest,
            'input_size': crash.stat().st_size,
            'reproducer': 'reproducer.sh',
        }
        (crash_dir / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
        repro = crash_dir / 'reproducer.sh'
        if args.engine == 'python':
            cmd = f'python3 "{args.target_file}" "{crash}"'
        elif args.engine == 'javascript':
            cmd = f'npx jazzer --reproduce="{crash}" "{args.target_file}"'
        elif args.engine == 'php':
            cmd = f'php-fuzzer run-single "{args.target_file}" "{crash}"'
        else:
            cmd = 'echo "Unknown engine"; exit 2'
        repro.write_text('#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")"\n'
                         f'echo "Reproducing {args.engine} crash for target {args.target}"\n'
                         f'echo "Input: {crash.name}"\n'
                         f'echo "SHA256: {digest}"\n'
                         '# Run this inside the matching fuzzing container, or adapt for local tooling.\n'
                         f'{cmd}\n')
        repro.chmod(repro.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
