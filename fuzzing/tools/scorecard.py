#!/usr/bin/env python3
"""Generate a simple fuzzing scorecard from findings directories."""
from __future__ import annotations
import argparse, json
from pathlib import Path

def count_files(path: Path, pattern: str) -> int:
    return len([p for p in path.glob(pattern) if p.is_file()]) if path.exists() else 0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('findings', nargs='?', default='fuzzing/findings')
    ap.add_argument('--output', default='fuzzing/reports/fuzz-scorecard.md')
    args = ap.parse_args()
    findings = Path(args.findings)
    rows = []
    if findings.exists():
        for target_dir in sorted(p for p in findings.iterdir() if p.is_dir()):
            meta_path = target_dir / 'metadata.json'
            meta = {}
            if meta_path.exists():
                try: meta = json.loads(meta_path.read_text())
                except Exception: meta = {}
            rows.append((target_dir.name, meta.get('engine','unknown'), count_files(target_dir/'corpus','*'), count_files(target_dir,'crash-*'), count_files(target_dir,'timeout-*'), 'yes' if (target_dir/'fuzz.log').exists() else 'no'))
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    lines = ['# Fuzzing Scorecard', '', '| Target | Engine | Corpus Files | Crashes | Timeouts | Log |', '|---|---:|---:|---:|---:|---|']
    if rows:
        lines += ['| ' + ' | '.join(map(str, row)) + ' |' for row in rows]
    else:
        lines.append('| _none yet_ | - | 0 | 0 | 0 | no |')
    out.write_text('\n'.join(lines) + '\n')
    print(f'wrote {out}')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
