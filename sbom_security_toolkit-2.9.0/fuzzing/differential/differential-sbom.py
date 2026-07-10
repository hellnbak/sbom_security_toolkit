#!/usr/bin/env python3
"""Differential SBOM parser/scanner harness.

Runs whatever tools are installed locally and records whether they accept,
reject, or fail on the same SBOM input. This intentionally does not install
or download tools for the user.
"""
from __future__ import annotations
import argparse, json, shutil, subprocess, time
from pathlib import Path

COMMANDS = {
    'python-json': ['python3', '-c', 'import json,sys; json.load(open(sys.argv[1])); print("json-ok")'],
    'trivy-sbom': ['trivy', 'sbom'],
    'grype-sbom': ['grype'],
    'syft-sbom': ['syft', 'scan'],
    'cyclonedx-cli-validate': ['cyclonedx', 'validate', '--input-file'],
}

def run_tool(name: str, base_cmd: list[str], sbom: Path, timeout: int):
    exe = base_cmd[0]
    if shutil.which(exe) is None:
        return {'tool': name, 'status': 'missing', 'command': base_cmd}
    cmd = base_cmd + [str(sbom)]
    start = time.time()
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return {'tool': name, 'status': 'accepted' if cp.returncode == 0 else 'rejected', 'returncode': cp.returncode, 'seconds': round(time.time()-start, 3), 'stdout_tail': cp.stdout[-2000:], 'stderr_tail': cp.stderr[-2000:], 'command': cmd}
    except subprocess.TimeoutExpired:
        return {'tool': name, 'status': 'timeout', 'seconds': timeout, 'command': cmd}
    except Exception as e:
        return {'tool': name, 'status': 'error', 'error': repr(e), 'command': cmd}

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--out', default='fuzzing/reports/differential-report.json'); ap.add_argument('--timeout', type=int, default=60); args = ap.parse_args()
    sbom = Path(args.sbom)
    results = [run_tool(name, cmd, sbom, args.timeout) for name, cmd in COMMANDS.items()]
    report = {'sbom': str(sbom), 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'results': results}
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report, indent=2) + '\n')
    print(f'wrote {out}')
    return 1 if any(r['status'] in ('timeout','error') for r in results) else 0
if __name__ == '__main__': raise SystemExit(main())
