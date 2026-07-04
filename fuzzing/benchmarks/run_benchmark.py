#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path

def run(name, cmd):
    start=time.time(); p=subprocess.run(cmd, text=True, capture_output=True, timeout=120)
    return {'name':name,'returncode':p.returncode,'seconds':round(time.time()-start,2),'stdout_tail':p.stdout[-1000:],'stderr_tail':p.stderr[-1000:]}

def main():
    ap=argparse.ArgumentParser(description='Run a fixed local fuzzing benchmark suite.')
    ap.add_argument('--sbom', default='test-sboms/clean/minimal-cyclonedx.json'); ap.add_argument('--out', default='reports/fuzzing/benchmarks/latest.json')
    args=ap.parse_args(); out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    steps=[
      ('schema-cyclonedx',[sys.executable,'fuzzing/schema/cyclonedx_schema_generator.py','--count','3']),
      ('semantic-oracles',[sys.executable,'fuzzing/oracles/semantic_oracles.py',args.sbom,'--out','reports/fuzzing/benchmark-oracles.json']),
      ('roundtrip',[sys.executable,'fuzzing/roundtrip/roundtrip_sbom.py',args.sbom,'--out-dir','reports/fuzzing/benchmark-roundtrip']),
      ('metamorphic-scanners',[sys.executable,'fuzzing/scanner-metamorphic/metamorphic_scanners.py',args.sbom]),
    ]
    results=[run(n,c) for n,c in steps]
    report={'runtime_seconds':sum(x['seconds'] for x in results),'targets_tested':len(results),'results':results}
    out.write_text(json.dumps(report, indent=2)+'\n'); print(out)
if __name__=='__main__': main()
