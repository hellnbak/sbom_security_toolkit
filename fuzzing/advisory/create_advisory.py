#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('crash'); ap.add_argument('--out-dir',default='advisories/draft')
    a=ap.parse_args(); c=Path(a.crash); raw=c.read_bytes() if c.exists() else b''; h=hashlib.sha256(raw).hexdigest()[:12]; out=Path(a.out_dir); out.mkdir(parents=True,exist_ok=True)
    (out/'impact-summary.md').write_text(f"# Fuzz Finding Impact Summary\n\nCrash input: `{c}`\n\nInput SHA256 prefix: `{h}`\n\n## Potential impact\n\nReview whether this causes parser denial of service, silent SBOM data loss, scanner disagreement, or policy bypass.\n")
    (out/'reproducer.sh').write_text(f"#!/usr/bin/env bash\nset -euo pipefail\npython3 fuzzing/tools/reproduce-crash.py {c}\n")
    (out/'draft.md').write_text(f"# Draft Advisory\n\n## Summary\n\nA fuzzing campaign identified an issue while processing an SBOM-like input.\n\n## Affected component\n\nTBD\n\n## Reproduction\n\nRun `./reproducer.sh`.\n\n## Evidence\n\nCrash input SHA256 prefix: `{h}`\n\n## Remediation\n\nAdd validation, cycle detection, size limits, or parser error handling as applicable.\n")
    print(f'wrote advisory draft to {out}')
if __name__=='__main__': main()
