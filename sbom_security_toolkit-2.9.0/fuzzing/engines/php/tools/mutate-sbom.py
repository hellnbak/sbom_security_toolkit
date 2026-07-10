#!/usr/bin/env python3
"""Generate deterministic malformed SBOM variants for fuzzing seed corpora."""
from __future__ import annotations
import argparse, json
from pathlib import Path

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--out', default='fuzzing/generated-corpus/mutations'); args = ap.parse_args()
    raw = Path(args.sbom).read_text(errors='ignore'); out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    variants = {
        'truncated.seed': raw[:max(1, len(raw)//2)],
        'nul-bytes.seed': raw[:128] + '\x00' * 16 + raw[128:512],
        'deep-json.seed': '[' * 96 + '"x"' + ']' * 96,
        'huge-version.seed': '{"bomFormat":"CycloneDX","components":[{"name":"x","version":"' + ('9.' * 2048) + '"}]}',
    }
    try:
        doc = json.loads(raw)
        if isinstance(doc, dict):
            doc.pop('components', None); doc.pop('packages', None)
            variants['missing-components.seed'] = json.dumps(doc)
    except Exception: pass
    for name, content in variants.items(): (out/name).write_text(content)
    print(f'wrote {len(variants)} mutations under {out}')
    return 0
if __name__ == '__main__': raise SystemExit(main())
