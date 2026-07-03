#!/usr/bin/env python3
"""Build SBOM-focused seed corpora from CycloneDX JSON/XML or SPDX JSON."""
from __future__ import annotations
import argparse, hashlib, json, xml.etree.ElementTree as ET
from pathlib import Path

def stable_write(outdir: Path, name: str, data: bytes) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:12]
    (outdir / f'{name}-{digest}.seed').write_bytes(data)

def load_sbom(path: Path):
    raw = path.read_bytes(); text = raw.decode('utf-8', errors='ignore')
    try: return 'json', json.loads(text), raw
    except Exception: pass
    try: return 'xml', ET.fromstring(raw), raw
    except Exception: return 'raw', text, raw

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('sbom'); ap.add_argument('--out', default='fuzzing/generated-corpus'); args = ap.parse_args()
    kind, doc, raw = load_sbom(Path(args.sbom)); out = Path(args.out)
    stable_write(out/'raw', 'original', raw)
    if kind == 'json' and isinstance(doc, dict):
        fmt = 'cyclonedx' if doc.get('bomFormat') == 'CycloneDX' else 'spdx' if 'spdxVersion' in doc else 'json'
        stable_write(out/f'{fmt}_json', 'document', json.dumps(doc, separators=(',', ':')).encode())
        components = doc.get('components') or doc.get('packages') or []
        if isinstance(components, list):
            for i, comp in enumerate(components[:100]):
                stable_write(out/'components', f'component-{i}', json.dumps(comp, separators=(',', ':')).encode())
                if isinstance(comp, dict):
                    purl = comp.get('purl')
                    refs = comp.get('externalRefs')
                    if not purl and isinstance(refs, list) and refs and isinstance(refs[0], dict):
                        purl = refs[0].get('referenceLocator')
                    if isinstance(purl, str) and purl.startswith('pkg:'):
                        stable_write(out/'purl', f'purl-{i}', purl.encode())
                    lic = comp.get('licenseDeclared') or comp.get('licenseConcluded')
                    if isinstance(lic, str):
                        stable_write(out/'license', f'license-{i}', lic.encode())
    elif kind == 'xml':
        stable_write(out/'cyclonedx_xml', 'document', raw)
        for i, elem in enumerate(list(doc.iter())[:200]):
            try: stable_write(out/'xml-fragments', f'element-{i}', ET.tostring(elem))
            except Exception: pass
    edge_cases = {
        'deep-array': b'[' * 64 + b'0' + b']' * 64,
        'unicode-purl': 'pkg:npm/☃@１.０.０?arch=arm64'.encode('utf-8'),
        'license-nesting': b'(' * 32 + b'MIT OR Apache-2.0' + b')' * 32,
        'xml-entity': b'<?xml version="1.0"?><bom><components><component><name>&unknown;</name></component></components></bom>',
    }
    for name, data in edge_cases.items(): stable_write(out/'edge-cases', name, data)
    print(f'wrote corpus seeds under {out}')
    return 0
if __name__ == '__main__': raise SystemExit(main())
