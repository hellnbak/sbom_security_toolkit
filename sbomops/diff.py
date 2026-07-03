#!/usr/bin/env python3
from __future__ import annotations
import argparse
from .common import parse_components, write_json, write_markdown

def key(c): return c.purl or c.key()
def main():
    ap=argparse.ArgumentParser(description='Diff two SBOMs by component identity.'); ap.add_argument('old'); ap.add_argument('new'); ap.add_argument('--out-dir',default='reports/sbom-experience/diff')
    a=ap.parse_args(); _, old, _=parse_components(a.old); _, new, _=parse_components(a.new)
    om={key(c):c for c in old}; nm={key(c):c for c in new}
    added=sorted(set(nm)-set(om)); removed=sorted(set(om)-set(nm)); common=set(om)&set(nm)
    changed=[k for k in common if om[k].version!=nm[k].version]
    data={'added':added,'removed':removed,'changed_versions':[{'component':k,'old':om[k].version,'new':nm[k].version} for k in changed]}
    write_json(f'{a.out_dir}/sbom-diff.json',data)
    md=f"# SBOM Diff\n\n- Added: {len(added)}\n- Removed: {len(removed)}\n- Version changes: {len(changed)}\n"
    write_markdown(f'{a.out_dir}/sbom-diff.md',md); print(f'wrote {a.out_dir}')
if __name__=='__main__': main()
