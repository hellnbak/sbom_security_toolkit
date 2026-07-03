#!/usr/bin/env python3
from __future__ import annotations
import argparse
from .common import parse_components, component_stats, write_markdown

def main():
    ap=argparse.ArgumentParser(description='Explain an SBOM in human-readable terms.'); ap.add_argument('sbom'); ap.add_argument('--out',default='reports/sbom-experience/explanation.md')
    a=ap.parse_args(); fmt, comps, meta=parse_components(a.sbom); s=component_stats(comps,meta)
    lines=['# SBOM Explanation','',f'- Detected format: **{fmt}**',f'- Components: **{s["component_count"]}**',f'- Ecosystems: {", ".join(s["ecosystems"]) or "unknown"}',f'- Dependency graph present: **{s["dependency_graph_present"]}**',f'- Components with versions: **{s["version_percent"]}%**',f'- Components with package URLs: **{s["purl_percent"]}%**',f'- Components with licenses: **{s["license_percent"]}%**',f'- Components with hashes: **{s["hash_percent"]}%**','','## What this means','']
    if not s['dependency_graph_present']: lines.append('- The SBOM lists components but does not describe dependency relationships. This limits reachability, direct/transitive triage, and supplier intake confidence.')
    if s['purl_percent'] < 80: lines.append('- Many components lack package URLs, which can reduce scanner accuracy and create disagreement between tools.')
    if s['hash_percent'] < 20: lines.append('- Few components include hashes, so artifact integrity and exact component identification are weak.')
    if s['duplicate_components']: lines.append(f'- There are {s["duplicate_components"]} duplicate component identity candidates that should be reviewed.')
    if len(lines)<14: lines.append('- This SBOM has enough basic metadata for demonstration workflows. Run policy and scanner comparison for release decisions.')
    write_markdown(a.out,'\n'.join(lines)+'\n'); print(f'wrote {a.out}')
if __name__=='__main__': main()
