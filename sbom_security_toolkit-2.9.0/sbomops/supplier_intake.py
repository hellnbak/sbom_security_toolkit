#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_components, component_stats, write_json, write_markdown

def main():
    ap=argparse.ArgumentParser(description='Create a supplier SBOM intake review.')
    ap.add_argument('sbom'); ap.add_argument('--out-dir', default='reports/supplier-intake')
    args=ap.parse_args(); fmt, comps, meta=parse_components(args.sbom); stats=component_stats(comps,meta)
    asks=[]
    if stats['purl_percent']<90: asks.append('Provide package URLs for components missing package identifiers.')
    if stats['hash_percent']<50: asks.append('Provide component hashes or artifact checksums.')
    if not stats['dependency_graph_present']: asks.append('Provide dependency relationships / graph information.')
    if stats['license_percent']<80: asks.append('Clarify license metadata for components missing licenses.')
    if not meta.get('vulnerability_count'): asks.append('Provide VEX or vulnerability status statements for known CVEs affecting shipped components.')
    if stats['duplicate_components']: asks.append('Deduplicate repeated component records or explain why duplicates are intentional.')
    status='ACCEPTABLE' if len(asks)<=1 else 'NEEDS_FOLLOW_UP'
    result={'status':status,'format':fmt,'stats':stats,'vendor_followup_questions':asks}
    out=Path(args.out_dir); out.mkdir(parents=True, exist_ok=True); write_json(out/'supplier-intake.json',result); write_markdown(out/'supplier-intake.md',render(result)); print(f"Supplier intake: {status}")

def render(r):
    lines=['# Supplier SBOM Intake Report','',f"**Status:** {r['status']}",'','## Follow-up questions','']
    lines += [f"- {x}" for x in r['vendor_followup_questions']] or ['- No immediate follow-up questions generated.']
    lines += ['','## Summary','',f"- Components: {r['stats']['component_count']}",f"- Package URL coverage: {r['stats']['purl_percent']}%",f"- License coverage: {r['stats']['license_percent']}%",f"- Hash coverage: {r['stats']['hash_percent']}%",'']
    return '\n'.join(lines)
if __name__=='__main__': main()
