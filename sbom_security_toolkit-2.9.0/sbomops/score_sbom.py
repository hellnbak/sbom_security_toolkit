#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from .common import parse_components, component_stats, write_json, write_markdown

def score(stats):
    points = 0
    max_points = 100
    points += min(stats['version_percent'], 100) * 0.15
    points += min(stats['purl_percent'], 100) * 0.20
    points += min(stats['license_percent'], 100) * 0.15
    points += min(stats['hash_percent'], 100) * 0.15
    points += min(stats['supplier_percent'], 100) * 0.10
    points += 10 if stats['dependency_graph_present'] else 0
    points += 5 if stats['component_count'] > 0 else 0
    points += max(0, 5 - stats['duplicate_components'])
    points += max(0, 5 - stats['invalid_purls'])
    return round(max(0, min(max_points, points)), 1)

def grade(value):
    if value >= 90: return 'A'
    if value >= 80: return 'B'
    if value >= 70: return 'C'
    if value >= 60: return 'D'
    return 'F'

def main():
    ap = argparse.ArgumentParser(description='Score SBOM quality and completeness.')
    ap.add_argument('sbom')
    ap.add_argument('--out-dir', default='reports/sbom-quality')
    args = ap.parse_args()
    fmt, comps, meta = parse_components(args.sbom)
    stats = component_stats(comps, meta)
    value = score(stats)
    result = {'score': value, 'grade': grade(value), 'format': fmt, 'metadata': meta, 'stats': stats,
              'recommendations': recommendations(stats)}
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    write_json(out/'sbom-quality.json', result)
    write_markdown(out/'sbom-quality.md', render_md(result))
    print(f"SBOM Quality Score: {value}/100 ({grade(value)})")
    print(f"Wrote {out/'sbom-quality.md'} and {out/'sbom-quality.json'}")

def recommendations(stats):
    recs=[]
    if not stats['dependency_graph_present']: recs.append('Add dependency relationships so direct/transitive risk can be distinguished.')
    if stats['purl_percent'] < 90: recs.append('Add package URLs (purl) to improve vulnerability matching across scanners.')
    if stats['hash_percent'] < 50: recs.append('Add component hashes for stronger artifact identity and supplier intake confidence.')
    if stats['license_percent'] < 80: recs.append('Improve license metadata for compliance and release-review workflows.')
    if stats['supplier_percent'] < 50: recs.append('Add supplier/author metadata to improve supplier and product-security reviews.')
    if stats['duplicate_components']: recs.append(f"Deduplicate {stats['duplicate_components']} component entries.")
    if stats['invalid_purls']: recs.append(f"Fix {stats['invalid_purls']} malformed package URLs.")
    return recs or ['SBOM has strong baseline metadata. Consider adding VEX and release provenance.']

def render_md(r):
    s=r['stats']
    lines=[f"# SBOM Quality Report",'',f"**Score:** {r['score']}/100 ({r['grade']})",f"**Format:** {r['format']}",'', '## Metrics','', '| Metric | Value |','|---|---|']
    for k in ['component_count','version_percent','purl_percent','license_percent','hash_percent','supplier_percent','duplicate_components','invalid_purls','dependency_graph_present']:
        lines.append(f"| {k.replace('_',' ')} | {s.get(k)} |")
    lines += ['', '## Recommendations',''] + [f"- {x}" for x in r['recommendations']] + ['']
    return '\n'.join(lines)
if __name__ == '__main__': main()
