#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, html
from pathlib import Path
from .common import parse_components, component_stats, parse_vuln_report, write_json, write_markdown, write_csv
from .score_sbom import score, grade, recommendations

def main():
    ap=argparse.ArgumentParser(description='Generate executive, engineering, and supplier SBOM reports.')
    ap.add_argument('sbom'); ap.add_argument('--vulns'); ap.add_argument('--policy-result'); ap.add_argument('--out-dir', default='reports/bundle')
    args=ap.parse_args(); out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    fmt, comps, meta=parse_components(args.sbom); stats=component_stats(comps,meta); q=score(stats); vulns=parse_vuln_report(args.vulns) if args.vulns else []
    data={'sbom':args.sbom,'format':fmt,'quality_score':q,'quality_grade':grade(q),'stats':stats,'vulnerability_count':len(vulns),'recommendations':recommendations(stats)}
    write_json(out/'summary.json', data)
    write_csv(out/'components.csv', [c.__dict__ for c in comps])
    write_csv(out/'vulnerabilities.csv', [v.__dict__ for v in vulns])
    md=render_md(data, comps, vulns); write_markdown(out/'executive-summary.md', md); write_markdown(out/'engineering-remediation.md', render_eng(vulns)); write_markdown(out/'supplier-followup.md', render_supplier(data)); (out/'index.html').write_text(render_html(md), encoding='utf-8')
    print(f"Report bundle written to {out}")

def render_md(data, comps, vulns):
    return '\n'.join(['# SBOM Risk Summary','',f"**SBOM:** `{data['sbom']}`",f"**Format:** {data['format']}",f"**Quality:** {data['quality_score']}/100 ({data['quality_grade']})",f"**Components:** {data['stats']['component_count']}",f"**Vulnerabilities in supplied report:** {len(vulns)}",'', '## Recommended actions','']+[f"- {r}" for r in data['recommendations']]+[''])

def render_eng(vulns):
    lines=['# Engineering Remediation List','', '| CVE | Component | Severity | Fix Available |','|---|---|---|---|']
    for v in vulns: lines.append(f"| {v.cve} | {v.component} | {v.severity} | {v.fix_available} |")
    return '\n'.join(lines)+'\n'

def render_supplier(data):
    asks=[]
    if data['stats']['purl_percent']<90: asks.append('Please provide package URLs for all identifiable components.')
    if data['stats']['hash_percent']<50: asks.append('Please provide artifact/component hashes.')
    if not data['stats']['dependency_graph_present']: asks.append('Please provide the dependency graph or relationships section.')
    if not asks: asks=['No supplier follow-up questions generated from baseline checks.']
    return '# Supplier Follow-up Questions\n\n'+'\n'.join(f'- {x}' for x in asks)+'\n'

def render_html(md):
    body='\n'.join(f'<p>{html.escape(line)}</p>' if line and not line.startswith('#') else f'<h1>{html.escape(line.lstrip("# "))}</h1>' if line.startswith('# ') else f'<h2>{html.escape(line.lstrip("# "))}</h2>' if line.startswith('## ') else '' for line in md.splitlines())
    return f'<!doctype html><meta charset="utf-8"><title>SBOM Report</title><main style="font-family:system-ui;max-width:920px;margin:3rem auto;line-height:1.5">{body}</main>'
if __name__=='__main__': main()
