#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_vuln_report, write_json, write_markdown

def priority(v):
    if v.kev or v.epss >= .5 or v.severity == 'critical': return 'P1'
    if v.severity == 'high' or v.cvss >= 7 or v.epss >= .1: return 'P2'
    if v.severity == 'medium' or v.cvss >= 4: return 'P3'
    return 'P4'

def main():
    ap=argparse.ArgumentParser(description='Prioritize vulnerabilities using CVSS, EPSS, KEV, and fix signals.')
    ap.add_argument('vuln_report'); ap.add_argument('--out-dir',default='reports/prioritization')
    args=ap.parse_args(); vulns=parse_vuln_report(args.vuln_report)
    rows=[]
    for v in vulns:
        rows.append({**v.__dict__,'priority':priority(v),'rationale': rationale(v)})
    rows=sorted(rows,key=lambda r: {'P1':0,'P2':1,'P3':2,'P4':3}[r['priority']])
    out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True); write_json(out/'prioritized-vulns.json', rows); write_markdown(out/'prioritized-vulns.md', render(rows)); print(f"Wrote {out/'prioritized-vulns.md'}")

def rationale(v):
    reasons=[]
    if v.kev: reasons.append('CISA KEV')
    if v.epss: reasons.append(f'EPSS {v.epss}')
    if v.severity: reasons.append(v.severity)
    if v.fix_available: reasons.append('fix available')
    return ', '.join(reasons) or 'baseline priority'

def render(rows):
    lines=['# Vulnerability Prioritization','', '| Priority | CVE | Component | Severity | CVSS | EPSS | KEV | Fix |','|---|---|---|---|---:|---:|---|---|']
    for r in rows: lines.append(f"| {r['priority']} | {r['cve']} | {r['component']} | {r['severity']} | {r['cvss']} | {r['epss']} | {r['kev']} | {r['fix_available']} |")
    return '\n'.join(lines)+'\n'
if __name__=='__main__': main()
