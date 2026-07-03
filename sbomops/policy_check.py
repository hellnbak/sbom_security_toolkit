#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_components, component_stats, load_policy, parse_vuln_report, write_json, write_markdown

def main():
    ap=argparse.ArgumentParser(description='Apply policy-as-code gates to SBOM and vulnerability metadata.')
    ap.add_argument('sbom'); ap.add_argument('--policy', default='policies/default-release-policy.yml'); ap.add_argument('--vulns'); ap.add_argument('--out-dir', default='reports/policy')
    args=ap.parse_args()
    fmt, comps, meta=parse_components(args.sbom); stats=component_stats(comps, meta); policy=load_policy(args.policy); vulns=parse_vuln_report(args.vulns) if args.vulns else []
    findings=[]; status='PASS'
    def add(level, msg):
        nonlocal status
        findings.append({'level':level,'message':msg})
        if level=='FAIL': status='FAIL'
        elif level=='WARN' and status!='FAIL': status='WARN'
    fail=policy.get('fail_on',{}); warn=policy.get('warn_on',{})
    if fail.get('missing_license_percent_gt') is not None and 100-stats['license_percent']>fail['missing_license_percent_gt']: add('FAIL', f"Missing license metadata exceeds {fail['missing_license_percent_gt']}%")
    if fail.get('missing_purl_percent_gt') is not None and 100-stats['purl_percent']>fail['missing_purl_percent_gt']: add('FAIL', f"Missing purl metadata exceeds {fail['missing_purl_percent_gt']}%")
    if fail.get('unknown_components_gt') is not None and sum(1 for c in comps if not c.version and not c.purl)>fail['unknown_components_gt']: add('FAIL','Too many components lack both version and purl')
    if fail.get('no_dependency_graph') and not stats['dependency_graph_present']: add('FAIL','No dependency graph present')
    if fail.get('cisa_kev') and any(v.kev for v in vulns): add('FAIL','CISA KEV vulnerability present')
    if fail.get('critical_without_vex') and any(v.severity=='critical' for v in vulns): add('FAIL','Critical vulnerability present without VEX evidence supplied')
    if warn.get('high_cvss_count_gt') is not None and sum(1 for v in vulns if v.severity in {'high','critical'} or v.cvss>=7)>=warn['high_cvss_count_gt']: add('WARN','High/Critical vulnerability count exceeds warning threshold')
    if warn.get('no_dependency_graph') and not stats['dependency_graph_present']: add('WARN','No dependency graph present')
    if not findings: findings.append({'level':'PASS','message':'All configured policy checks passed.'})
    result={'status':status,'policy':args.policy,'sbom':args.sbom,'stats':stats,'findings':findings}
    out=Path(args.out_dir); out.mkdir(parents=True, exist_ok=True); write_json(out/'policy-result.json', result); write_markdown(out/'policy-result.md', render(result)); print(f"Policy status: {status}")

def render(r):
    return '\n'.join(['# SBOM Policy Result','',f"**Status:** {r['status']}",'','## Findings','']+[f"- **{f['level']}**: {f['message']}" for f in r['findings']]+[''])
if __name__=='__main__': main()
