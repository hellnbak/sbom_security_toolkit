#!/usr/bin/env python3
from __future__ import annotations
import argparse, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from sbomops.common import parse_vuln_report, write_markdown

def main():
    ap=argparse.ArgumentParser(description='Generate a deterministic human-review triage summary from scanner JSON.')
    ap.add_argument('vuln_report'); ap.add_argument('--out', default='reports/ai-triage/advisory-summary.md')
    args=ap.parse_args(); vulns=parse_vuln_report(args.vuln_report)
    crit=[v for v in vulns if v.severity=='critical']; high=[v for v in vulns if v.severity=='high']; kev=[v for v in vulns if v.kev]
    lines=['# AI-Assisted Triage Input Summary','','> Advisory only. Do not auto-close, auto-accept VEX, or suppress findings without human review.','',f'- Critical: {len(crit)}',f'- High: {len(high)}',f'- CISA KEV-marked: {len(kev)}','','## Human review checklist','','- Confirm runtime reachability.','- Confirm direct vs transitive dependency status.','- Confirm fixed version and upgrade path.','- Require evidence before marking VEX `not_affected`.','']
    write_markdown(args.out,'\n'.join(lines)); print(args.out)
if __name__=='__main__': main()
