#!/usr/bin/env python3
from __future__ import annotations
import argparse
from collections import defaultdict
from pathlib import Path
from .common import parse_vuln_report, write_json, write_markdown


def score_group(items):
    scanners = {v.scanner for v in items if v.scanner and v.scanner != "unknown"}
    max_cvss = max((v.cvss for v in items), default=0)
    max_epss = max((v.epss for v in items), default=0)
    kev = any(v.kev for v in items)
    fix = any(v.fix_available for v in items)
    pts = 20
    if len(scanners) >= 2: pts += 25
    if kev: pts += 25
    if max_epss >= .5: pts += 20
    elif max_epss >= .1: pts += 10
    if max_cvss >= 9: pts += 15
    elif max_cvss >= 7: pts += 10
    if fix: pts += 5
    level = "High" if pts >= 70 else "Medium" if pts >= 45 else "Low"
    reasons = []
    if scanners: reasons.append(f"reported by {len(scanners)} scanner(s): {', '.join(sorted(scanners))}")
    if kev: reasons.append("CISA KEV signal present")
    if max_epss: reasons.append(f"max EPSS {max_epss}")
    if max_cvss: reasons.append(f"max CVSS {max_cvss}")
    if fix: reasons.append("fix available")
    return min(100, pts), level, reasons


def main():
    ap = argparse.ArgumentParser(description="Score confidence in vulnerability findings across reports/scanners.")
    ap.add_argument("vuln_reports", nargs="+")
    ap.add_argument("--out-dir", default="reports/confidence")
    args = ap.parse_args()
    grouped = defaultdict(list)
    for report in args.vuln_reports:
        for v in parse_vuln_report(report):
            grouped[(v.cve, v.component)].append(v)
    rows = []
    for (cve, component), items in grouped.items():
        pts, level, reasons = score_group(items)
        rows.append({"cve": cve, "component": component, "confidence_score": pts, "confidence": level, "reasons": reasons, "scanner_count": len({v.scanner for v in items})})
    rows.sort(key=lambda r: (-r["confidence_score"], r["cve"]))
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    write_json(out / "scanner-confidence.json", rows)
    lines = ["# Scanner Confidence Report", "", "| Confidence | Score | CVE | Component | Rationale |", "|---|---:|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['confidence']} | {r['confidence_score']} | {r['cve']} | {r['component']} | {'; '.join(r['reasons'])} |")
    write_markdown(out / "scanner-confidence.md", "\n".join(lines) + "\n")
    print(f"Wrote confidence report to {out}")

if __name__ == "__main__":
    main()
