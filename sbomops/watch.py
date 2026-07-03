#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime, json
from pathlib import Path
from .common import parse_components, parse_vuln_report, write_json, write_markdown


def main():
    ap = argparse.ArgumentParser(description="Local SBOM watch mode: compare current component/vulnerability state with previous run.")
    ap.add_argument("sbom"); ap.add_argument("--vulns"); ap.add_argument("--state-dir", default=".sbom-watch"); ap.add_argument("--out-dir", default="reports/watch")
    args = ap.parse_args()
    fmt, comps, meta = parse_components(args.sbom)
    vulns = parse_vuln_report(args.vulns) if args.vulns else []
    current = {"time": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"), "sbom": args.sbom, "components": sorted(c.key() for c in comps), "vulns": sorted({v.cve + "|" + v.component for v in vulns})}
    state_dir = Path(args.state_dir); state_dir.mkdir(parents=True, exist_ok=True); state_file = state_dir / "latest.json"
    previous = json.loads(state_file.read_text()) if state_file.exists() else {"components": [], "vulns": []}
    delta = {
        "new_components": sorted(set(current["components"]) - set(previous.get("components", []))),
        "removed_components": sorted(set(previous.get("components", [])) - set(current["components"])),
        "new_vulnerabilities": sorted(set(current["vulns"]) - set(previous.get("vulns", []))),
        "resolved_vulnerabilities": sorted(set(previous.get("vulns", [])) - set(current["vulns"])),
    }
    state_file.write_text(json.dumps(current, indent=2) + "\n")
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    write_json(out / "latest-delta.json", {"current": current, "delta": delta})
    md = ["# SBOM Watch Delta", "", f"Run: {current['time']}", "", "## New vulnerabilities", ""]
    md += [f"- {x}" for x in delta["new_vulnerabilities"]] or ["- None"]
    md += ["", "## Resolved vulnerabilities", ""] + ([f"- {x}" for x in delta["resolved_vulnerabilities"]] or ["- None"])
    md += ["", "## Component changes", "", f"- New components: {len(delta['new_components'])}", f"- Removed components: {len(delta['removed_components'])}", ""]
    write_markdown(out / "latest-delta.md", "\n".join(md))
    print(out / "latest-delta.md")

if __name__ == "__main__":
    main()
