#!/usr/bin/env python3
"""CISA/NTIA-style SBOM minimum-elements checker.

This is intentionally a practical checker, not a legal/compliance opinion. It
uses the fields visible in CycloneDX/SPDX documents and reports gaps teams
should remediate before using an SBOM for release evidence or supplier intake.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_components, component_stats, write_json, write_markdown

REQUIRED = [
    "supplier_name",
    "component_name",
    "component_version",
    "unique_identifier",
    "dependency_relationships",
    "sbom_author",
    "timestamp",
    "format_version",
]


def evaluate(sbom: str):
    fmt, comps, meta = parse_components(sbom)
    stats = component_stats(comps, meta)
    component_count = stats["component_count"]
    supplier_ok = stats["supplier_percent"] >= 80
    version_ok = stats["version_percent"] >= 95
    ids_ok = stats["purl_percent"] >= 80 or stats["with_cpe"] >= max(1, int(component_count * 0.5)) if component_count else False
    format_ok = fmt in {"cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"}
    # The common parser exposes limited metadata. Treat absent author/timestamp as WARN,
    # because some tools place this information in format-specific locations.
    findings = [
        {"element": "Supplier name", "status": "PASS" if supplier_ok else "WARN", "detail": f"Supplier coverage: {stats['supplier_percent']}%"},
        {"element": "Component name", "status": "PASS" if component_count else "FAIL", "detail": f"Components detected: {component_count}"},
        {"element": "Component version", "status": "PASS" if version_ok else "WARN", "detail": f"Version coverage: {stats['version_percent']}%"},
        {"element": "Other unique identifiers", "status": "PASS" if ids_ok else "WARN", "detail": f"purl coverage: {stats['purl_percent']}%; CPE count: {stats['with_cpe']}"},
        {"element": "Dependency relationships", "status": "PASS" if stats["dependency_graph_present"] else "FAIL", "detail": "Dependency graph present" if stats["dependency_graph_present"] else "No dependency relationships found"},
        {"element": "Author of SBOM data", "status": "WARN", "detail": "Verify author/tool metadata in the source SBOM"},
        {"element": "Timestamp", "status": "WARN", "detail": "Verify timestamp/create date metadata in the source SBOM"},
        {"element": "SBOM format/version", "status": "PASS" if format_ok else "FAIL", "detail": f"Detected format: {fmt}; spec version: {meta.get('specVersion') or meta.get('spdxVersion') or 'unknown'}"},
    ]
    status = "PASS"
    if any(f["status"] == "FAIL" for f in findings):
        status = "FAIL"
    elif any(f["status"] == "WARN" for f in findings):
        status = "PARTIAL"
    return {"status": status, "sbom": sbom, "format": fmt, "stats": stats, "findings": findings}


def render(result):
    lines = ["# SBOM Minimum Elements Check", "", f"**Status:** {result['status']}", "", "| Element | Status | Detail |", "|---|---|---|"]
    for f in result["findings"]:
        lines.append(f"| {f['element']} | {f['status']} | {f['detail']} |")
    lines += ["", "## Notes", "", "This checker is a practical minimum-elements helper. Treat WARN findings as follow-up items for supplier, build, or compliance teams.", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Check SBOM minimum elements.")
    ap.add_argument("sbom")
    ap.add_argument("--out-dir", default="reports/minimum-elements")
    args = ap.parse_args()
    result = evaluate(args.sbom)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    write_json(out / "minimum-elements.json", result)
    write_markdown(out / "minimum-elements.md", render(result))
    print(f"Minimum elements: {result['status']}")

if __name__ == "__main__":
    main()
