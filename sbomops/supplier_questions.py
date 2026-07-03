#!/usr/bin/env python3
from __future__ import annotations
import argparse
from pathlib import Path
from .common import parse_components, component_stats, write_csv, write_markdown, write_json


def build_questions(sbom: str):
    fmt, comps, meta = parse_components(sbom)
    stats = component_stats(comps, meta)
    qs = []
    def add(category, question, priority="medium"):
        qs.append({"priority": priority, "category": category, "question": question})
    if stats["component_count"] == 0:
        add("format", "Please provide a machine-readable CycloneDX or SPDX SBOM that includes package components.", "high")
    if stats["purl_percent"] < 90:
        add("identity", "Please provide package URLs (purl) or equivalent unique package identifiers for components missing them.", "high")
    if stats["version_percent"] < 95:
        add("identity", "Please provide versions for all shipped components or explain components where a version is unavailable.", "high")
    if not stats["dependency_graph_present"]:
        add("relationships", "Please provide dependency relationships showing direct and transitive dependencies.", "high")
    if stats["hash_percent"] < 50:
        add("integrity", "Please provide component or artifact hashes/checksums where available.")
    if stats["license_percent"] < 90:
        add("license", "Please clarify license metadata for components missing license data.")
    add("scope", "Please confirm whether this SBOM covers runtime dependencies, build-time dependencies, containers, operating-system packages, or all shipped artifacts.", "high")
    add("vex", "Please provide VEX or exploitability status for known vulnerabilities affecting shipped components.", "high")
    add("maintenance", "Please identify unsupported, end-of-life, forked, or internally modified components.")
    return {"sbom": sbom, "format": fmt, "stats": stats, "questions": qs}


def render_email(result):
    lines = ["Hello,", "", "We reviewed the supplied SBOM and have a few follow-up questions before we can complete intake:", ""]
    for q in result["questions"]:
        lines.append(f"- [{q['priority'].upper()}] {q['question']}")
    lines += ["", "Please include an updated SBOM and any supporting VEX or exploitability evidence with your response.", "", "Thank you.", ""]
    return "\n".join(lines)


def render_md(result):
    lines = ["# Supplier SBOM Follow-up Questions", "", f"SBOM: `{result['sbom']}`", "", "| Priority | Category | Question |", "|---|---|---|"]
    for q in result["questions"]:
        lines.append(f"| {q['priority']} | {q['category']} | {q['question']} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Generate supplier SBOM questionnaire and follow-up email.")
    ap.add_argument("sbom")
    ap.add_argument("--out-dir", default="reports/supplier-questions")
    args = ap.parse_args()
    result = build_questions(args.sbom)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    write_json(out / "supplier-questions.json", result)
    write_markdown(out / "supplier-followup.md", render_md(result))
    write_markdown(out / "supplier-followup-email.md", render_email(result))
    write_csv(out / "supplier-questionnaire.csv", result["questions"], ["priority", "category", "question"])
    print(f"Wrote supplier questions to {out}")

if __name__ == "__main__":
    main()
