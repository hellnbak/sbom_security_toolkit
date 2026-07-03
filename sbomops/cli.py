#!/usr/bin/env python3
from __future__ import annotations
import argparse, subprocess, sys

MODULES = {
    "analyze": "sbomops.analyze_project",
    "score": "sbomops.score_sbom",
    "minimum-elements": "sbomops.minimum_elements",
    "policy": "sbomops.policy_check",
    "supplier-intake": "sbomops.supplier_intake",
    "supplier-questions": "sbomops.supplier_questions",
    "confidence": "sbomops.confidence",
    "redact": "sbomops.redact",
    "watch": "sbomops.watch",
    "ui": "sbomops.ui_bundle",
    "workbench": "sbomops.workbench.server",
}

def main():
    ap = argparse.ArgumentParser(prog="sst", description="SBOM Security Toolkit CLI")
    ap.add_argument("command", choices=sorted(MODULES))
    args, rest = ap.parse_known_args()
    raise SystemExit(subprocess.call([sys.executable, "-m", MODULES[args.command], *rest]))

if __name__ == "__main__": main()
