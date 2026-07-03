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
    "ai-fuzz": "ai_fuzz.tools.ai_fuzz",
    "ai-review": "ai_fuzz.tools.review_queue",
    "ai-provider-test": "ai_fuzz.tools.provider_test",
    "normalize": "sbomops.normalize",
    "explain": "sbomops.explain",
    "repair": "sbomops.repair",
    "diff": "sbomops.diff",
    "inventory": "sbomops.inventory",
}

def main():
    ap = argparse.ArgumentParser(prog="sst", description="SBOM Security Toolkit CLI")
    commands = sorted([*MODULES.keys(), "version"])
    ap.add_argument("command", choices=commands)
    args, rest = ap.parse_known_args()
    if args.command == "version":
        try:
            from sbomops.__version__ import __version__
        except Exception:
            __version__ = "0.0.0"
        print(__version__)
        return 0
    raise SystemExit(subprocess.call([sys.executable, "-m", MODULES[args.command], *rest]))

if __name__ == "__main__": main()
