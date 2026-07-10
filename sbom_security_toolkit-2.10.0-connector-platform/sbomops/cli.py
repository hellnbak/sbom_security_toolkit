#!/usr/bin/env python3
from __future__ import annotations
import argparse, subprocess, sys

MODULES = {
    "assurance": "sbomops.assurance",
    "release-assurance": "sbomops.assurance",
    "exceptions": "sbomops.risk_exceptions",
    "risk-exceptions": "sbomops.risk_exceptions",
    "provenance": "sbomops.provenance",
    "evidence-bundle": "sbomops.evidence_bundle",
    "org-model": "sbomops.org_model",
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
    "ai-fuzz-analysis": "sbomops.ai_fuzz_analysis",
    "normalize": "sbomops.normalize",
    "explain": "sbomops.explain",
    "repair": "sbomops.repair",
    "diff": "sbomops.diff",
    "inventory": "sbomops.inventory",
    "repo": "sbomops.repo_intake",
    "repo-intake": "sbomops.repo_intake",
    "dependency-health": "sbomops.dependency_health",
    "lifecycle": "sbomops.dependency_health",
    "lifecycle-intelligence": "sbomops.dependency_health",
    "ai-report": "sbomops.ai_report_writer",
    "ai-reports": "sbomops.ai_report_writer",
    "report-writer": "sbomops.ai_report_writer",
    "project": "sbomops.project_ops",
    "release-decision": "sbomops.project_ops",
    "cloud": "sbomops.cloud",
    "config": "sbomops.config_manager",
    "enterprise": "sbomops.enterprise",
    "integrations": "sbomops.integrations",
    "connector": "sbomops.connectors",
    "connectors": "sbomops.connectors",
    "findings": "sbomops.findings",
    "remediation": "sbomops.findings",
    "reports-viewer": "sbomops.reports_viewer",
    "reports": "sbomops.reports_viewer",
    "product": "sbomops.productization",
    "qa": "sbomops.productization",
    "doctor": "sbomops.productization",
    "demo-product": "sbomops.productization",
    "export": "sbomops.integrations",
    "vex": "sbomops.integrations",

    "fuzz-plan": "fuzzing.planner.fuzz_plan",
    "fuzz-kb": "fuzzing.kb.fuzz_kb",
    "fuzz-benchmark": "fuzzing.benchmarks.run_benchmark",
    "scanner-compatibility": "fuzzing.compatibility.scanner_compatibility",
    "scanner-truthset": "fuzzing.truthset.scanner_truthset",
    "fuzz-replay-pack": "fuzzing.replay.create_replay_pack",
    "ai-harness-loop": "ai_fuzz.tools.ai_harness_loop",
    "ai-fuzz-loop": "ai_fuzz.tools.ai_fuzz_loop",
    "ai-fuzz-eval": "ai_fuzz.tools.ai_eval",
    "fuzz-intelligence": "fuzzing.intelligence.intelligence_score",
    "fuzz-corpus-recommend": "fuzzing.corpus.recommend",
    "fuzz-harness-audit": "fuzzing.harness.audit",
    "ai-harness-quality-loop": "ai_fuzz.tools.ai_harness_quality_loop",
    "ai-seed-generator": "ai_fuzz.tools.ai_seed_generator",
    "ai-seed-generator-test": "ai_fuzz.tools.ai_seed_generator_test",
    "fuzz-grammar": "fuzzing.grammar.run_grammar_mutator",
    "fuzz-target-coverage": "fuzzing.coverage.target_coverage",
    "fuzz-semantic-format-diff": "fuzzing.semantic_format_diff.semantic_format_diff",
    "fuzz-vuln-matching": "fuzzing.vuln_matching.vuln_matching_fuzz",
    "fuzz-vex-logic": "fuzzing.vex_logic.vex_logic_fuzz",
    "fuzz-evil-supplier": "fuzzing.evil_supplier.evil_supplier",
    "ai-fuzz-redteam": "ai_fuzz.tools.ai_redteam",
    "cflite-import-results": "fuzzing.clusterfuzzlite.import_results",
    "fuzz-ci-dashboard": "fuzzing.clusterfuzzlite.ci_dashboard",
    "fuzz-finding-update": "fuzzing.findings_lifecycle.lifecycle",
    "fuzz-lab-dashboard": "fuzzing.visualize.fuzzing_lab_dashboard",
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
