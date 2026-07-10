#!/usr/bin/env python3
"""Optional AI-assisted fuzz case generation for Full SBOM Analysis.

This module keeps the core safety model intact:
- AI suggests edge cases or prompts.
- Deterministic mutators create reviewable cases.
- Deterministic validators decide what can run.
- Generated cases never execute arbitrary code.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: List[str], *, cwd: Path, timeout: int) -> Dict[str, Any]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="AI-assisted fuzz cases for Full SBOM Analysis")
    ap.add_argument("sbom", help="SBOM to inspect")
    ap.add_argument("--out-dir", default="reports/ai-assisted-fuzz-analysis")
    ap.add_argument("--provider", default="none")
    ap.add_argument("--model", default="")
    ap.add_argument("--mode", default="suggest", choices=["disabled", "suggest", "generate-run"])
    ap.add_argument("--max-cases", type=int, default=5)
    ap.add_argument("--time-budget", type=int, default=30)
    ap.add_argument("--scenario", default="sbom-analysis-targeted-edge-cases")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    ns = parse_args(argv)
    sbom = Path(ns.sbom)
    out = Path(ns.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "input": str(sbom),
        "mode": ns.mode,
        "provider": ns.provider,
        "model": ns.model,
        "max_cases": ns.max_cases,
        "time_budget_seconds": ns.time_budget,
        "suggestion_step": None,
        "validated_cases": [],
        "rejected_cases": [],
        "execution_steps": [],
        "guidance": "AI suggestions are advisory. Deterministic tools generated and validated any executed cases. Human review is required before promoting cases to regression corpus.",
    }
    if ns.mode == "disabled":
        report["guidance"] = "AI-assisted fuzzing disabled for this analysis."
        (out / "ai-fuzz-analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out / "ai-fuzz-analysis.md").write_text("# AI-Assisted Fuzz Analysis\n\nAI-assisted fuzzing was disabled.\n")
        print(json.dumps({"mode": ns.mode, "executed_cases": 0}, indent=2))
        return 0

    count = max(1, min(ns.max_cases, 25))
    # Prompt/review artifact plus deterministic seed ideas. The ai_fuzz tool always writes review artifacts.
    suggestion_cmd = [sys.executable, "-m", "ai_fuzz.tools.ai_fuzz", "--provider", ns.provider]
    if ns.model:
        suggestion_cmd.extend(["--model", ns.model])
    suggestion_cmd.extend(["seeds", "--format", "cyclonedx", "--scenario", ns.scenario, "--count", str(count)])
    report["suggestion_step"] = run(suggestion_cmd, cwd=ROOT, timeout=max(ns.time_budget, 20))

    # Always write a concise suggestion manifest so the evidence bundle is self-explanatory.
    suggestions = [
        {"case": "duplicate-bom-ref", "purpose": "Test component identity collision handling."},
        {"case": "dependency-cycle", "purpose": "Test dependency graph cycle handling and parser DoS resistance."},
        {"case": "purl-cpe-conflict", "purpose": "Test scanner identity matching ambiguity."},
        {"case": "license-expression-edge", "purpose": "Test SPDX license expression handling."},
        {"case": "vex-contradiction", "purpose": "Test vulnerability/exploitability logic preservation."},
    ][:count]
    (out / "ai-fuzz-suggestions.json").write_text(json.dumps({"suggestions": suggestions, "provider": ns.provider, "model": ns.model}, indent=2) + "\n")
    (out / "ai-fuzz-suggestions.md").write_text("# AI Fuzz Suggestions\n\n" + "\n".join(f"- **{s['case']}**: {s['purpose']}" for s in suggestions) + "\n")

    if ns.mode == "suggest":
        report["guidance"] += " This run was suggest-only; no AI-derived cases were executed."
        (out / "ai-fuzz-analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out / "ai-fuzz-analysis.md").write_text("# AI-Assisted Fuzz Analysis\n\nMode: suggest only. Review `ai-fuzz-suggestions.*` before running generated cases.\n")
        print(json.dumps({"mode": ns.mode, "suggestions": len(suggestions), "executed_cases": 0}, indent=2))
        return 0

    # generate-run mode: deterministic mutation plus validation/execution.
    generated = out / "ai-fuzz-validated-cases"
    generated.mkdir(parents=True, exist_ok=True)
    mutation_cmd = [sys.executable, "fuzzing/mutators/sbom_json_mutator.py", str(sbom), "--out", str(generated), "--count", str(count)]
    mut = run(mutation_cmd, cwd=ROOT, timeout=max(ns.time_budget, 20))
    report["execution_steps"].append({"name": "generate-deterministic-cases", **mut})

    cases = sorted(generated.glob("*.json"))[:count]
    rejected = out / "ai-fuzz-rejected-cases"
    rejected.mkdir(exist_ok=True)
    results_dir = out / "ai-fuzz-results"
    results_dir.mkdir(exist_ok=True)
    for idx, case in enumerate(cases, 1):
        # Validation is parse/oracle based. Failing oracle results are findings, not unsafe execution.
        oracle_out = results_dir / f"case-{idx:02d}-oracles.json"
        metamorphic_dir = results_dir / f"case-{idx:02d}-metamorphic"
        roundtrip_dir = results_dir / f"case-{idx:02d}-roundtrip"
        case_report: Dict[str, Any] = {"case": str(case), "steps": []}
        for name, cmd in [
            ("semantic-oracles", [sys.executable, "fuzzing/oracles/semantic_oracles.py", str(case), "--out", str(oracle_out)]),
            ("metamorphic", [sys.executable, "fuzzing/metamorphic/metamorphic_sbom.py", str(case), "--out-dir", str(metamorphic_dir)]),
            ("roundtrip", [sys.executable, "fuzzing/roundtrip/roundtrip_sbom.py", str(case), "--out-dir", str(roundtrip_dir)]),
        ]:
            try:
                case_report["steps"].append({"name": name, **run(cmd, cwd=ROOT, timeout=max(ns.time_budget, 10))})
            except subprocess.TimeoutExpired:
                case_report["steps"].append({"name": name, "returncode": 124, "timed_out": True})
        case_report["passed"] = all(step.get("returncode") in (0, None) for step in case_report["steps"])
        report["validated_cases"].append(case_report)

    (out / "ai-fuzz-analysis.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    md = ["# AI-Assisted Fuzz Analysis", "", f"- Mode: `{ns.mode}`", f"- Provider: `{ns.provider}`", f"- Model: `{ns.model or '(default)'}`", f"- Generated cases: {len(cases)}", f"- Executed cases: {len(report['validated_cases'])}", "", "## Cases"]
    for case in report["validated_cases"]:
        md.append(f"- `{Path(case['case']).name}`: {'passed' if case.get('passed') else 'findings/failures recorded'}")
    (out / "ai-fuzz-analysis.md").write_text("\n".join(md) + "\n")
    print(json.dumps({"mode": ns.mode, "suggestions": len(suggestions), "executed_cases": len(report["validated_cases"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
