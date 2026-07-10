#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .providers import complete
from .validators import redact_text, validate_seed, write_json

ROOT = Path(__file__).resolve().parents[2]
REVIEW_INCOMING = ROOT / "ai_fuzz" / "review" / "incoming"
AI_CORPUS_INCOMING = ROOT / "fuzzing" / "corpus" / "ai" / "incoming"


def utc_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}"


def write_artifact(kind: str, files: Dict[str, str], metadata: Dict[str, Any]) -> Path:
    out = REVIEW_INCOMING / utc_id(kind)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    write_json(out / "metadata.json", metadata)
    print(f"Wrote review item: {out.relative_to(ROOT)}")
    return out


def call_or_prompt(prompt: str, *, provider: Optional[str], model: Optional[str]) -> Dict[str, Any]:
    result = complete(prompt, provider=provider, model=model)
    return {
        "provider": result.provider,
        "model": result.model,
        "used_network": result.used_network,
        "error": result.error,
        "text": result.text,
    }


def seed_doc(fmt: str, scenario: str, idx: int) -> Dict[str, Any]:
    scenario_key = scenario.lower().replace("_", "-")
    odd_name = {
        "dependency-cycles": "cycle-root",
        "license-edge-cases": "license-oddity",
        "vex-contradictions": "vex-conflict",
        "unicode-package-names": "pkg-𝖘𝖇𝖔𝖒",
        "mixed-ecosystems": "mixed-identity",
    }.get(scenario_key, f"ai-seed-{scenario_key}")
    if fmt.lower().startswith("spdx"):
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-DOCUMENT-{idx}",
            "name": f"ai-fuzz-{scenario_key}-{idx}",
            "documentNamespace": f"https://example.invalid/sbom-security-toolkit/ai-fuzz/{scenario_key}/{idx}",
            "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: sbom-security-toolkit-ai-fuzz"]},
            "packages": [
                {"SPDXID": "SPDXRef-Package-A", "name": odd_name, "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "licenseConcluded": "NOASSERTION"},
                {"SPDXID": "SPDXRef-Package-B", "name": odd_name + "-dep", "versionInfo": "999999999999999999.0.0", "downloadLocation": "NOASSERTION", "licenseConcluded": "MIT OR Apache-2.0"},
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT-0", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-A"},
                {"spdxElementId": "SPDXRef-Package-A", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-B"},
                {"spdxElementId": "SPDXRef-Package-B", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-A"} if "cycle" in scenario_key else {"spdxElementId": "SPDXRef-Package-B", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-B"},
            ],
        }
    components = [
        {"type": "library", "bom-ref": "pkg:a", "name": odd_name, "version": "1.0.0", "purl": "pkg:pypi/example@1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "bom-ref": "pkg:b", "name": odd_name + "-dep", "version": "999999999999999999.0.0", "purl": "pkg:npm/example@999999999999999999.0.0", "cpe": "cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*"},
    ]
    if "unicode" in scenario_key:
        components[0]["name"] = "ѕbοm-confusable-𝓹𝓴𝓰"
        components[0]["purl"] = "pkg:pypi/%D1%95b%CE%BFm-confusable@1.0.0"
    if "license" in scenario_key:
        components[0]["licenses"] = [{"expression": "MIT OR Apache-2.0 WITH LLVM-exception"}]
        components[1]["licenses"] = [{"expression": "((MIT AND GPL-2.0-only) OR LicenseRef-Custom)"}]
    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{idx:012d}",
        "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": [{"vendor": "SBOM Security Toolkit", "name": "ai-fuzz", "version": "1.6.0"}]},
        "components": components,
        "dependencies": [{"ref": "pkg:a", "dependsOn": ["pkg:b"]}],
    }
    if "cycle" in scenario_key:
        doc["dependencies"].append({"ref": "pkg:b", "dependsOn": ["pkg:a"]})
    if "vex" in scenario_key:
        doc["vulnerabilities"] = [{
            "id": "CVE-2099-0001",
            "source": {"name": "example"},
            "affects": [{"ref": "pkg:a"}],
            "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "AI fuzz seed contradiction: dependency is still present and direct."},
        }]
    return doc


def prompt_header(task: str) -> str:
    return textwrap.dedent(f"""
    You are assisting defensive fuzzing for an SBOM security toolkit.
    Task: {task}

    Hard rules:
    - Return reviewable artifacts only.
    - Do not include exploit code, credential material, or live targets.
    - Generated content is advisory and must be reviewed by a human.
    - Prefer structured SBOM/parser edge cases over random bytes.
    """).strip()


def cmd_seeds(args: argparse.Namespace) -> int:
    fmt = args.format
    scenario = args.scenario
    prompt = prompt_header("Generate SBOM fuzzing seed ideas") + f"\n\nFormat: {fmt}\nScenario: {scenario}\nCount: {args.count}\nReturn JSON seeds or a concise list of seed designs."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    files = {"prompt.md": prompt + "\n"}
    if model["text"]:
        files["model-output.md"] = model["text"]
    docs = []
    corpus_dir = AI_CORPUS_INCOMING / utc_id(f"{fmt}-{scenario}")
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for i in range(args.count):
        doc = seed_doc(fmt, scenario, i + 1)
        seed_path = corpus_dir / f"{fmt}-{scenario}-{i+1}.json".replace("/", "-")
        write_json(seed_path, doc)
        docs.append(str(seed_path.relative_to(ROOT)))
    validations = [validate_seed(ROOT / p) for p in docs]
    files["generated-seeds.json"] = json.dumps({"seeds": docs, "validation": validations}, indent=2) + "\n"
    metadata = {"kind": "ai-fuzz-seeds", "format": fmt, "scenario": scenario, "provider": model, "corpus_dir": str(corpus_dir.relative_to(ROOT))}
    write_artifact("seeds", files, metadata)
    return 0


def cmd_mutation_plan(args: argparse.Namespace) -> int:
    sbom_path = Path(args.sbom)
    raw = redact_text(sbom_path.read_text(errors="replace") if sbom_path.exists() else "")
    prompt = prompt_header("Create a deterministic mutation plan for an SBOM") + f"\n\nSBOM path: {sbom_path}\nSBOM excerpt:\n```\n{raw}\n```\nReturn JSON with mutations using known operations: duplicate_bom_ref, introduce_dependency_cycle, mutate_purl, mutate_license_expression, oversize_version, unicode_name, drop_required_field."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    plan = {
        "source": str(sbom_path),
        "mutations": [
            {"field": "components[].bom-ref", "strategy": "duplicate_bom_ref", "reason": "Tests duplicate component identity handling."},
            {"field": "dependencies[].dependsOn", "strategy": "introduce_dependency_cycle", "reason": "Tests graph traversal and cycle protection."},
            {"field": "components[].purl", "strategy": "mutate_purl", "reason": "Tests package identity normalization."},
            {"field": "components[].licenses", "strategy": "mutate_license_expression", "reason": "Tests SPDX expression parsing."},
        ],
        "human_review_required": True,
    }
    files = {"prompt.md": prompt + "\n", "mutation-plan.json": json.dumps(plan, indent=2) + "\n"}
    if model["text"]: files["model-output.md"] = model["text"]
    write_artifact("mutation-plan", files, {"kind": "ai-mutation-plan", "provider": model, "sbom": str(sbom_path)})
    return 0


def cmd_oracle_suggest(args: argparse.Namespace) -> int:
    target = Path(args.target)
    raw = redact_text(target.read_text(errors="replace") if target.exists() else "", 16000)
    prompt = prompt_header("Suggest semantic fuzzing oracles") + f"\n\nTarget file: {target}\nCode excerpt:\n```\n{raw}\n```\nSuggest oracles as bullet points with invariant, why it matters, and possible regression seed."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    fallback = textwrap.dedent(f"""
    Suggested semantic oracles for {target}:
    - Normalization should not silently drop components unless a duplicate is explicitly reported.
    - Redaction should preserve dependency graph shape when configured to hash identities.
    - Minimum-elements checks should fail closed for malformed or unknown SBOM formats.
    - Supplier-question output should cite missing fields without inventing vulnerability impact.
    """).strip()
    files = {"prompt.md": prompt + "\n", "oracle-suggestions.md": (model["text"] or fallback) + "\n"}
    write_artifact("oracle-suggest", files, {"kind": "ai-oracle-suggest", "provider": model, "target": str(target)})
    return 0


def read_crash(crash: Path) -> str:
    if crash.is_dir():
        chunks = []
        for name in ["metadata.json", "stacktrace.txt", "stderr.txt", "logs.txt", "input"]:
            p = crash / name
            if p.exists() and p.is_file():
                chunks.append(f"--- {name} ---\n" + p.read_text(errors="replace")[:12000])
        return "\n\n".join(chunks)
    return crash.read_text(errors="replace")[:20000] if crash.exists() else ""


def cmd_crash_triage(args: argparse.Namespace) -> int:
    crash = Path(args.crash)
    raw = redact_text(read_crash(crash), 20000)
    prompt = prompt_header("Triage a fuzzing crash or semantic failure") + f"\n\nCrash path: {crash}\nCrash data:\n```\n{raw}\n```\nExplain likely root cause, security relevance, minimal reproducer idea, and regression test recommendation."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    fallback = textwrap.dedent("""
    Likely issue: input handling failed during SBOM parsing or semantic validation.

    Security relevance: malformed supplier SBOMs should not crash analysis or silently change security-relevant data.

    Suggested regression: add the crashing input to fuzzing/regression/corpus and assert that analysis exits cleanly with a structured warning.
    """).strip()
    files = {"prompt.md": prompt + "\n", "triage.md": (model["text"] or fallback) + "\n"}
    write_artifact("crash-triage", files, {"kind": "ai-crash-triage", "provider": model, "crash": str(crash)})
    return 0


def cmd_regression_test(args: argparse.Namespace) -> int:
    crash = Path(args.crash)
    digest = hashlib.sha256(str(crash).encode()).hexdigest()[:10]
    prompt = prompt_header("Draft a regression test for a fuzzing crash") + f"\n\nCrash path: {crash}\nCrash data excerpt:\n```\n{redact_text(read_crash(crash), 12000)}\n```\nReturn a Python unittest and a safe regression corpus filename."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    test = f'''#!/usr/bin/env python3\nfrom __future__ import annotations\nimport subprocess, sys, unittest\nfrom pathlib import Path\n\nROOT = Path(__file__).resolve().parents[2]\n\nclass GeneratedRegression{digest}(unittest.TestCase):\n    def test_crash_{digest}_does_not_crash_score(self):\n        corpus = ROOT / "fuzzing" / "regression" / "corpus"\n        self.assertTrue(corpus.exists())\n        proc = subprocess.run([sys.executable, "-m", "sbomops.score_sbom", str(corpus / "minimal-cyclonedx.json"), "--out-dir", str(ROOT / "reports" / "regression-generated")], cwd=ROOT, text=True, capture_output=True, timeout=30)\n        self.assertEqual(proc.returncode, 0, proc.stderr)\n\nif __name__ == "__main__":\n    unittest.main()\n'''
    files = {"prompt.md": prompt + "\n", f"test_regression_{digest}.py": test}
    if model["text"]: files["model-output.md"] = model["text"]
    write_artifact("regression-test", files, {"kind": "ai-regression-test", "provider": model, "crash": str(crash)})
    return 0


def cmd_harness(args: argparse.Namespace) -> int:
    target = Path(args.target)
    raw = redact_text(target.read_text(errors="replace") if target.exists() else "", 16000)
    name = re.sub(r"[^a-zA-Z0-9_]+", "_", target.stem or "target")
    prompt = prompt_header("Draft a fuzz harness") + f"\n\nTarget: {target}\nCode excerpt:\n```\n{raw}\n```\nDraft an Atheris or unittest-style harness that exercises public parsing/analysis entrypoints."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    harness = f'''#!/usr/bin/env python3\nfrom __future__ import annotations\nimport json\n\n# Review before use. Generated scaffold for {target}.\ndef TestOneInput(data: bytes) -> None:\n    try:\n        text = data.decode("utf-8", errors="ignore")\n        if not text.strip():\n            return\n        if text.lstrip().startswith("{{"):\n            json.loads(text)\n    except Exception:\n        # Fuzz harnesses should ignore expected parser exceptions.\n        return\n\nif __name__ == "__main__":\n    import sys\n    for path in sys.argv[1:]:\n        TestOneInput(open(path, "rb").read())\n'''
    files = {"prompt.md": prompt + "\n", f"{name}_fuzz_harness.py": harness}
    if model["text"]: files["model-output.md"] = model["text"]
    write_artifact("harness", files, {"kind": "ai-fuzz-harness", "provider": model, "target": str(target)})
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    cov = Path(args.coverage)
    raw = redact_text(cov.read_text(errors="replace") if cov.exists() else "", 16000)
    prompt = prompt_header("Suggest fuzzing seeds from coverage gaps") + f"\n\nCoverage report: {cov}\n```\n{raw}\n```\nSuggest seed types, mutators, and oracles for uncovered branches."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    fallback = "Suggested coverage seeds:\n- VEX fixed/affected/not_affected states.\n- CycloneDX dependencies with missing refs.\n- SPDX packages with NOASSERTION and malformed relationships.\n"
    files = {"prompt.md": prompt + "\n", "coverage-suggestions.md": (model["text"] or fallback) + "\n"}
    write_artifact("coverage-suggest", files, {"kind": "ai-coverage-suggest", "provider": model, "coverage": str(cov)})
    return 0


def cmd_campaign(args: argparse.Namespace) -> int:
    goal = args.goal
    prompt = prompt_header("Create an AI-assisted fuzz campaign profile") + f"\n\nGoal: {goal}\nReturn YAML with name, duration, targets, mutators, and oracles."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    safe_name = re.sub(r"[^a-z0-9-]+", "-", goal.lower()).strip("-") or "ai-campaign"
    yaml = textwrap.dedent(f"""
    name: {safe_name}
    description: AI-assisted campaign draft. Review before long-running execution.
    duration: 30m
    targets:
      - cyclonedx-json
      - spdx-json
      - semantic-oracles
    mutators:
      - structure-preserving
      - dependency-cycle
      - purl-edge-cases
      - license-expression-edge-cases
      - oversized-metadata
    oracles:
      - no-crash
      - no-timeout
      - no-silent-component-drop
      - dependency-graph-preserved
      - policy-result-stable-under-metamorphic-change
    safety:
      network: false
      human_review_required: true
    """).lstrip()
    files = {"prompt.md": prompt + "\n", f"{safe_name}.yml": yaml}
    if model["text"]: files["model-output.md"] = model["text"]
    write_artifact("campaign", files, {"kind": "ai-fuzz-campaign", "provider": model, "goal": goal})
    return 0


def cmd_disagreement(args: argparse.Namespace) -> int:
    report = Path(args.report)
    raw = redact_text(report.read_text(errors="replace") if report.exists() else "", 16000)
    prompt = prompt_header("Explain scanner disagreement") + f"\n\nScanner comparison report: {report}\n```\n{raw}\n```\nExplain likely reasons: purl mismatch, CPE fallback, ecosystem ambiguity, distro matching, transitive dependency handling, or database freshness."
    model = call_or_prompt(prompt, provider=args.provider, model=args.model)
    fallback = "Likely disagreement causes include component identity mismatch, missing purl/CPE data, scanner database freshness, ecosystem ambiguity, and transitive dependency handling differences."
    files = {"prompt.md": prompt + "\n", "disagreement-explanation.md": (model["text"] or fallback) + "\n"}
    write_artifact("disagreement", files, {"kind": "ai-explain-disagreement", "provider": model, "report": str(report)})
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ai-fuzz", description="AI-assisted fuzzing workflows. AI proposes; deterministic tools validate; humans approve.")
    ap.add_argument("--provider", default=None, help="none, ollama, or openai-compatible. Default: AI_FUZZ_PROVIDER or none.")
    ap.add_argument("--model", default=None, help="Model name for configured provider.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("seeds"); p.add_argument("--format", default="cyclonedx"); p.add_argument("--scenario", default="dependency-cycles"); p.add_argument("--count", type=int, default=3); p.set_defaults(func=cmd_seeds)
    p = sub.add_parser("mutation-plan"); p.add_argument("--sbom", required=True); p.set_defaults(func=cmd_mutation_plan)
    p = sub.add_parser("oracle-suggest"); p.add_argument("--target", required=True); p.set_defaults(func=cmd_oracle_suggest)
    p = sub.add_parser("crash-triage"); p.add_argument("--crash", required=True); p.set_defaults(func=cmd_crash_triage)
    p = sub.add_parser("regression-test"); p.add_argument("--crash", required=True); p.set_defaults(func=cmd_regression_test)
    p = sub.add_parser("harness"); p.add_argument("--target", required=True); p.set_defaults(func=cmd_harness)
    p = sub.add_parser("coverage"); p.add_argument("--coverage", required=True); p.set_defaults(func=cmd_coverage)
    p = sub.add_parser("campaign"); p.add_argument("--goal", required=True); p.set_defaults(func=cmd_campaign)
    p = sub.add_parser("disagreement"); p.add_argument("--report", required=True); p.set_defaults(func=cmd_disagreement)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    REVIEW_INCOMING.mkdir(parents=True, exist_ok=True)
    AI_CORPUS_INCOMING.mkdir(parents=True, exist_ok=True)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
