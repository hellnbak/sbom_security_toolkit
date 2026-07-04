#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
STORAGE = ROOT / "ui" / "storage"
JOBS = STORAGE / "jobs"
UPLOADS = STORAGE / "uploads"
ALLOWED_SUFFIXES = {".json", ".xml", ".spdx", ".txt"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

WORKFLOWS = {
    "analyze": "Full SBOM analysis",
    "score": "SBOM quality score",
    "minimum-elements": "CISA/NTIA minimum elements",
    "policy": "Policy check",
    "supplier-intake": "Supplier intake",
    "supplier-questions": "Supplier questions",
    "report": "Report bundle",
    "redact": "Redact SBOM",
    "scanner-compare": "Scanner comparison",
    "release-evidence": "Release evidence bundle",
    "ai-fuzz-seeds": "AI fuzz seed suggestions",
    "ai-mutation-plan": "AI mutation plan",
    "ai-fuzz-campaign": "AI fuzz campaign draft",

    # Fuzzing Lab workflows exposed in the local web UI.
    "fuzz-lab-plan": "Fuzzing Lab: recommended next plan",
    "fuzz-lab-benchmark": "Fuzzing Lab: local benchmark",
    "fuzz-lab-truthset": "Fuzzing Lab: scanner truth-set",
    "fuzz-lab-compatibility": "Fuzzing Lab: scanner compatibility matrix",
    "fuzz-lab-replay-pack": "Fuzzing Lab: replay pack from uploaded SBOM",
    "fuzz-structured": "Fuzzing Lab: structure-preserving mutations",
    "fuzz-roundtrip": "Fuzzing Lab: round-trip semantics",
    "fuzz-metamorphic": "Fuzzing Lab: metamorphic SBOM checks",
    "fuzz-oracles": "Fuzzing Lab: semantic oracle checks",
    "fuzz-toolchain": "Fuzzing Lab: scanner/toolchain fuzzing",
    "fuzz-stateful-dtrack": "Fuzzing Lab: Dependency-Track stateful dry run",
    "fuzz-metamorphic-scanners": "Fuzzing Lab: scanner metamorphic testing",
    "fuzz-generate-cyclonedx": "Fuzzing Lab: generate CycloneDX seeds",
    "fuzz-generate-spdx": "Fuzzing Lab: generate SPDX seeds",
    "fuzz-generate-vex": "Fuzzing Lab: generate VEX seeds",
    "fuzz-generate-dtrack-payloads": "Fuzzing Lab: generate Dependency-Track payload seeds",
    "fuzz-budget": "Fuzzing Lab: run budget profile",
    "fuzz-coverage": "Fuzzing Lab: coverage summary",
    "fuzz-status": "Fuzzing Lab: fuzzing status report",
    "fuzz-all-local": "Fuzzing Lab: all local smoke workflows",
    "fuzz-all-timed": "Fuzzing Lab: run all fuzzing modes with per-step time limit",
    "ai-corpus-review": "Fuzzing Lab: AI corpus review",
    "ai-harness-repair": "Fuzzing Lab: AI harness repair prompt",
    "ai-fuzz-eval": "AI fuzz provider evaluation",
    "fuzz-intelligence": "Fuzzing Lab: intelligence scoring",
    "fuzz-corpus-recommend": "Fuzzing Lab: corpus promotion recommendations",
    "fuzz-harness-audit": "Fuzzing Lab: harness quality audit",
    "ai-harness-quality-loop": "Fuzzing Lab: AI harness quality loop",
    "ai-seed-generator": "Fuzzing Lab: AI seed-generator synthesis",
    "ai-seed-generator-test": "Fuzzing Lab: AI seed-generator test",
    "fuzz-grammar": "Fuzzing Lab: grammar mutator mode",
    "fuzz-target-coverage": "Fuzzing Lab: method-targeted coverage",
    "fuzz-semantic-format-diff": "Fuzzing Lab: semantic format diff",
    "fuzz-vuln-matching": "Fuzzing Lab: vulnerability matching cases",
    "fuzz-vex-logic": "Fuzzing Lab: VEX contradiction fuzzing",
    "fuzz-evil-supplier": "Fuzzing Lab: evil supplier scenarios",
    "ai-fuzz-redteam": "Fuzzing Lab: AI provider red-team checks",
    "cflite-import-results": "Fuzzing Lab: ClusterFuzzLite result import",
    "fuzz-ci-dashboard": "Fuzzing Lab: CI fuzzing dashboard",
    "fuzz-finding-update": "Fuzzing Lab: finding lifecycle update",
    "fuzz-lab-dashboard": "Fuzzing Lab: visual dashboard",
}

FUZZ_WORKFLOWS = {k: v for k, v in WORKFLOWS.items() if k.startswith("fuzz-") or k.startswith("ai-fuzz") or k in {"ai-mutation-plan", "ai-corpus-review", "ai-harness-repair", "ai-harness-quality-loop", "ai-seed-generator", "ai-seed-generator-test", "ai-fuzz-redteam"}}



def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in Path(name).name)
    return cleaned[:180] or "upload.sbom"


def storage_init() -> None:
    JOBS.mkdir(parents=True, exist_ok=True)
    UPLOADS.mkdir(parents=True, exist_ok=True)


def job_dir(job_id: str) -> Path:
    return JOBS / job_id


def status_path(job_id: str) -> Path:
    return job_dir(job_id) / "status.json"


def logs_path(job_id: str) -> Path:
    return job_dir(job_id) / "logs.txt"


def read_status(job_id: str) -> Dict[str, Any]:
    p = status_path(job_id)
    if not p.exists():
        raise FileNotFoundError(job_id)
    return json.loads(p.read_text())


def write_status(job_id: str, data: Dict[str, Any]) -> None:
    d = job_dir(job_id); d.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = now()
    status_path(job_id).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def append_log(job_id: str, text: str) -> None:
    with logs_path(job_id).open("a", encoding="utf-8") as f:
        f.write(text)
        if text and not text.endswith("\n"):
            f.write("\n")


def list_jobs() -> List[Dict[str, Any]]:
    storage_init()
    out = []
    for p in sorted(JOBS.iterdir(), reverse=True):
        if p.is_dir() and (p / "status.json").exists():
            try:
                out.append(json.loads((p / "status.json").read_text()))
            except Exception:
                pass
    return out


def save_upload(filename: str, content: bytes) -> Path:
    storage_init()
    name = safe_name(filename)
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError(f"Unsupported file type: {suffix or '(none)'}")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload too large. Max size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    dest = UPLOADS / f"{int(time.time())}-{uuid.uuid4().hex[:8]}-{name}"
    dest.write_bytes(content)
    return dest


def create_job(workflow: str, upload: Path, *, policy: str = "policies/default-release-policy.yml", network: bool = False, options: Optional[Dict[str, str]] = None) -> str:
    if workflow not in WORKFLOWS:
        raise ValueError(f"Unknown workflow: {workflow}")
    job_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    d = job_dir(job_id)
    (d / "input").mkdir(parents=True, exist_ok=True)
    (d / "results").mkdir(parents=True, exist_ok=True)
    input_path = d / "input" / safe_name(upload.name)
    shutil.copy2(upload, input_path)
    status = {
        "job_id": job_id,
        "workflow": workflow,
        "workflow_label": WORKFLOWS[workflow],
        "state": "queued",
        "created_at": now(),
        "updated_at": now(),
        "input_file": str(input_path.relative_to(ROOT)),
        "policy": policy,
        "network_enabled": bool(network),
        "options": options or {},
        "exit_code": None,
        "results_dir": str((d / "results").relative_to(ROOT)),
        "error": None,
    }
    write_status(job_id, status)
    t = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    t.start()
    return job_id


def module_cmd(module: str, *args: Any) -> List[str]:
    return [sys.executable, "-m", module, *map(str, args)]


def run_step(job_id: str, name: str, cmd: List[str], timeout: int = 600, *, timeout_ok: bool = False, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    append_log(job_id, f"\n=== {name} ===\n$ {' '.join(cmd)}")
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout, env=env)
        elapsed = round(time.time() - started, 2)
        if proc.stdout:
            append_log(job_id, proc.stdout[-12000:])
        if proc.stderr:
            append_log(job_id, proc.stderr[-12000:])
        return {"name": name, "cmd": cmd, "returncode": proc.returncode, "elapsed_seconds": elapsed}
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.time() - started, 2)
        append_log(job_id, f"Timed out after {timeout} seconds. This is expected for time-boxed fuzzing runs.\n")
        if exc.stdout:
            append_log(job_id, str(exc.stdout)[-12000:])
        if exc.stderr:
            append_log(job_id, str(exc.stderr)[-12000:])
        return {"name": name, "cmd": cmd, "returncode": 0 if timeout_ok else 124, "elapsed_seconds": elapsed, "timed_out": True}



def option(status: Dict[str, Any], name: str, default: str = "") -> str:
    value = (status.get("options") or {}).get(name, default)
    return str(value or default)


def option_int(status: Dict[str, Any], name: str, default: int, *, low: int = 1, high: int = 1000) -> int:
    try:
        value = int(option(status, name, str(default)))
    except ValueError:
        value = default
    return max(low, min(high, value))


def ensure_placeholder_finding(sbom: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    finding = out / "finding.json"
    finding.write_text(json.dumps({
        "finding_id": "workbench-uploaded-sbom",
        "summary": "Replay pack generated from the uploaded SBOM.",
        "input": str(sbom),
        "severity": "informational"
    }, indent=2) + "\n")
    return finding

def run_job(job_id: str) -> None:
    status = read_status(job_id)
    status["state"] = "running"; status["started_at"] = now(); write_status(job_id, status)
    d = job_dir(job_id)
    sbom = ROOT / status["input_file"]
    out = d / "results"
    policy = status.get("policy") or "policies/default-release-policy.yml"
    workflow = status["workflow"]
    count = option_int(status, "count", 10, low=1, high=250)
    duration_seconds = option_int(status, "duration_seconds", 60, low=5, high=86400)
    edge = option(status, "edge", "valid-edge")
    budget_profile = option(status, "budget_profile", "fuzzing/budgets/pr-smoke.yml")
    ai_provider = option(status, "ai_provider", "none")
    ai_model = option(status, "ai_model", "")
    ai_goal = option(status, "ai_goal", "sbom-workbench-upload-hardening")
    dtrack_url = option(status, "dtrack_url", "http://127.0.0.1:8081")
    library_targets = [x.strip().lower() for x in option(status, "library_targets", "sbom,scanner,ai").split(",") if x.strip()]
    steps: List[Dict[str, Any]] = []
    try:
        if workflow in {"analyze", "score"}:
            steps.append(run_step(job_id, "SBOM quality", module_cmd("sbomops.score_sbom", sbom, "--out-dir", out / "sbom-quality")))
        if workflow in {"analyze", "minimum-elements"}:
            steps.append(run_step(job_id, "Minimum elements", module_cmd("sbomops.minimum_elements", sbom, "--out-dir", out / "minimum-elements")))
        if workflow in {"analyze", "policy"}:
            steps.append(run_step(job_id, "Policy check", module_cmd("sbomops.policy_check", sbom, "--policy", policy, "--out-dir", out / "policy")))
        if workflow in {"analyze", "supplier-intake"}:
            steps.append(run_step(job_id, "Supplier intake", module_cmd("sbomops.supplier_intake", sbom, "--out-dir", out / "supplier-intake")))
        if workflow in {"analyze", "supplier-questions"}:
            steps.append(run_step(job_id, "Supplier questions", module_cmd("sbomops.supplier_questions", sbom, "--out-dir", out / "supplier-questions")))
        if workflow in {"analyze", "report"}:
            steps.append(run_step(job_id, "Report bundle", module_cmd("sbomops.report", sbom, "--out-dir", out / "bundle")))
        if workflow == "redact":
            steps.append(run_step(job_id, "Redact SBOM", module_cmd("sbomops.redact", sbom, "--out", out / "redacted-sbom.json", "--hash-internal-names")))
        if workflow == "scanner-compare":
            steps.append(run_step(job_id, "Scanner compare", module_cmd("sbomops.scanner_compare", sbom, "--out-dir", out / "scanner-compare"), timeout=900))

        if workflow == "ai-fuzz-seeds":
            steps.append(run_step(job_id, "AI fuzz seeds", module_cmd("ai_fuzz.tools.ai_fuzz", "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "seeds", "--format", "cyclonedx", "--scenario", option(status, "scenario", "dependency-cycles"), "--count", str(count))))
        if workflow == "ai-mutation-plan":
            steps.append(run_step(job_id, "AI mutation plan", module_cmd("ai_fuzz.tools.ai_fuzz", "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "mutation-plan", "--sbom", sbom)))
        if workflow == "ai-fuzz-campaign":
            steps.append(run_step(job_id, "AI fuzz campaign", module_cmd("ai_fuzz.tools.ai_fuzz", "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "campaign", "--goal", ai_goal)))

        if workflow == "fuzz-lab-plan":
            steps.append(run_step(job_id, "Fuzz plan", [sys.executable, "fuzzing/planner/fuzz_plan.py", "--out", str(out / "fuzz-plan.md")]))
        if workflow == "fuzz-lab-benchmark":
            steps.append(run_step(job_id, "Fuzz benchmark", [sys.executable, "fuzzing/benchmarks/run_benchmark.py", "--sbom", str(sbom), "--out", str(out / "fuzz-benchmark.json")], timeout=900))
        if workflow == "fuzz-lab-truthset":
            steps.append(run_step(job_id, "Scanner truth-set", [sys.executable, "fuzzing/truthset/scanner_truthset.py", "--out", str(out / "truthset-results.json")], timeout=900))
        if workflow == "fuzz-lab-compatibility":
            steps.append(run_step(job_id, "Scanner compatibility", [sys.executable, "fuzzing/compatibility/scanner_compatibility.py", "--out", str(out / "scanner-compatibility.json")], timeout=900))
        if workflow == "fuzz-lab-replay-pack":
            steps.append(run_step(job_id, "Replay pack", [sys.executable, "fuzzing/replay/create_replay_pack.py", str(sbom), "--out-dir", str(out / "replay-pack")]))
        if workflow == "fuzz-structured":
            steps.append(run_step(job_id, "Structure-preserving SBOM mutation", [sys.executable, "fuzzing/mutators/sbom_json_mutator.py", str(sbom), "--out", str(out / "structured-corpus"), "--count", str(count)]))
        if workflow == "fuzz-roundtrip":
            steps.append(run_step(job_id, "Round-trip semantic fuzzing", [sys.executable, "fuzzing/roundtrip/roundtrip_sbom.py", str(sbom), "--out-dir", str(out / "roundtrip")]))
        if workflow == "fuzz-metamorphic":
            steps.append(run_step(job_id, "Metamorphic SBOM fuzzing", [sys.executable, "fuzzing/metamorphic/metamorphic_sbom.py", str(sbom), "--out-dir", str(out / "metamorphic")]))
        if workflow == "fuzz-oracles":
            steps.append(run_step(job_id, "Semantic oracle checks", [sys.executable, "fuzzing/oracles/semantic_oracles.py", str(sbom), "--out", str(out / "semantic-oracles.json")]))
        if workflow == "fuzz-toolchain":
            steps.append(run_step(job_id, "Scanner/toolchain fuzzing", [sys.executable, "fuzzing/toolchain/fuzz_toolchain.py", str(sbom), "--out", str(out / "toolchain-fuzz.json")], timeout=900))
        if workflow == "fuzz-stateful-dtrack":
            steps.append(run_step(job_id, "Dependency-Track stateful dry-run fuzzing", [sys.executable, "fuzzing/stateful/dependency_track_state_machine.py", "--url", dtrack_url, "--sbom", str(sbom), "--dry-run", "--out", str(out / "dependency-track-stateful.json")], timeout=900))
        if workflow == "fuzz-metamorphic-scanners":
            steps.append(run_step(job_id, "Scanner metamorphic testing", [sys.executable, "fuzzing/scanner-metamorphic/metamorphic_scanners.py", str(sbom), "--out-dir", str(out / "scanner-metamorphic")], timeout=900))
        if workflow == "fuzz-generate-cyclonedx":
            steps.append(run_step(job_id, "Generate CycloneDX seeds", [sys.executable, "fuzzing/schema/cyclonedx_schema_generator.py", "--count", str(count), "--edge", edge, "--out", str(out / "generated-cyclonedx")]))
        if workflow == "fuzz-generate-spdx":
            steps.append(run_step(job_id, "Generate SPDX seeds", [sys.executable, "fuzzing/schema/spdx_schema_generator.py", "--count", str(count), "--edge", edge, "--out", str(out / "generated-spdx")]))
        if workflow == "fuzz-generate-vex":
            steps.append(run_step(job_id, "Generate VEX seeds", [sys.executable, "fuzzing/schema/vex_schema_generator.py", "--count", str(count), "--out", str(out / "generated-vex")]))
        if workflow == "fuzz-generate-dtrack-payloads":
            steps.append(run_step(job_id, "Generate Dependency-Track payload seeds", [sys.executable, "fuzzing/schema/dependency_track_payload_generator.py", str(sbom), "--count", str(count), "--out", str(out / "generated-dtrack-payloads")]))
        if workflow == "fuzz-budget":
            steps.append(run_step(job_id, "Run fuzzing budget profile", [sys.executable, "fuzzing/budgets/run_budget.py", budget_profile, "--out", str(out / "fuzz-budget.json")]))
        if workflow == "fuzz-coverage":
            steps.append(run_step(job_id, "Fuzz coverage summary", [sys.executable, "fuzzing/coverage/coverage_report.py", "--out", str(out / "fuzz-coverage.md")]))
        if workflow == "fuzz-status":
            steps.append(run_step(job_id, "Fuzzing status report", [sys.executable, "fuzzing/status_report.py", "--out", str(out / "fuzz-status.md")]))
        if workflow == "fuzz-all-local":
            for step_name, cmd in [
                ("Generate CycloneDX seeds", [sys.executable, "fuzzing/schema/cyclonedx_schema_generator.py", "--count", str(min(count, 10)), "--edge", edge, "--out", str(out / "all-local" / "cyclonedx")]),
                ("Generate SPDX seeds", [sys.executable, "fuzzing/schema/spdx_schema_generator.py", "--count", str(min(count, 10)), "--edge", edge, "--out", str(out / "all-local" / "spdx")]),
                ("Generate VEX seeds", [sys.executable, "fuzzing/schema/vex_schema_generator.py", "--count", str(min(count, 10)), "--out", str(out / "all-local" / "vex")]),
                ("Structure mutations", [sys.executable, "fuzzing/mutators/sbom_json_mutator.py", str(sbom), "--out", str(out / "all-local" / "structured"), "--count", str(min(count, 25))]),
                ("Round-trip", [sys.executable, "fuzzing/roundtrip/roundtrip_sbom.py", str(sbom), "--out-dir", str(out / "all-local" / "roundtrip")]),
                ("Metamorphic", [sys.executable, "fuzzing/metamorphic/metamorphic_sbom.py", str(sbom), "--out-dir", str(out / "all-local" / "metamorphic")]),
                ("Semantic oracles", [sys.executable, "fuzzing/oracles/semantic_oracles.py", str(sbom), "--out", str(out / "all-local" / "semantic-oracles.json")]),
                ("Toolchain fuzzing", [sys.executable, "fuzzing/toolchain/fuzz_toolchain.py", str(sbom), "--out", str(out / "all-local" / "toolchain.json")]),
                ("Scanner metamorphic", [sys.executable, "fuzzing/scanner-metamorphic/metamorphic_scanners.py", str(sbom), "--out-dir", str(out / "all-local" / "scanner-metamorphic")]),
                ("Vulnerability matching cases", [sys.executable, "fuzzing/vuln_matching/vuln_matching_fuzz.py", "--out-dir", str(out / "all-local" / "vuln-matching")]),
                ("VEX logic cases", [sys.executable, "fuzzing/vex_logic/vex_logic_fuzz.py", "--out-dir", str(out / "all-local" / "vex-logic")]),
                ("Evil supplier scenarios", [sys.executable, "fuzzing/evil_supplier/evil_supplier.py", "--out-dir", str(out / "all-local" / "evil-supplier")]),
                ("Fuzzing status", [sys.executable, "fuzzing/status_report.py", "--out", str(out / "all-local" / "fuzz-status.md")]),
            ]:
                steps.append(run_step(job_id, step_name, cmd, timeout=900))
        if workflow == "fuzz-all-timed":
            timed_env = os.environ.copy()
            timed_env["TIME_BUDGET"] = str(duration_seconds)
            timed_env["FUZZ_MAX_SECONDS"] = str(duration_seconds)
            timed_plan = [
                ("Generate CycloneDX seeds", [sys.executable, "fuzzing/schema/cyclonedx_schema_generator.py", "--count", str(min(count, 25)), "--edge", edge, "--out", str(out / "timed" / "cyclonedx")]),
                ("Generate SPDX seeds", [sys.executable, "fuzzing/schema/spdx_schema_generator.py", "--count", str(min(count, 25)), "--edge", edge, "--out", str(out / "timed" / "spdx")]),
                ("Generate VEX seeds", [sys.executable, "fuzzing/schema/vex_schema_generator.py", "--count", str(min(count, 25)), "--out", str(out / "timed" / "vex")]),
                ("Structure mutations", [sys.executable, "fuzzing/mutators/sbom_json_mutator.py", str(sbom), "--out", str(out / "timed" / "structured"), "--count", str(min(count, 50))]),
                ("Round-trip", [sys.executable, "fuzzing/roundtrip/roundtrip_sbom.py", str(sbom), "--out-dir", str(out / "timed" / "roundtrip")]),
                ("Metamorphic", [sys.executable, "fuzzing/metamorphic/metamorphic_sbom.py", str(sbom), "--out-dir", str(out / "timed" / "metamorphic")]),
                ("Semantic oracles", [sys.executable, "fuzzing/oracles/semantic_oracles.py", str(sbom), "--out", str(out / "timed" / "semantic-oracles.json")]),
                ("Toolchain fuzzing", [sys.executable, "fuzzing/toolchain/fuzz_toolchain.py", str(sbom), "--out", str(out / "timed" / "toolchain.json"), "--timeout", str(max(5, duration_seconds))]),
                ("Dependency-Track dry-run", [sys.executable, "fuzzing/stateful/dependency_track_state_machine.py", "--url", dtrack_url, "--sbom", str(sbom), "--dry-run", "--out", str(out / "timed" / "dependency-track-stateful.json")]),
                ("Scanner metamorphic", [sys.executable, "fuzzing/scanner-metamorphic/metamorphic_scanners.py", str(sbom), "--out-dir", str(out / "timed" / "scanner-metamorphic")]),
                ("Budget profile", [sys.executable, "fuzzing/budgets/run_budget.py", budget_profile, "--out", str(out / "timed" / "budget.json")]),
                ("Fuzz intelligence", [sys.executable, "fuzzing/intelligence/intelligence_score.py", "--inputs", "fuzzing/findings", "fuzzing/generated-corpus", "test-sboms", "--out-dir", str(out / "timed" / "intelligence")]),
                ("Vulnerability matching", [sys.executable, "fuzzing/vuln_matching/vuln_matching_fuzz.py", "--out-dir", str(out / "timed" / "vuln-matching")]),
                ("VEX logic", [sys.executable, "fuzzing/vex_logic/vex_logic_fuzz.py", "--out-dir", str(out / "timed" / "vex-logic")]),
                ("Evil supplier", [sys.executable, "fuzzing/evil_supplier/evil_supplier.py", "--out-dir", str(out / "timed" / "evil-supplier")]),
                ("Grammar mutator", [sys.executable, "fuzzing/grammar/run_grammar_mutator.py", "--grammar", option(status, "grammar", "cyclonedx"), "--count", str(min(count, 25)), "--out", str(out / "timed" / "grammar")]),
                ("Fuzz status", [sys.executable, "fuzzing/status_report.py", "--out", str(out / "timed" / "fuzz-status.md")]),
            ]
            if "ai" in library_targets:
                timed_plan.extend([
                    ("AI corpus review", [sys.executable, "ai_fuzz/tools/ai_corpus_review.py", "--corpus", "fuzzing/corpus/ai/incoming", "--out", str(out / "timed" / "ai-corpus-review.md")]),
                    ("AI provider evaluation", [sys.executable, "-m", "ai_fuzz.tools.ai_eval", "--providers", "none,glm", "--out", str(out / "timed" / "ai-fuzz-provider-eval.json")]),
                ])
            if shutil.which("docker") and any(x in library_targets for x in ["python", "javascript", "js", "php"]):
                if "python" in library_targets:
                    timed_plan.append(("Python engine smoke", ["bash", "-lc", f"docker build -t sbom-fuzzer-python fuzzing/engines/python >/dev/null && docker run --rm -e TIME_BUDGET={duration_seconds} sbom-fuzzer-python"]))
                if "javascript" in library_targets or "js" in library_targets:
                    timed_plan.append(("JavaScript engine smoke", ["bash", "-lc", f"docker build -t sbom-fuzzer-javascript fuzzing/engines/javascript >/dev/null && docker run --rm -e TIME_BUDGET={duration_seconds} sbom-fuzzer-javascript"]))
                if "php" in library_targets:
                    timed_plan.append(("PHP engine smoke", ["bash", "-lc", f"docker build -t sbom-fuzzer-php fuzzing/engines/php >/dev/null && docker run --rm -e TIME_BUDGET={duration_seconds} sbom-fuzzer-php"]))
            for step_name, cmd in timed_plan:
                steps.append(run_step(job_id, step_name, cmd, timeout=duration_seconds + 10, timeout_ok=True, env=timed_env))
        if workflow == "ai-corpus-review":
            steps.append(run_step(job_id, "AI corpus review", [sys.executable, "ai_fuzz/tools/ai_corpus_review.py", "--corpus", "fuzzing/corpus/ai/incoming", "--out", str(out / "ai-corpus-review.md")]))
        if workflow == "ai-harness-repair":
            target = option(status, "target", "fuzzing/engines/python/targets/cyclonedx_json_atheris.py")
            steps.append(run_step(job_id, "AI harness repair prompt", [sys.executable, "ai_fuzz/tools/ai_harness_repair.py", "--target", target, "--out", str(out / "ai-harness-repair.md")]))

        if workflow == "ai-fuzz-eval":
            steps.append(run_step(job_id, "AI fuzz provider evaluation", [sys.executable, "-m", "ai_fuzz.tools.ai_eval", "--providers", "none,glm", "--out", str(out / "ai-fuzz-provider-eval.json")]))

        if workflow == "fuzz-intelligence":
            steps.append(run_step(job_id, "Fuzzing intelligence", [sys.executable, "fuzzing/intelligence/intelligence_score.py", "--inputs", "fuzzing/findings", "fuzzing/generated-corpus", "test-sboms", "--out-dir", str(out / "intelligence")]))
        if workflow == "fuzz-corpus-recommend":
            steps.append(run_step(job_id, "Corpus promotion recommendations", [sys.executable, "fuzzing/corpus/recommend.py", "--corpus", "fuzzing/corpus/ai/incoming", "--out-dir", str(out / "corpus-recommendations")]))
        if workflow == "fuzz-harness-audit":
            target = option(status, "target", "fuzzing/engines/python/targets/cyclonedx_json_atheris.py")
            steps.append(run_step(job_id, "Harness quality audit", [sys.executable, "fuzzing/harness/audit.py", target, "--out", str(out / "harness-audit.json")]))
        if workflow == "ai-harness-quality-loop":
            target = option(status, "target", "sbomops/minimum_elements.py")
            steps.append(run_step(job_id, "AI harness quality loop", [sys.executable, "-m", "ai_fuzz.tools.ai_harness_quality_loop", "--target", target, "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "--out-dir", str(out / "ai-harness-quality-loop")]))
        if workflow == "ai-seed-generator":
            steps.append(run_step(job_id, "AI seed-generator synthesis", [sys.executable, "-m", "ai_fuzz.tools.ai_seed_generator", "--goal", ai_goal, "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "--out-dir", str(out / "ai-seed-generator")]))
        if workflow == "ai-seed-generator-test":
            target = option(status, "target", "")
            if not target:
                target = "ai_fuzz/review/incoming/generators/" + ai_goal.replace(" ", "-") + "_generator.py"
            steps.append(run_step(job_id, "AI seed-generator test", [sys.executable, "-m", "ai_fuzz.tools.ai_seed_generator_test", "--generator", target, "--out", str(out / "ai-seed-generator-test.json")]))
        if workflow == "fuzz-grammar":
            steps.append(run_step(job_id, "Grammar mutator", [sys.executable, "fuzzing/grammar/run_grammar_mutator.py", "--grammar", option(status, "grammar", "cyclonedx"), "--count", str(count), "--out", str(out / "grammar-corpus")]))
        if workflow == "fuzz-target-coverage":
            target = option(status, "target", "sbomops.minimum_elements:main")
            steps.append(run_step(job_id, "Method-targeted coverage", [sys.executable, "fuzzing/coverage/target_coverage.py", "--target", target, "--out", str(out / "target-coverage.json")]))
        if workflow == "fuzz-semantic-format-diff":
            steps.append(run_step(job_id, "Semantic format diff", [sys.executable, "fuzzing/semantic_format_diff/semantic_format_diff.py", str(sbom), str(sbom), "--out", str(out / "semantic-format-diff.json")]))
        if workflow == "fuzz-vuln-matching":
            steps.append(run_step(job_id, "Vulnerability matching fuzz cases", [sys.executable, "fuzzing/vuln_matching/vuln_matching_fuzz.py", "--out-dir", str(out / "vuln-matching")]))
        if workflow == "fuzz-vex-logic":
            steps.append(run_step(job_id, "VEX contradiction fuzz cases", [sys.executable, "fuzzing/vex_logic/vex_logic_fuzz.py", "--out-dir", str(out / "vex-logic")]))
        if workflow == "fuzz-evil-supplier":
            steps.append(run_step(job_id, "Evil supplier SBOM scenarios", [sys.executable, "fuzzing/evil_supplier/evil_supplier.py", "--out-dir", str(out / "evil-supplier")]))
        if workflow == "ai-fuzz-redteam":
            steps.append(run_step(job_id, "AI fuzz red-team", [sys.executable, "-m", "ai_fuzz.tools.ai_redteam", "--provider", ai_provider, *( ["--model", ai_model] if ai_model else [] ), "--out", str(out / "ai-fuzz-redteam.json")]))
        if workflow == "cflite-import-results":
            steps.append(run_step(job_id, "ClusterFuzzLite result import", [sys.executable, "fuzzing/clusterfuzzlite/import_results.py", "--out", str(out / "clusterfuzzlite-results.json")]))
        if workflow == "fuzz-ci-dashboard":
            steps.append(run_step(job_id, "CI fuzzing dashboard", [sys.executable, "fuzzing/clusterfuzzlite/ci_dashboard.py", "--out", str(out / "ci-dashboard.html")]))
        if workflow == "fuzz-finding-update":
            steps.append(run_step(job_id, "Fuzz finding lifecycle update", [sys.executable, "fuzzing/findings_lifecycle/lifecycle.py", "--finding", option(status, "finding_id", "workbench-demo-finding"), "--state", option(status, "finding_state", "triaged"), "--notes", "Updated from local workbench"] ))
        if workflow == "fuzz-lab-dashboard":
            steps.append(run_step(job_id, "Fuzzing Lab dashboard", [sys.executable, "fuzzing/visualize/fuzzing_lab_dashboard.py", "--out", str(out / "lab-dashboard.html")]))
        if workflow == "release-evidence":
            env = os.environ.copy(); env.update({"SBOM": str(sbom), "POLICY": policy, "OUT": str(out / "release-evidence")})
            cmd = ["bash", "scripts/release-evidence.sh"]
            append_log(job_id, f"\n=== Release evidence ===\n$ {' '.join(cmd)}")
            proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=900, env=env)
            steps.append({"name":"Release evidence", "cmd":cmd, "returncode":proc.returncode})
            append_log(job_id, proc.stdout[-12000:] + proc.stderr[-12000:])
        # Always generate a UI bundle from available outputs.
        steps.append(run_step(job_id, "UI bundle", module_cmd("sbomops.ui_bundle", "--reports-dir", out, "--out-dir", out / "ui")))
        bundle = create_evidence_zip(job_id)
        failed = [s for s in steps if s.get("returncode") not in (0, None)]
        status.update({"state": "failed" if failed else "completed", "exit_code": 1 if failed else 0, "steps": steps, "completed_at": now(), "bundle": str(bundle.relative_to(ROOT))})
        if failed:
            status["error"] = f"{len(failed)} step(s) failed. See logs."
    except Exception as exc:
        append_log(job_id, f"\nERROR: {exc}\n")
        status.update({"state": "failed", "exit_code": 1, "error": str(exc), "steps": steps, "completed_at": now()})
    write_status(job_id, status)


def create_evidence_zip(job_id: str) -> Path:
    d = job_dir(job_id)
    dest = d / "evidence-bundle.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in ["input", "results", "status.json", "logs.txt"]:
            p = d / rel
            if p.is_file():
                z.write(p, p.name)
            elif p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file():
                        z.write(f, str(Path(rel) / f.relative_to(p)))
    return dest


def delete_job(job_id: str) -> None:
    d = job_dir(job_id)
    if d.exists():
        shutil.rmtree(d)


def scanner_status() -> List[Dict[str, Any]]:
    tools = ["syft", "trivy", "grype", "osv-scanner", "cosign", "docker", "git"]
    rows = []
    for tool in tools:
        path = shutil.which(tool)
        rows.append({"tool": tool, "available": bool(path), "path": path or "", "note": "optional" if tool != "git" else "recommended"})
    return rows
