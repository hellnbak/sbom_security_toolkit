#!/usr/bin/env python3
"""Runtime hooks for executable wizards, automatic reporting, and live demo mode."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict

ALIASES = {
    "quick-scan": "analyze",
    "full-analysis": "analyze",
    "full-sbom-analysis": "analyze",
    "repository-analysis": "repo-analyze",
    "supplier-review": "supplier-intake",
    "dependency-review": "dependency-health",
    "live-demo": "demo-live",
    "demo": "demo-live",
}


def install_runtime_hooks(namespace: Dict[str, Any]) -> None:
    if namespace.get("_SST_V214_RUNTIME_HOOKS_INSTALLED"):
        return
    namespace["_SST_V214_RUNTIME_HOOKS_INSTALLED"] = True

    workflows = namespace["WORKFLOWS"]
    workflows.setdefault("demo-live", "Live offline product demonstration")
    original_create_job = namespace["create_job"]
    original_run_job = namespace["run_job"]

    def create_job(workflow: str, upload: Path, **kwargs: Any) -> str:
        normalized = ALIASES.get(workflow, workflow)
        # Do not rewrite status after the original creator starts its worker
        # thread.  Carry the requested alias in options so the worker can add
        # the execution contract without a create/start race.
        options = dict(kwargs.get("options") or {})
        options.setdefault("_requested_workflow", workflow)
        kwargs["options"] = options
        return original_create_job(normalized, upload, **kwargs)

    def run_job(job_id: str) -> None:
        started = time.time()
        initial = namespace["read_status"](job_id)
        requested_workflow = initial.get("workflow")
        initial["requested_workflow"] = (initial.get("options") or {}).get("_requested_workflow", requested_workflow)
        initial["normalized_workflow"] = requested_workflow
        initial["execution_contract_state"] = "planned"
        try:
            from sbomops.wizard_runtime import write_execution_contract
            contract = write_execution_contract(namespace["job_dir"](job_id), initial)
            initial["execution_contract"] = str(contract.relative_to(namespace["ROOT"]))
        except Exception as exc:
            namespace["append_log"](job_id, f"Execution contract warning: {exc}")
        namespace["write_status"](job_id, initial)
        is_demo = requested_workflow == "demo-live"
        if is_demo:
            from sbomops.demo_runtime import prepare_demo_evidence
            prepare_demo_evidence(job_id, namespace["job_dir"](job_id))
            initial["workflow"] = "analyze"
            initial["workflow_label"] = "Live offline product demonstration"
            initial["demo"] = {"synthetic": True, "network_required": False, "normal_pipeline": True}
            namespace["write_status"](job_id, initial)

        original_run_job(job_id)

        # Restore the user-facing workflow name after borrowing the standard
        # analysis pipeline for the live demo.
        status = namespace["read_status"](job_id)
        if is_demo:
            status["workflow"] = "demo-live"
            status["workflow_label"] = workflows["demo-live"]
            namespace["write_status"](job_id, status)

        report_started = time.time()
        report_step: Dict[str, Any] = {
            "name": "Automatic full security engineering report",
            "blocking": False,
            "automatic": True,
        }
        try:
            from sbomops.reporting_runtime import generate_default_for_job
            options = status.get("options") or {}
            provider = options.get("report_provider") or options.get("ai_provider") or "none"
            model = options.get("report_model") or options.get("ai_model") or ""
            result = generate_default_for_job(namespace["job_dir"](job_id), provider=provider, model=model)
            report_step.update({"returncode": 0, "elapsed_seconds": round(time.time() - report_started, 2), "result": result})
        except Exception as exc:
            # The scan result remains authoritative; a narrative-generation
            # problem is visible and retryable but never rewrites scan state.
            report_step.update({"returncode": 1, "elapsed_seconds": round(time.time() - report_started, 2), "error": str(exc), "scan_state_unchanged": True})
            namespace["append_log"](job_id, f"\nAutomatic reporting failed without changing scan state: {exc}\n")

        status = namespace["read_status"](job_id)
        status.setdefault("steps", []).append(report_step)
        status["execution_contract_state"] = "completed" if status.get("state") in {"completed", "failed", "cancelled"} else status.get("state")
        status["runtime_elapsed_seconds"] = round(time.time() - started, 2)
        namespace["write_status"](job_id, status)

        if is_demo:
            try:
                from sbomops.demo_runtime import finalize_demo_evidence
                summary = finalize_demo_evidence(job_id, namespace["job_dir"](job_id), namespace["read_status"](job_id))
                status = namespace["read_status"](job_id)
                status["demo_summary"] = summary
                namespace["write_status"](job_id, status)
            except Exception as exc:
                namespace["append_log"](job_id, f"Demo summary warning: {exc}")

        # Rebuild the evidence archive so the automatically generated report is
        # part of the downloadable bundle.
        try:
            bundle = namespace["create_evidence_zip"](job_id)
            status = namespace["read_status"](job_id)
            status["bundle"] = str(bundle.relative_to(namespace["ROOT"]))
            namespace["write_status"](job_id, status)
        except Exception as exc:
            namespace["append_log"](job_id, f"Evidence bundle refresh warning: {exc}")

    namespace["create_job"] = create_job
    namespace["run_job"] = run_job
