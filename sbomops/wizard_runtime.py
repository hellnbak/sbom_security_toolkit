#!/usr/bin/env python3
"""Translate guided UX choices into executable Workbench jobs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parents[1]


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", (value or "guided").lower()).strip("-") or "guided"


def _policy_path(preset: str) -> str:
    candidates = {
        "basic": ["policies/basic.yml", "policies/default-release-policy.yml"],
        "standard": ["policies/default-release-policy.yml", "policies/standard.yml"],
        "production": ["policies/production-release-policy.yml", "policies/default-release-policy.yml"],
        "high-assurance": ["policies/high-assurance.yml", "policies/default-release-policy.yml"],
    }.get(preset or "standard", ["policies/default-release-policy.yml"])
    for value in candidates:
        if (ROOT / value).exists():
            return value
    return "policies/default-release-policy.yml"


def _sample_sbom() -> Path:
    for rel in ("test-sboms/example-spdx-2.3.json", "test-sboms/clean/minimal-cyclonedx.json"):
        p = ROOT / rel
        if p.exists():
            return p
    from sbomops.demo_runtime import ensure_demo_sbom
    return ensure_demo_sbom()


def _source_job_input(source: str, goal: str) -> Tuple[Path, str, Dict[str, str]]:
    source = (source or "").strip()
    if not source:
        if goal == "repository" and (ROOT / "test-repos" / "demo-mixed").exists():
            source = str(ROOT / "test-repos" / "demo-mixed")
        else:
            return _sample_sbom(), "analyze", {}

    if source.startswith(("https://", "http://", "git@")):
        placeholder = ROOT / "ui" / "storage" / "guided" / f"{_slug(source)}.source.txt"
        placeholder.parent.mkdir(parents=True, exist_ok=True)
        placeholder.write_text(source + "\n", encoding="utf-8")
        return placeholder, "repo-analyze", {"repo_source": source, "repo_source_type": "github", "repo_allow_remote": "1"}

    p = Path(source).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    if p.exists() and p.is_dir():
        placeholder = ROOT / "ui" / "storage" / "guided" / f"{_slug(p.name)}.source.txt"
        placeholder.parent.mkdir(parents=True, exist_ok=True)
        placeholder.write_text(str(p.resolve()) + "\n", encoding="utf-8")
        return placeholder, "repo-analyze", {"repo_source": str(p.resolve()), "repo_source_type": "local"}
    if p.exists() and p.is_file():
        return p, "analyze", {}

    raise ValueError(f"Guided source was not found: {source}")


def task_to_workflow(task: str) -> str:
    value = (task or "").lower()
    if "supplier" in value or "vendor" in value:
        return "supplier-intake"
    if "lifecycle" in value or "dependency" in value or "unsupported" in value:
        return "dependency-health"
    if "fuzz" in value:
        return "fuzz-all-timed"
    if "score" in value or "quality" in value:
        return "score"
    if "minimum" in value or "compliance" in value:
        return "minimum-elements"
    if "release" in value:
        return "release-review"
    if "policy" in value:
        return "policy"
    if "compare" in value:
        return "scanner-compare"
    if "repository" in value or "repo" in value:
        return "repo-analyze"
    return "analyze"


def start_guided(*, task: str, source: str = "", profile: str = "standard", environment: str = "production", project_id: str = "guided-project") -> str:
    from sbomops.workbench.job_runner import create_job

    goal = "repository" if "repo" in (task or "").lower() else "sbom"
    upload, inferred, source_options = _source_job_input(source, goal)
    workflow = task_to_workflow(task)
    if workflow == "repo-analyze" and inferred != "repo-analyze":
        workflow = inferred
    if workflow != "repo-analyze" and inferred == "repo-analyze":
        workflow = "repo-analyze"
    options = {
        "project_id": _slug(project_id),
        "environment": environment,
        "scan_profile": profile,
        "repo_dependency_health": "0" if profile == "quick" else "1",
        "repo_fuzz": "1" if profile in {"full", "fuzz"} else "0",
        "stale_days": "365",
        "lifecycle_sources": "sbom,known",
        "offline_cache_only": "1",
        "duration_seconds": "10",
        "library_targets": "sbom",
        **source_options,
    }
    network_enabled = source_options.get("repo_source_type") == "github"
    return create_job(workflow, upload, policy=_policy_path(profile), network=network_enabled, options=options)


def start_from_guide(state: Dict[str, Any]) -> Dict[str, str]:
    goal = str(state.get("goal") or "repository")
    if goal == "connector":
        return {"route": "/connectors/setup"}
    source = str(state.get("source") or "")
    profile = str(state.get("policy") or "standard")
    environment = str(state.get("environment") or "production")
    task = "repository-analysis" if goal == "repository" else "release-review" if goal == "release" else "sbom-analysis"
    job_id = start_guided(task=task, source=source, profile=profile, environment=environment, project_id=state.get("project_id", "guided-project"))
    return {"job_id": job_id, "route": f"/jobs/{job_id}"}


def start_project(project: Dict[str, Any]) -> Dict[str, str]:
    source = str(project.get("source") or "")
    task = "repository-analysis" if source and not source.lower().endswith((".json", ".xml", ".spdx", ".txt")) else "sbom-analysis"
    job_id = start_guided(
        task=task,
        source=source,
        profile=str(project.get("default_policy") or "standard"),
        environment=str(project.get("environment") or "production"),
        project_id=str(project.get("project_id") or "project"),
    )
    return {"job_id": job_id, "route": f"/jobs/{job_id}"}


def write_execution_contract(job_dir: Path, status: Dict[str, Any]) -> Path:
    workflow = status.get("workflow", "analyze")
    plans = {
        "analyze": ["SBOM quality", "Minimum elements", "Policy check", "Supplier intake", "Supplier questions", "Report bundle", "UI bundle", "Automatic security engineering report"],
        "release-review": ["SBOM analysis", "Deterministic release assurance", "Evidence bundle", "Automatic security engineering report"],
        "scanner-compare": ["Scanner availability and comparison", "Automatic security engineering report"],
        "repo-analyze": ["Repository intake and SBOM generation", "Dependency health", "Evidence outputs", "Automatic security engineering report"],
        "demo-live": ["Synthetic demo preparation", "Normal analysis pipeline", "Evidence bundle", "Automatic security engineering report"],
    }
    payload = {
        "workflow": workflow,
        "workflow_label": status.get("workflow_label", workflow),
        "will_execute": plans.get(workflow, [status.get("workflow_label", workflow), "Automatic security engineering report"]),
        "completion_requires_terminal_state": True,
        "automatic_report_required": True,
        "report_failure_is_non_blocking": True,
    }
    target = job_dir / "execution-contract.json"
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
