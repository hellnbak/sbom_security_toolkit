#!/usr/bin/env python3
"""A real, offline, synthetic Workbench demonstration.

The demo uses the normal Workbench job runner and normal analysis/reporting
completion path.  It does not require credentials or network access and every
artifact is explicitly marked synthetic.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import time
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def ensure_demo_sbom() -> Path:
    path = ROOT / "ui" / "storage" / "demo" / "synthetic-demo.cdx.json"
    payload: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:11111111-2222-4333-8444-555555555555",
        "version": 1,
        "metadata": {
            "timestamp": now_iso(),
            "component": {"type": "application", "name": "synthetic-payment-service", "version": "2026.07-demo"},
            "properties": [
                {"name": "sst:demo", "value": "true"},
                {"name": "sst:data-classification", "value": "synthetic-only"},
            ],
        },
        "components": [
            {"type": "library", "name": "demo-auth-core", "version": "1.0.0", "purl": "pkg:pypi/demo-auth-core@1.0.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "demo-legacy-parser", "version": "0.8.1", "purl": "pkg:npm/demo-legacy-parser@0.8.1", "licenses": [{"license": {"id": "Apache-2.0"}}], "properties": [{"name": "sst:lifecycle", "value": "end-of-life"}]},
            {"type": "library", "name": "demo-crypto-wrapper", "version": "2.1.0", "purl": "pkg:maven/example/demo-crypto-wrapper@2.1.0"},
            {"type": "library", "name": "demo-json", "version": "4.2.0", "purl": "pkg:golang/example.org/demo-json@v4.2.0", "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
            {"type": "library", "name": "demo-logging", "version": "1.4.3", "purl": "pkg:nuget/Demo.Logging@1.4.3"},
            {"type": "library", "name": "demo-transitive-util", "version": "0.1.2", "purl": "pkg:cargo/demo-transitive-util@0.1.2"},
        ],
        "dependencies": [
            {"ref": "synthetic-payment-service", "dependsOn": ["pkg:pypi/demo-auth-core@1.0.0", "pkg:npm/demo-legacy-parser@0.8.1", "pkg:maven/example/demo-crypto-wrapper@2.1.0"]},
            {"ref": "pkg:maven/example/demo-crypto-wrapper@2.1.0", "dependsOn": ["pkg:cargo/demo-transitive-util@0.1.2"]},
        ],
        "vulnerabilities": [
            {"id": "DEMO-2026-0001", "ratings": [{"severity": "critical", "score": 9.8}], "affects": [{"ref": "pkg:npm/demo-legacy-parser@0.8.1"}], "description": "Synthetic critical parser finding used only to demonstrate prioritization."},
            {"id": "DEMO-2026-0002", "ratings": [{"severity": "high", "score": 8.1}], "affects": [{"ref": "pkg:maven/example/demo-crypto-wrapper@2.1.0"}], "description": "Synthetic high-severity dependency finding used only for demo output."},
        ],
    }
    return _write_json(path, payload)


def prepare_demo_evidence(job_id: str, job_dir: Path) -> Dict[str, Any]:
    report_root = ROOT / "reports" / "demo-live" / job_id
    findings = {
        "generated_at": now_iso(),
        "synthetic": True,
        "project": "synthetic-payment-service",
        "findings": [
            {"finding_id": "DEMO-2026-0001", "title": "Synthetic parser memory-safety risk", "severity": "critical", "status": "new", "component": "demo-legacy-parser", "owner": "application-security", "source": "demo-mode"},
            {"finding_id": "DEMO-2026-0002", "title": "Synthetic crypto wrapper weakness", "severity": "high", "status": "assigned", "component": "demo-crypto-wrapper", "owner": "platform-security", "source": "demo-mode"},
            {"finding_id": "DEMO-EOL-0001", "title": "Synthetic unsupported dependency", "severity": "high", "status": "new", "component": "demo-legacy-parser", "owner": "payments-team", "source": "demo-mode"},
        ],
    }
    findings_path = _write_json(report_root / "findings.json", findings)
    manifest = {
        "generated_at": now_iso(),
        "mode": "live-offline-demo",
        "synthetic": True,
        "credentials_required": False,
        "network_required": False,
        "normal_job_runner_used": True,
        "normal_auto_reporting_used": True,
        "expected_tasks": ["SBOM quality", "Minimum elements", "Policy check", "Supplier intake", "Supplier questions", "Report bundle", "UI bundle", "Automatic full security engineering report"],
        "findings": str(findings_path),
    }
    manifest_path = _write_json(job_dir / "results" / "demo" / "demo-manifest.json", manifest)
    (job_dir / "results" / "demo" / "README.md").write_text(
        "# Live Demo Evidence\n\nThis job executed the normal local analysis pipeline against a synthetic CycloneDX SBOM. No external credentials or production data were used.\n",
        encoding="utf-8",
    )
    return {"manifest": str(manifest_path), "findings": str(findings_path)}


def finalize_demo_evidence(job_id: str, job_dir: Path, status: Dict[str, Any]) -> Dict[str, Any]:
    artifacts = [p for p in (job_dir / "results").rglob("*") if p.is_file()]
    summary = {
        "generated_at": now_iso(),
        "job_id": job_id,
        "synthetic": True,
        "state": status.get("state"),
        "steps_executed": len(status.get("steps", [])),
        "artifacts_generated": len(artifacts),
        "automatic_report_state": (status.get("reporting") or {}).get("state", "pending"),
        "what_was_demonstrated": [
            "queued-to-running-to-terminal job lifecycle",
            "real local SBOM analysis subprocesses",
            "evidence and UI bundle generation",
            "automatic detailed engineering report generation",
            "availability of optional report variants",
        ],
    }
    _write_json(job_dir / "results" / "demo" / "demo-run-summary.json", summary)
    return summary


def start_demo(wait: bool = False, timeout: int = 300) -> str:
    from sbomops.workbench.job_runner import create_job, read_status

    sbom = ensure_demo_sbom()
    job_id = create_job(
        "demo-live",
        sbom,
        policy="policies/default-release-policy.yml",
        network=False,
        options={"project_id": "synthetic-demo", "ai_provider": "none", "demo_mode": "1", "duration_seconds": "5"},
    )
    if wait:
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = read_status(job_id).get("state")
            if state not in {"queued", "running"}:
                break
            time.sleep(0.25)
    return job_id


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the real offline SBOM Toolkit demo")
    ap.add_argument("command", nargs="?", default="start", choices=["start", "create-sbom"])
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args(argv)
    if args.command == "create-sbom":
        print(ensure_demo_sbom())
    else:
        print(start_demo(wait=args.wait, timeout=args.timeout))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
