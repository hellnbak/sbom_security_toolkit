#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
DEMO_DIR = REPORTS / "demo-product"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_json(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run(cmd: List[str], *, timeout: int = 90) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "") + f"\n[TIMEOUT after {timeout}s]"
    except Exception as exc:
        return 1, f"{type(exc).__name__}: {exc}"


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except Exception:
        return str(p)


def doctor(args) -> int:
    checks = []
    def add(name: str, ok: bool, detail: str = ""):
        checks.append({"name": name, "ok": ok, "detail": detail})

    add("python", sys.version_info >= (3, 9), sys.version.split()[0])
    for cmd in ["git", "docker", "make"]:
        path = shutil.which(cmd)
        add(cmd, bool(path), path or "not found")
    add("workbench storage", (ROOT / "ui/storage").exists(), rel(ROOT / "ui/storage"))
    add("sample SBOMs", (ROOT / "test-sboms").exists(), rel(ROOT / "test-sboms"))
    add("default policy", (ROOT / "policies/default-release-policy.yml").exists(), "policies/default-release-policy.yml")
    add("README", (ROOT / "README.md").exists(), "README.md")
    add("license", (ROOT / "LICENSE").exists(), "LICENSE")

    payload = {
        "generated_at": now(),
        "platform": platform.platform(),
        "python": sys.version,
        "checks": checks,
        "ok": all(c["ok"] for c in checks if c["name"] not in {"docker"}),
        "note": "Docker is optional unless you use Docker/cloud/fuzz engine workflows.",
    }
    out = Path(args.out or REPORTS / "doctor/doctor.json")
    write_json(out, payload)
    md = ["# SBOM Security Toolkit Doctor", "", f"Generated: {payload['generated_at']}", ""]
    for c in checks:
        md.append(f"- {'✅' if c['ok'] else '⚠️'} **{c['name']}** — {c['detail']}")
    write(out.with_suffix(".md"), "\n".join(md) + "\n")
    print(f"Doctor report written to {rel(out)} and {rel(out.with_suffix('.md'))}")
    return 0 if payload["ok"] else 1


def demo(args) -> int:
    out = Path(args.out_dir or DEMO_DIR)
    if args.reset and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    sample = ROOT / "test-sboms/example-spdx-2.3.json"
    if not sample.exists():
        sample = ROOT / "test-sboms/clean/minimal-cyclonedx.json"
    demo_sbom = out / "sample-sbom.json"
    if sample.exists():
        shutil.copyfile(sample, demo_sbom)
    else:
        write_json(demo_sbom, {"bomFormat":"CycloneDX","specVersion":"1.5","components":[]})

    project = {
        "project_id": "demo-product",
        "name": "Demo Product",
        "created_at": now(),
        "mode": "local-first demo",
        "description": "Generated demo workspace for SBOM Security Toolkit product walkthroughs.",
    }
    write_json(out / "project.json", project)
    findings = [
        {"id":"FIND-DEMO-001","severity":"critical","source":"vulnerability","component":"pkg:npm/example-vuln@1.0.0","status":"new","owner":"platform-security","sla":"overdue","recommended_action":"Upgrade to a fixed version and verify with a new SBOM scan."},
        {"id":"FIND-DEMO-002","severity":"high","source":"lifecycle","component":"python 3.8","status":"triaged","owner":"runtime-platform","sla":"due_this_week","recommended_action":"Plan migration to a supported Python release."},
        {"id":"FIND-DEMO-003","severity":"medium","source":"fuzzing","component":"sbom parser","status":"assigned","owner":"appsec","sla":"within_sla","recommended_action":"Reproduce parser inconsistency and add regression coverage."},
    ]
    write_json(out / "findings.json", {"generated_at": now(), "findings": findings})
    release = {"decision":"warn","reasons":["1 critical finding requires remediation or approved exception","1 lifecycle EOL item requires migration plan"],"evidence":["findings.json","ai-executive-summary.md"]}
    write_json(out / "release-decision.json", release)
    md = """# Demo Executive Summary

**Overall release posture:** Warn

The demo product has one critical vulnerability finding, one high-priority lifecycle/EOL item, and one fuzzing follow-up. The recommended next action is to remediate the critical dependency first, assign the Python runtime migration to the platform owner, and verify fixes with a follow-up SBOM scan.

## Next best actions

1. Create remediation ticket for `FIND-DEMO-001`.
2. Assign lifecycle migration for Python 3.8.
3. Re-run dependency health and findings verification after remediation.
4. Generate a final release decision memo before shipping.

_AI-generated narrative should be treated as advisory and evidence-bound._
"""
    write(out / "ai-executive-summary.md", md)
    write(out / "walkthrough-state.md", """# Demo Walkthrough State

Open the Workbench and visit:

- Projects
- Findings
- Reports
- AI Reports
- Integrations

Generated demo artifacts live under `reports/demo-product/`.
""")
    index = "# Demo Product Workspace\n\n" + "\n".join(f"- `{p.name}`" for p in sorted(out.iterdir()) if p.is_file()) + "\n"
    write(out / "README.md", index)
    print(f"Demo workspace generated under {rel(out)}")
    return 0


def reset_demo(args) -> int:
    target = Path(args.out_dir or DEMO_DIR)
    if target.exists():
        shutil.rmtree(target)
        print(f"Removed {rel(target)}")
    else:
        print(f"No demo workspace found at {rel(target)}")
    return 0


def first_run(args) -> int:
    cfg = {
        "generated_at": now(),
        "mode": args.mode,
        "default_project": args.project_id,
        "default_policy": args.policy,
        "default_ai_provider": args.ai_provider,
        "default_fuzzing_profile": args.fuzzing_profile,
        "load_demo": bool(args.load_demo),
        "notes": [
            "Local-first mode is the default.",
            "Cloud/self-hosted mode should be deployed behind authentication.",
            "AI providers are opt-in and should use secret references for credentials.",
        ],
    }
    out = Path(args.out or ROOT / "configs/generated/first-run/first-run.yml")
    lines = ["# SBOM Security Toolkit first-run configuration"]
    for k, v in cfg.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            lines += [f"  - {x}" for x in v]
        else:
            lines.append(f"{k}: {json.dumps(v)}")
    write(out, "\n".join(lines) + "\n")
    if args.load_demo:
        demo(argparse.Namespace(out_dir=str(DEMO_DIR), reset=True))
    print(f"First-run configuration written to {rel(out)}")
    return 0


def security_checklist(args) -> int:
    items = [
        "No secrets are committed to the repository.",
        "Generated reports do not include raw tokens or API keys.",
        "Live integrations require explicit SEND=1 / --send style opt-in where supported.",
        "Network enrichment is opt-in.",
        "AI calls are opt-in and evidence-bound.",
        "Repo code execution is not enabled by default.",
        "Workbench upload paths are sanitized and workspace-relative.",
        "Cloud mode should be deployed with authentication, TLS, and secret references.",
        "Evidence retention and cleanup policies are configured for team deployments.",
    ]
    out = Path(args.out or ROOT / "reports/security-hardening-checklist.md")
    md = "# Security Hardening Checklist\n\n" + "\n".join(f"- [ ] {i}" for i in items) + "\n"
    write(out, md)
    print(f"Security checklist written to {rel(out)}")
    return 0


def release_gate(args) -> int:
    checks = []
    commands = [
        ("compile", [sys.executable, "-m", "compileall", "-q", "sbomops", "scripts"], 120),
        ("validate", ["make", "validate"], 180),
        ("integration-smoke-offline", ["make", "integration-smoke", "SBOM=test-sboms/example-spdx-2.3.json"], 180),
        ("ai-report-smoke", ["make", "ai-report-smoke"], 180),
    ]
    if args.include_fuzz:
        commands.append(("fuzz-workflow-smoke", ["make", "fuzz-workflow-smoke", "COUNT=1", "TIME_BUDGET=1", "SBOM=test-sboms/clean/minimal-cyclonedx.json"], 240))
    for name, cmd, timeout in commands:
        rc, output = run(cmd, timeout=timeout)
        checks.append({"name": name, "command": cmd, "returncode": rc, "passed": rc == 0, "output_tail": output[-4000:]})
        print(f"{name}: {'PASS' if rc == 0 else 'FAIL'}")
        if rc != 0 and args.stop_on_fail:
            break
    payload = {"generated_at": now(), "checks": checks, "passed": all(c["passed"] for c in checks)}
    out = Path(args.out or REPORTS / "release-gate/release-gate.json")
    write_json(out, payload)
    md = ["# Release Gate", "", f"Generated: {payload['generated_at']}", "", f"Overall: **{'PASS' if payload['passed'] else 'FAIL'}**", ""]
    md += [f"- {'✅' if c['passed'] else '❌'} {c['name']}" for c in checks]
    write(out.with_suffix(".md"), "\n".join(md) + "\n")
    print(f"Release gate written to {rel(out)}")
    return 0 if payload["passed"] else 1


def install_notes(args) -> int:
    out = Path(args.out or ROOT / "reports/install-notes.md")
    write(out, """# Install / Upgrade Notes

## Local

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
make validate
make ui-server
```

## Upgrade

```bash
git pull
pip install -e .
make doctor
make test-fast
```

## Self-hosted cloud

Use `docker/docker-compose.cloud.yml` or the Kubernetes/Helm scaffolds under `deploy/kubernetes`.
""")
    print(f"Install notes written to {rel(out)}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Productization, QA, demo, and release-readiness helpers")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("doctor"); p.add_argument("--out"); p.set_defaults(func=doctor)
    p = sub.add_parser("demo"); p.add_argument("--out-dir"); p.add_argument("--reset", action="store_true"); p.set_defaults(func=demo)
    p = sub.add_parser("reset-demo"); p.add_argument("--out-dir"); p.set_defaults(func=reset_demo)
    p = sub.add_parser("first-run"); p.add_argument("--mode", default="local"); p.add_argument("--project-id", default="demo-product"); p.add_argument("--policy", default="policies/default-release-policy.yml"); p.add_argument("--ai-provider", default="none"); p.add_argument("--fuzzing-profile", default="release-smoke"); p.add_argument("--load-demo", action="store_true"); p.add_argument("--out"); p.set_defaults(func=first_run)
    p = sub.add_parser("security-checklist"); p.add_argument("--out"); p.set_defaults(func=security_checklist)
    p = sub.add_parser("release-gate"); p.add_argument("--include-fuzz", action="store_true"); p.add_argument("--stop-on-fail", action="store_true"); p.add_argument("--out"); p.set_defaults(func=release_gate)
    p = sub.add_parser("install-notes"); p.add_argument("--out"); p.set_defaults(func=install_notes)
    args = ap.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
