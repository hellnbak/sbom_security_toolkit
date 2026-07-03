#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, shutil, subprocess, sys
from pathlib import Path
from .common import write_json, write_markdown

ROOT = Path(__file__).resolve().parents[1]

def run(cmd, cwd=None, timeout=300):
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout[-4000:], "stderr": p.stderr[-4000:]}


def detect(project: Path):
    files = {p.name for p in project.iterdir()} if project.exists() and project.is_dir() else set()
    ecosystems = []
    if "package.json" in files: ecosystems.append("javascript")
    if "requirements.txt" in files or "pyproject.toml" in files: ecosystems.append("python")
    if "pom.xml" in files or "build.gradle" in files: ecosystems.append("jvm")
    if "composer.json" in files: ecosystems.append("php")
    if "go.mod" in files: ecosystems.append("go")
    if "Cargo.toml" in files: ecosystems.append("rust")
    return ecosystems or ["unknown"]


def find_or_generate_sbom(project: Path, out: Path):
    candidates = list(project.rglob("*cyclonedx*.json")) + list(project.rglob("*sbom*.json")) + list(project.rglob("*sbom*.xml"))
    if candidates:
        dest = out / "sbom-input" / candidates[0].name
        dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(candidates[0], dest)
        return dest, {"source": "existing", "path": str(candidates[0])}
    if shutil.which("syft"):
        dest = out / "sbom-input" / "generated.cdx.json"; dest.parent.mkdir(parents=True, exist_ok=True)
        res = run(["syft", str(project), "-o", f"cyclonedx-json={dest}"], timeout=600)
        if dest.exists(): return dest, {"source": "syft", "result": res}
    # fall back to toolkit minimal demo SBOM so workflow remains runnable
    fallback = ROOT / "test-sboms" / "clean" / "minimal-cyclonedx.json"
    dest = out / "sbom-input" / "fallback-minimal-cyclonedx.json"; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(fallback, dest)
    return dest, {"source": "fallback-demo", "note": "Install syft or provide an SBOM in the project to analyze real dependencies."}


def py_module(module, args, cwd=None):
    return run([sys.executable, "-m", module, *map(str, args)], cwd=cwd or ROOT)


def main():
    ap = argparse.ArgumentParser(description="Run the full SBOM Security Toolkit workflow against a project directory.")
    ap.add_argument("project"); ap.add_argument("--out-dir", default="reports/latest"); ap.add_argument("--policy", default="policies/default-release-policy.yml"); ap.add_argument("--vulns")
    args = ap.parse_args()
    project = Path(args.project).resolve(); out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    ecosystems = detect(project)
    sbom, sbom_info = find_or_generate_sbom(project, out)
    steps = []
    reports_base = out / "reports"
    def step(name, module, modargs):
        res = py_module(module, modargs); steps.append({"name": name, **res})
    step("SBOM quality", "sbomops.score_sbom", [sbom, "--out-dir", reports_base / "sbom-quality"])
    step("Minimum elements", "sbomops.minimum_elements", [sbom, "--out-dir", reports_base / "minimum-elements"])
    step("Policy", "sbomops.policy_check", [sbom, "--policy", args.policy, "--out-dir", reports_base / "policy"])
    step("Supplier intake", "sbomops.supplier_intake", [sbom, "--out-dir", reports_base / "supplier-intake"])
    step("Supplier questions", "sbomops.supplier_questions", [sbom, "--out-dir", reports_base / "supplier-questions"])
    rep_args = [sbom, "--out-dir", reports_base / "bundle"]
    if args.vulns: rep_args += ["--vulns", args.vulns]
    step("Report bundle", "sbomops.report", rep_args)
    step("Static UI", "sbomops.ui", ["--reports-dir", reports_base, "--out", out / "dashboard.html"])
    manifest = {"project": str(project), "ecosystems": ecosystems, "sbom": str(sbom), "sbom_info": sbom_info, "steps": steps}
    write_json(out / "analysis-manifest.json", manifest)
    write_markdown(out / "README.md", f"# SBOM Analysis Bundle\n\nProject: `{project}`\n\nSBOM: `{sbom}`\n\nDashboard: `dashboard.html`\n\nEcosystems: {', '.join(ecosystems)}\n")
    print(f"Analysis bundle written to {out}")

if __name__ == "__main__":
    main()
