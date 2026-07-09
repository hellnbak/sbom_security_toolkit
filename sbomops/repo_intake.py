#!/usr/bin/env python3
"""Repository intake, SBOM build, scan, fuzz, and evidence workflows.

This module is intentionally static-first: it inspects manifests and lock files,
orchestrates locally installed SBOM/scanner tools when present, and never runs
project install/build scripts by default.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

MANIFESTS: Dict[str, List[str]] = {
    "javascript/npm": ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
    "python": ["requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "setup.py", "setup.cfg"],
    "go": ["go.mod", "go.sum"],
    "java/maven": ["pom.xml"],
    "java/gradle": ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "php/composer": ["composer.json", "composer.lock"],
    "ruby": ["Gemfile", "Gemfile.lock", "*.gemspec"],
    "dotnet": ["*.csproj", "packages.lock.json", "Directory.Packages.props", "packages.config"],
    "container": ["Dockerfile", "Containerfile", "docker-compose.yml", "docker-compose.yaml"],
    "github-actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
}

SAFE_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", ".tox", ".mypy_cache", "__pycache__"}
MAX_REPO_ARCHIVE_BYTES = 250 * 1024 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as z:
        total = 0
        for info in z.infolist():
            total += info.file_size
            if total > MAX_REPO_ARCHIVE_BYTES:
                raise ValueError("Archive expands beyond maximum allowed size")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"Unsafe zip path: {info.filename}")
        z.extractall(dest)


def safe_extract_tar(tar_path: Path, dest: Path) -> None:
    with tarfile.open(tar_path) as t:
        total = 0
        for member in t.getmembers():
            if member.isfile():
                total += member.size
            if total > MAX_REPO_ARCHIVE_BYTES:
                raise ValueError("Archive expands beyond maximum allowed size")
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"Unsafe tar path: {member.name}")
        t.extractall(dest)


def first_repo_root(path: Path) -> Path:
    children = [p for p in path.iterdir() if not p.name.startswith("__MACOSX")]
    dirs = [p for p in children if p.is_dir()]
    files = [p for p in children if p.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return path


def askpass_script(tmpdir: Path) -> Path:
    script = tmpdir / "git-askpass-token.sh"
    script.write_text("""#!/usr/bin/env bash
case \"$1\" in
  *Username*) printf '%s\\n' 'x-access-token' ;;
  *) printf '%s\\n' \"$GITHUB_TOKEN\" ;;
esac
""")
    script.chmod(0o700)
    return script


def clone_github_repo(url: str, dest: Path, token_env: str = "GITHUB_TOKEN", depth: int = 1) -> Dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only HTTPS GitHub URLs are supported for remote repository intake by default")
    env = os.environ.copy()
    if token_env and os.environ.get(token_env):
        # Do not put tokens in the git URL or command line. GIT_ASKPASS reads the token from env.
        askpass = askpass_script(dest.parent)
        env.update({"GIT_ASKPASS": str(askpass), "GIT_TERMINAL_PROMPT": "0"})
    else:
        env.update({"GIT_TERMINAL_PROMPT": "0"})
    cmd = ["git", "clone", "--depth", str(max(1, depth)), url, str(dest)]
    proc = subprocess.run(cmd, text=True, capture_output=True, env=env, timeout=900)
    return {
        "command": ["git", "clone", "--depth", str(max(1, depth)), "<url>", "<dest>"],
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def materialize_source(source: str, work_dir: Path, *, allow_remote: bool = False, token_env: str = "GITHUB_TOKEN") -> Tuple[Path, Dict[str, Any]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    meta: Dict[str, Any] = {"source": source, "materialized_at": now(), "remote": False}
    if re.match(r"^https?://", source):
        if not allow_remote:
            raise ValueError("Remote Git intake is disabled unless --allow-remote is set")
        repo_dir = work_dir / "repo"
        clone_result = clone_github_repo(source, repo_dir, token_env=token_env)
        meta.update({"remote": True, "clone": clone_result, "token_env_used": bool(token_env and os.environ.get(token_env))})
        if clone_result["returncode"] != 0:
            raise RuntimeError("git clone failed; see repo-intake-source.json for sanitized stderr")
        return repo_dir, meta
    p = Path(source).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(source)
    if p.is_dir():
        meta.update({"kind": "directory", "path": str(p)})
        return p, meta
    suffixes = [s.lower() for s in p.suffixes]
    extract_dir = work_dir / "repo"
    extract_dir.mkdir(parents=True, exist_ok=True)
    meta.update({"kind": "archive", "path": str(p), "sha256": sha256_path(p)})
    if p.suffix.lower() == ".zip":
        safe_extract_zip(p, extract_dir)
    elif suffixes[-2:] in [[".tar", ".gz"], [".tar", ".bz2"], [".tar", ".xz"]] or p.suffix.lower() == ".tgz":
        safe_extract_tar(p, extract_dir)
    else:
        raise ValueError("Repository intake accepts local directories, .zip, .tar.gz/.tgz, or HTTPS GitHub URLs")
    return first_repo_root(extract_dir), meta


def iter_files(repo: Path) -> Iterable[Path]:
    for p in repo.rglob("*"):
        try:
            rel = p.relative_to(repo)
        except ValueError:
            continue
        if any(part in SAFE_SKIP_DIRS for part in rel.parts):
            continue
        if p.is_file():
            yield p


def detect_ecosystems(repo: Path) -> Dict[str, Any]:
    files = [p.relative_to(repo).as_posix() for p in iter_files(repo)]
    findings: Dict[str, Any] = {"repo": str(repo), "detected_at": now(), "ecosystems": [], "manifests": [], "counts": {}}
    for eco, patterns in MANIFESTS.items():
        matched = []
        for pattern in patterns:
            if "*" in pattern:
                matched.extend([f for f in files if Path(f).match(pattern)])
            else:
                matched.extend([f for f in files if Path(f).name == pattern or f.endswith("/" + pattern)])
        matched = sorted(set(matched))
        if matched:
            findings["ecosystems"].append(eco)
            findings["counts"][eco] = len(matched)
            findings["manifests"].extend({"ecosystem": eco, "path": m} for m in matched)
    findings["ecosystems"] = sorted(set(findings["ecosystems"]))
    findings["file_count_sampled"] = len(files)
    return findings


def parse_package_json(path: Path) -> List[Dict[str, str]]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []
    out = []
    for section, scope in [("dependencies", "required"), ("devDependencies", "optional"), ("peerDependencies", "peer")]:
        deps = data.get(section) or {}
        if isinstance(deps, dict):
            for name, ver in deps.items():
                out.append({"type": "library", "name": str(name), "version": str(ver), "purl": f"pkg:npm/{name}", "scope": scope, "evidence": path.name})
    if data.get("name"):
        out.append({"type": "application", "name": str(data.get("name")), "version": str(data.get("version", "0.0.0")), "purl": f"pkg:npm/{data.get('name')}@{data.get('version','0.0.0')}", "scope": "root", "evidence": path.name})
    return out


def parse_requirements(path: Path) -> List[Dict[str, str]]:
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^;#\s]+)?", line)
        if m:
            name, ver = m.group(1), m.group(2) or ""
            purl = f"pkg:pypi/{name.lower()}" + (f"@{ver}" if ver and not any(c in ver for c in "*<>=~") else "")
            out.append({"type": "library", "name": name, "version": ver, "purl": purl, "scope": "required", "evidence": path.name})
    return out


def parse_go_mod(path: Path) -> List[Dict[str, str]]:
    out = []
    in_require_block = False
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("module "):
            name = line.split(None, 1)[1]
            out.append({"type": "application", "name": name, "version": "", "purl": f"pkg:golang/{name}", "scope": "root", "evidence": path.name})
        elif line.startswith("require ("):
            in_require_block = True
        elif in_require_block and line == ")":
            in_require_block = False
        elif line.startswith("require ") or in_require_block:
            line = line.replace("require ", "", 1).split("//", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                name, ver = parts[0], parts[1]
                out.append({"type": "library", "name": name, "version": ver, "purl": f"pkg:golang/{name}@{ver}", "scope": "required", "evidence": path.name})
    return out


def parse_composer_json(path: Path) -> List[Dict[str, str]]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return []
    out = []
    if data.get("name"):
        out.append({"type": "application", "name": str(data.get("name")), "version": str(data.get("version", "")), "purl": f"pkg:composer/{data.get('name')}", "scope": "root", "evidence": path.name})
    for section in ["require", "require-dev"]:
        deps = data.get(section) or {}
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if name.lower() == "php":
                    continue
                out.append({"type": "library", "name": str(name), "version": str(ver), "purl": f"pkg:composer/{name}", "scope": "required" if section == "require" else "optional", "evidence": path.name})
    return out


def parse_cargo_toml(path: Path) -> List[Dict[str, str]]:
    out = []
    section = None
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            continue
        if section in {"dependencies", "dev-dependencies", "build-dependencies"} and "=" in line and not line.startswith("#"):
            name, ver = line.split("=", 1)
            name = name.strip().strip('"')
            ver = ver.strip().strip('"').split()[0].strip('{').strip(',')
            if name:
                out.append({"type": "library", "name": name, "version": ver, "purl": f"pkg:cargo/{name}", "scope": "required" if section == "dependencies" else "optional", "evidence": path.name})
    return out


def parse_manifests(repo: Path) -> List[Dict[str, str]]:
    components: List[Dict[str, str]] = []
    for p in iter_files(repo):
        name = p.name
        if name == "package.json":
            components.extend(parse_package_json(p))
        elif name == "requirements.txt":
            components.extend(parse_requirements(p))
        elif name == "go.mod":
            components.extend(parse_go_mod(p))
        elif name == "composer.json":
            components.extend(parse_composer_json(p))
        elif name == "Cargo.toml":
            components.extend(parse_cargo_toml(p))
    dedup = {}
    for c in components:
        key = (c.get("purl") or c.get("name"), c.get("version"), c.get("scope"))
        dedup[key] = c
    return list(dedup.values())


def internal_cyclonedx(repo: Path, out: Path) -> Path:
    comps = parse_manifests(repo)
    root_name = repo.name or "repository"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + hashlib.sha256(str(repo).encode()).hexdigest()[:32],
        "version": 1,
        "metadata": {
            "timestamp": now(),
            "tools": [{"vendor": "SBOM Security Toolkit", "name": "repo-intake-internal-generator", "version": "2.2.0"}],
            "component": {"type": "application", "name": root_name, "version": "0.0.0", "bom-ref": f"root:{root_name}"},
        },
        "components": [{"type": "application", "name": root_name, "version": "0.0.0", "bom-ref": f"root:{root_name}"}],
        "dependencies": [{"ref": f"root:{root_name}", "dependsOn": []}],
    }
    for i, c in enumerate(comps):
        ref = c.get("purl") or f"component:{i}:{c.get('name')}"
        item: Dict[str, Any] = {"type": c.get("type", "library"), "name": c.get("name", "unknown"), "bom-ref": ref, "scope": c.get("scope", "required")}
        if c.get("version"):
            item["version"] = c["version"]
        if c.get("purl"):
            item["purl"] = c["purl"]
        item["properties"] = [{"name": "sst:evidence", "value": c.get("evidence", "manifest")}]
        bom["components"].append(item)
        bom["dependencies"][0]["dependsOn"].append(ref)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    return out


def run_tool(cmd: List[str], cwd: Path, out_file: Path, timeout: int = 900) -> Dict[str, Any]:
    started = time.time()
    tool = cmd[0]
    if not shutil.which(tool):
        return {"tool": tool, "available": False, "skipped": True, "reason": f"{tool} not found"}
    try:
        proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        if proc.stdout:
            out_file.write_text(proc.stdout)
        return {"tool": tool, "available": True, "returncode": proc.returncode, "elapsed_seconds": round(time.time()-started,2), "stdout_file": str(out_file), "stderr_tail": proc.stderr[-2000:]}
    except subprocess.TimeoutExpired as exc:
        return {"tool": tool, "available": True, "returncode": 124, "elapsed_seconds": round(time.time()-started,2), "timed_out": True, "stderr_tail": str(exc.stderr or "")[-2000:]}


def generate_sboms(repo: Path, out_dir: Path, generators: List[str]) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Any] = {"generated_at": now(), "repo": str(repo), "generators": []}
    if "internal" in generators or "auto" in generators:
        internal = internal_cyclonedx(repo, out_dir / "internal.cdx.json")
        results["generators"].append({"tool": "internal", "available": True, "returncode": 0, "stdout_file": str(internal), "note": "static manifest/lockfile fallback generator"})
    if "syft" in generators or "auto" in generators:
        results["generators"].append(run_tool(["syft", str(repo), "-o", "cyclonedx-json"], repo, out_dir / "syft.cdx.json"))
        results["generators"].append(run_tool(["syft", str(repo), "-o", "spdx-json"], repo, out_dir / "syft.spdx.json"))
    if "cdxgen" in generators or "auto" in generators:
        results["generators"].append(run_tool(["cdxgen", "-o", str(out_dir / "cdxgen.cdx.json"), str(repo)], repo, out_dir / "cdxgen-run.log"))
    if "trivy" in generators or "auto" in generators:
        results["generators"].append(run_tool(["trivy", "fs", "--format", "cyclonedx", str(repo)], repo, out_dir / "trivy.cdx.json"))
    (out_dir / "sbom-generation-results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    return results


def load_components(sbom: Path) -> Dict[str, Dict[str, Any]]:
    try:
        data = json.loads(sbom.read_text(errors="replace"))
    except Exception:
        return {}
    comps = data.get("components") or []
    out = {}
    for c in comps:
        if isinstance(c, dict):
            key = c.get("purl") or f"{c.get('name','')}@{c.get('version','')}"
            out[key] = c
    return out


def compare_generated_sboms(sbom_dir: Path, out: Path) -> Dict[str, Any]:
    files = sorted([p for p in sbom_dir.glob("*.json") if p.name.endswith((".cdx.json", ".spdx.json"))])
    maps = {p.name: load_components(p) for p in files}
    all_keys = set().union(*(set(m.keys()) for m in maps.values())) if maps else set()
    report = {"generated_at": now(), "files": {}, "common_components": 0, "all_component_identities": len(all_keys), "only_in": {}}
    if maps:
        common = set.intersection(*(set(m.keys()) for m in maps.values())) if len(maps) > 1 else set(next(iter(maps.values())).keys())
        report["common_components"] = len(common)
        for name, m in maps.items():
            report["files"][name] = {"component_count": len(m)}
            others = set().union(*(set(x.keys()) for n, x in maps.items() if n != name)) if len(maps) > 1 else set()
            report["only_in"][name] = sorted(set(m.keys()) - others)[:200]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def scan_repo(repo: Path, sbom: Path, out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {"generated_at": now(), "repo": str(repo), "scans": []}
    results["scans"].append(run_tool(["grype", f"sbom:{sbom}"], repo, out_dir / "grype.txt"))
    results["scans"].append(run_tool(["trivy", "fs", "--format", "json", str(repo)], repo, out_dir / "trivy.json"))
    results["scans"].append(run_tool(["osv-scanner", "--format", "json", str(repo)], repo, out_dir / "osv-scanner.json"))
    (out_dir / "repo-scan-results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    return results


def summarize(out_dir: Path, source_meta: Dict[str, Any], detection: Dict[str, Any], gen: Dict[str, Any], comparison: Dict[str, Any], scans: Optional[Dict[str, Any]]) -> Path:
    md = out_dir / "repo-intake-summary.md"
    available = [g for g in gen.get("generators", []) if g.get("available") and not g.get("skipped")]
    skipped = [g for g in gen.get("generators", []) if g.get("skipped")]
    lines = [
        "# Repository Intake Summary",
        "",
        f"Generated: {now()}",
        "",
        "## Source",
        f"- Remote: {source_meta.get('remote', False)}",
        f"- Kind: {source_meta.get('kind', 'git' if source_meta.get('remote') else 'unknown')}",
        "",
        "## Detected ecosystems",
    ]
    if detection.get("ecosystems"):
        lines.extend(f"- {x}" for x in detection["ecosystems"])
    else:
        lines.append("- None detected from known manifests")
    lines += ["", "## SBOM generation", f"- Successful/attempted generators: {len(available)}", f"- Skipped unavailable generators: {len(skipped)}", "", "## Generator comparison", f"- Files compared: {len(comparison.get('files', {}))}", f"- Common component identities: {comparison.get('common_components', 0)}", f"- Total distinct component identities: {comparison.get('all_component_identities', 0)}"]
    if scans:
        lines += ["", "## Vulnerability scanning"]
        for s in scans.get("scans", []):
            lines.append(f"- {s.get('tool')}: {'available' if s.get('available') else 'not installed'} return={s.get('returncode','skipped')}")
    if (out_dir / "dependency-health" / "dependency-health.md").exists():
        lines += ["", "## Dependency health", f"- Unsupported/EOL risk report: `{(out_dir / 'dependency-health' / 'dependency-health.md').name}`"]
    lines += ["", "## Safety notes", "- Static-first analysis: the toolkit does not run project install/build scripts by default.", "- GitHub tokens are intended to be supplied via environment variables or transient UI process memory, not committed or written to status files."]
    md.write_text("\n".join(lines) + "\n")
    return md


def write_repo_descriptor(source: str, out: Path, **kwargs: Any) -> Path:
    data = {"source": source, **kwargs}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return out


def analyze_repo(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    work_dir = out_dir / "workspace"
    out_dir.mkdir(parents=True, exist_ok=True)
    source = args.source
    # Descriptor support for workbench Git URL jobs.
    source_path = Path(source)
    if source_path.exists() and source_path.suffix == ".json":
        try:
            descriptor = json.loads(source_path.read_text(errors="replace"))
            if descriptor.get("kind") == "repo-descriptor":
                source = descriptor["source"]
                args.allow_remote = bool(descriptor.get("allow_remote", args.allow_remote))
                args.github_token_env = descriptor.get("github_token_env", args.github_token_env)
        except Exception:
            pass
    repo, source_meta = materialize_source(source, work_dir, allow_remote=args.allow_remote, token_env=args.github_token_env)
    (out_dir / "repo-intake-source.json").write_text(json.dumps(source_meta, indent=2, sort_keys=True) + "\n")
    detection = detect_ecosystems(repo)
    (out_dir / "detected-ecosystems.json").write_text(json.dumps(detection, indent=2, sort_keys=True) + "\n")
    generators = [x.strip() for x in args.generators.split(",") if x.strip()] or ["auto"]
    gen = generate_sboms(repo, out_dir / "generated-sboms", generators)
    comparison = compare_generated_sboms(out_dir / "generated-sboms", out_dir / "generator-comparison.json")
    preferred = out_dir / "generated-sboms" / "internal.cdx.json"
    for candidate in ["syft.cdx.json", "cdxgen.cdx.json", "trivy.cdx.json", "internal.cdx.json"]:
        p = out_dir / "generated-sboms" / candidate
        if p.exists() and p.stat().st_size > 0:
            preferred = p
            break
    scans = scan_repo(repo, preferred, out_dir / "vuln-scan-results") if args.scan else None
    if getattr(args, "dependency_health", False):
        dh_cmd = [sys.executable, "-m", "sbomops.dependency_health", str(preferred), "--out-dir", str(out_dir / "dependency-health"), "--stale-days", str(args.stale_days)]
        if getattr(args, "network", False):
            dh_cmd.append("--network")
        subprocess.run(dh_cmd, cwd=ROOT)
    # Reuse existing SBOM experience workflows on the preferred SBOM.
    subprocess.run([sys.executable, "-m", "sbomops.score_sbom", str(preferred), "--out-dir", str(out_dir / "sbom-quality")], cwd=ROOT)
    subprocess.run([sys.executable, "-m", "sbomops.minimum_elements", str(preferred), "--out-dir", str(out_dir / "minimum-elements")], cwd=ROOT)
    if args.policy:
        subprocess.run([sys.executable, "-m", "sbomops.policy_check", str(preferred), "--policy", args.policy, "--out-dir", str(out_dir / "policy")], cwd=ROOT)
    if args.fuzz:
        fuzz_dir = out_dir / "fuzzing-results"
        subprocess.run([sys.executable, "fuzzing/roundtrip/roundtrip_sbom.py", str(preferred), "--out-dir", str(fuzz_dir / "roundtrip")], cwd=ROOT)
        subprocess.run([sys.executable, "fuzzing/metamorphic/metamorphic_sbom.py", str(preferred), "--out-dir", str(fuzz_dir / "metamorphic")], cwd=ROOT)
        subprocess.run([sys.executable, "fuzzing/oracles/semantic_oracles.py", str(preferred), "--out", str(fuzz_dir / "semantic-oracles.json")], cwd=ROOT)
    summarize(out_dir, source_meta, detection, gen, comparison, scans)
    print(out_dir)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Repository intake: generate SBOMs, compare generators, scan, fuzz, and build evidence.")
    sub = ap.add_subparsers(dest="cmd")
    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("source", help="Local repo path, repo .zip/.tar.gz, HTTPS GitHub URL, or workbench descriptor JSON")
        p.add_argument("--out-dir", default="reports/repo-intake")
        p.add_argument("--generators", default="auto", help="Comma list: auto,internal,syft,cdxgen,trivy")
        p.add_argument("--policy", default="policies/default-release-policy.yml")
        p.add_argument("--allow-remote", action="store_true", help="Allow HTTPS GitHub clone")
        p.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Environment variable containing a GitHub token for private repos")
    p = sub.add_parser("analyze", help="Full repository intake pipeline")
    add_common(p); p.add_argument("--scan", action="store_true", default=True); p.add_argument("--no-scan", dest="scan", action="store_false"); p.add_argument("--fuzz", action="store_true"); p.add_argument("--dependency-health", action="store_true", help="Run unsupported/EOL dependency health analysis on the generated SBOM"); p.add_argument("--stale-days", type=int, default=365); p.add_argument("--network", action="store_true", help="Allow optional registry/lifecycle metadata enrichment for dependency health")
    p.add_argument("--lifecycle-sources", default="sbom,known,registry,endoflife", help="Comma list of lifecycle sources: sbom,known,registry,endoflife")
    p.add_argument("--lifecycle-cache", default="", help="Optional lifecycle cache JSON keyed by product slug")
    p.add_argument("--offline-cache-only", action="store_true", help="Use built-in/user lifecycle cache only")
    p2 = sub.add_parser("detect", help="Detect ecosystems only")
    p2.add_argument("source"); p2.add_argument("--out", default="reports/repo-intake/detected-ecosystems.json")
    p2.add_argument("--allow-remote", action="store_true"); p2.add_argument("--github-token-env", default="GITHUB_TOKEN")
    p3 = sub.add_parser("descriptor", help="Create a workbench-safe repo descriptor JSON")
    p3.add_argument("source"); p3.add_argument("--out", required=True); p3.add_argument("--allow-remote", action="store_true"); p3.add_argument("--github-token-env", default="GITHUB_TOKEN")
    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        return analyze_repo(args)
    if args.cmd == "detect":
        with tempfile.TemporaryDirectory(prefix="sst-repo-detect-") as td:
            repo, meta = materialize_source(args.source, Path(td), allow_remote=args.allow_remote, token_env=args.github_token_env)
            data = detect_ecosystems(repo); data["source_meta"] = meta
            out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n")
            print(out); return 0
    if args.cmd == "descriptor":
        write_repo_descriptor(args.source, Path(args.out), kind="repo-descriptor", allow_remote=args.allow_remote, github_token_env=args.github_token_env)
        print(args.out); return 0
    ap.print_help(); return 2

if __name__ == "__main__":
    raise SystemExit(main())
