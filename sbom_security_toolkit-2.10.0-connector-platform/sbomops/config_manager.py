#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable

import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "configs" / "generated"
POLICY_DIR = ROOT / "policies" / "generated"
AI_DIR = GENERATED / "ai-providers"
FUZZ_DIR = GENERATED / "fuzzing-profiles"
PROJECT_DIR = GENERATED / "project-defaults"
CLOUD_DIR = GENERATED / "cloud"

SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


def safe_slug(value: str, default: str = "default") -> str:
    cleaned = SAFE_NAME_RE.sub("-", (value or default).strip()).strip(".-_")
    return (cleaned or default)[:80]


def ensure_dirs() -> None:
    for d in [POLICY_DIR, AI_DIR, FUZZ_DIR, PROJECT_DIR, CLOUD_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        gitkeep = d / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.write_text("")


def write_yaml(path: Path, data: Dict[str, Any]) -> Path:
    ensure_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False), encoding="utf-8")
    return path


def read_yaml(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return data


def list_configs() -> Dict[str, list[Dict[str, Any]]]:
    ensure_dirs()
    groups = {
        "policies": POLICY_DIR,
        "ai_providers": AI_DIR,
        "fuzzing_profiles": FUZZ_DIR,
        "project_defaults": PROJECT_DIR,
        "cloud_settings": CLOUD_DIR,
    }
    out: Dict[str, list[Dict[str, Any]]] = {}
    for group, base in groups.items():
        rows = []
        for p in sorted(base.glob("*.yml")) + sorted(base.glob("*.yaml")):
            rows.append({"name": p.stem, "path": str(p.relative_to(ROOT)), "bytes": p.stat().st_size})
        out[group] = rows
    return out


def build_policy_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "kind": "sbom-security-toolkit-policy",
        "version": 1,
        "name": args.name,
        "generated_by": "workbench-policy-builder",
        "decision": {
            "fail_on_critical": args.fail_on_critical,
            "fail_on_high": args.fail_on_high,
            "fail_on_cisa_kev": args.fail_on_cisa_kev,
            "fail_on_exploit_available": args.fail_on_exploit_available,
            "fail_on_unsupported_dependencies": args.fail_on_unsupported,
            "warn_on_scanner_disagreement": args.warn_on_scanner_disagreement,
            "fail_on_vex_contradiction": args.fail_on_vex_contradiction,
        },
        "sbom_quality": {
            "require_supplier": args.require_supplier,
            "require_license": args.require_license,
            "require_version": args.require_version,
            "require_dependency_graph": args.require_dependency_graph,
        },
        "dependency_health": {
            "enabled": True,
            "stale_days": args.stale_days,
            "network_enrichment": args.network_enrichment,
        },
        "notes": "Generated from the Workbench Policy Builder. Edit directly or import back into the GUI.",
    }


def build_ai_provider_config(args: argparse.Namespace) -> Dict[str, Any]:
    provider = args.provider
    cfg: Dict[str, Any] = {
        "kind": "sbom-security-toolkit-ai-provider",
        "version": 1,
        "name": args.name,
        "provider": provider,
        "model": args.model or "",
        "default_mode": args.default_mode,
        "max_generated_cases": args.max_cases,
        "time_budget_seconds": args.time_budget,
        "store_secrets": False,
        "secret_handling": "Use environment variables, AWS SDK credential chain, instance role, or external secret manager. The GUI does not store API keys.",
    }
    if provider == "bedrock":
        cfg["bedrock"] = {"region": args.region or "us-east-1", "credential_source": "aws-sdk-default-chain"}
    elif provider in {"openai-compatible", "glm", "ollama"}:
        cfg["endpoint_url"] = args.endpoint_url or ""
        cfg["api_key_env"] = args.api_key_env or ""
    return cfg


def build_fuzzing_profile_config(args: argparse.Namespace) -> Dict[str, Any]:
    targets = [x.strip() for x in (args.targets or "sbom,scanner,ai").split(",") if x.strip()]
    return {
        "kind": "sbom-security-toolkit-fuzzing-profile",
        "version": 1,
        "name": args.name,
        "targets": targets,
        "duration_seconds_per_target": args.duration,
        "seed_count": args.seed_count,
        "max_ai_generated_cases": args.max_ai_cases,
        "ai_mode": args.ai_mode,
        "run_generated_cases": args.run_generated_cases,
        "safety": {
            "execute_project_code": False,
            "run_install_scripts": False,
            "only_validated_deterministic_cases": True,
        },
    }


def build_project_defaults_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "kind": "sbom-security-toolkit-project-defaults",
        "version": 1,
        "project_id": args.project_id,
        "default_policy": args.policy,
        "default_ai_provider": args.ai_provider,
        "default_fuzzing_profile": args.fuzzing_profile,
        "stale_days": args.stale_days,
        "evidence_retention_days": args.evidence_retention_days,
        "schedule": args.schedule,
        "release_decision": {"enabled": True, "default_behavior": args.release_behavior},
    }


def build_cloud_settings_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "kind": "sbom-security-toolkit-cloud-settings",
        "version": 1,
        "name": args.name,
        "storage_backend": args.storage_backend,
        "s3_bucket": args.s3_bucket or "",
        "s3_prefix": args.s3_prefix or "sbom-security-toolkit",
        "database_backend": args.database_backend,
        "queue_backend": args.queue_backend,
        "evidence_retention_days": args.evidence_retention_days,
        "workers": {
            "sbom": args.worker_sbom,
            "vulnerability": args.worker_vulnerability,
            "fuzzing": args.worker_fuzzing,
            "ai": args.worker_ai,
            "report": args.worker_report,
        },
        "security": {
            "require_auth": True,
            "require_tls_or_private_network": True,
            "store_tokens_in_plaintext": False,
            "recommended_secret_store": "AWS Secrets Manager, cloud secret manager, or environment injected by orchestrator",
        },
    }


def import_config(kind: str, name: str, raw_yaml: str) -> Path:
    ensure_dirs()
    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
        raise ValueError("Imported YAML must be a YAML object")
    slug = safe_slug(name or data.get("name") or data.get("project_id") or kind)
    if kind == "policy":
        base = POLICY_DIR
    elif kind == "ai-provider":
        base = AI_DIR
    elif kind == "fuzzing-profile":
        base = FUZZ_DIR
    elif kind == "project-defaults":
        base = PROJECT_DIR
    elif kind == "cloud-settings":
        base = CLOUD_DIR
    else:
        raise ValueError(f"Unsupported config kind: {kind}")
    return write_yaml(base / f"{slug}.yml", data)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="GUI/CLI-managed configuration helper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    val = sub.add_parser("validate")
    val.add_argument("path")

    imp = sub.add_parser("import")
    imp.add_argument("kind", choices=["policy", "ai-provider", "fuzzing-profile", "project-defaults", "cloud-settings"])
    imp.add_argument("--name", default="imported")
    imp.add_argument("--input", required=True)

    p = sub.add_parser("policy")
    p.add_argument("--name", default="gui-policy")
    p.add_argument("--stale-days", type=int, default=365)
    p.add_argument("--network-enrichment", action="store_true")
    for flag in ["fail-on-critical", "fail-on-high", "fail-on-cisa-kev", "fail-on-exploit-available", "fail-on-unsupported", "warn-on-scanner-disagreement", "fail-on-vex-contradiction", "require-supplier", "require-license", "require-version", "require-dependency-graph"]:
        p.add_argument(f"--{flag}", action="store_true")
    p.add_argument("--out")

    ai = sub.add_parser("ai-provider")
    ai.add_argument("--name", default="default-ai")
    ai.add_argument("--provider", default="none", choices=["none", "bedrock", "ollama", "glm", "openai-compatible"])
    ai.add_argument("--model", default="")
    ai.add_argument("--region", default="us-east-1")
    ai.add_argument("--endpoint-url", default="")
    ai.add_argument("--api-key-env", default="")
    ai.add_argument("--default-mode", default="suggest", choices=["suggest", "generate-run"])
    ai.add_argument("--max-cases", type=int, default=5)
    ai.add_argument("--time-budget", type=int, default=30)
    ai.add_argument("--out")

    fz = sub.add_parser("fuzzing-profile")
    fz.add_argument("--name", default="release-smoke")
    fz.add_argument("--targets", default="sbom,scanner,ai")
    fz.add_argument("--duration", type=int, default=60)
    fz.add_argument("--seed-count", type=int, default=10)
    fz.add_argument("--max-ai-cases", type=int, default=5)
    fz.add_argument("--ai-mode", default="suggest", choices=["disabled", "suggest", "generate-run"])
    fz.add_argument("--run-generated-cases", action="store_true")
    fz.add_argument("--out")

    pr = sub.add_parser("project-defaults")
    pr.add_argument("--project-id", default="default-project")
    pr.add_argument("--policy", default="policies/generated/gui-policy.yml")
    pr.add_argument("--ai-provider", default="configs/generated/ai-providers/default-ai.yml")
    pr.add_argument("--fuzzing-profile", default="configs/generated/fuzzing-profiles/release-smoke.yml")
    pr.add_argument("--stale-days", type=int, default=365)
    pr.add_argument("--evidence-retention-days", type=int, default=90)
    pr.add_argument("--schedule", default="manual")
    pr.add_argument("--release-behavior", default="warn", choices=["pass", "warn", "block"])
    pr.add_argument("--out")

    cl = sub.add_parser("cloud-settings")
    cl.add_argument("--name", default="self-hosted")
    cl.add_argument("--storage-backend", default="local", choices=["local", "s3", "minio"])
    cl.add_argument("--s3-bucket", default="")
    cl.add_argument("--s3-prefix", default="sbom-security-toolkit")
    cl.add_argument("--database-backend", default="postgres", choices=["local", "postgres"])
    cl.add_argument("--queue-backend", default="redis", choices=["in-process", "redis"])
    cl.add_argument("--evidence-retention-days", type=int, default=90)
    for flag in ["worker-sbom", "worker-vulnerability", "worker-fuzzing", "worker-ai", "worker-report"]:
        cl.add_argument(f"--{flag}", action="store_true")
    cl.add_argument("--out")
    return ap


def main(argv: Iterable[str] | None = None) -> int:
    ensure_dirs()
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.cmd == "list":
        print(json.dumps(list_configs(), indent=2, sort_keys=True))
        return 0
    if args.cmd == "validate":
        path = (ROOT / args.path).resolve() if not Path(args.path).is_absolute() else Path(args.path)
        data = read_yaml(path)
        print(json.dumps({"ok": True, "path": str(path), "kind": data.get("kind", "unknown"), "keys": sorted(data.keys())}, indent=2))
        return 0
    if args.cmd == "import":
        path = import_config(args.kind, args.name, Path(args.input).read_text(encoding="utf-8"))
        print(path.relative_to(ROOT))
        return 0

    if args.cmd == "policy":
        data = build_policy_config(args)
        out = Path(args.out) if args.out else POLICY_DIR / f"{safe_slug(args.name)}.yml"
    elif args.cmd == "ai-provider":
        data = build_ai_provider_config(args)
        out = Path(args.out) if args.out else AI_DIR / f"{safe_slug(args.name)}.yml"
    elif args.cmd == "fuzzing-profile":
        data = build_fuzzing_profile_config(args)
        out = Path(args.out) if args.out else FUZZ_DIR / f"{safe_slug(args.name)}.yml"
    elif args.cmd == "project-defaults":
        data = build_project_defaults_config(args)
        out = Path(args.out) if args.out else PROJECT_DIR / f"{safe_slug(args.project_id)}.yml"
    elif args.cmd == "cloud-settings":
        data = build_cloud_settings_config(args)
        out = Path(args.out) if args.out else CLOUD_DIR / f"{safe_slug(args.name)}.yml"
    else:
        raise AssertionError(args.cmd)
    path = write_yaml((ROOT / out).resolve() if not out.is_absolute() else out, data)
    print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
