#!/usr/bin/env python3
"""Automatic per-run reporting and on-demand report variants.

This module is intentionally a small orchestration layer around the toolkit's
existing evidence-bound ``sbomops.ai_report_writer`` implementation.  It makes
one detailed engineering report mandatory for every Workbench job while
keeping provider failures non-blocking for the underlying scan.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Mapping

ROOT = Path(__file__).resolve().parents[1]

VARIANTS: Dict[str, Dict[str, str]] = {
    "executive": {"report_type": "executive", "audience": "executive", "tone": "concise", "title": "Executive Security Report"},
    "developer": {"report_type": "engineering", "audience": "engineering", "tone": "action-oriented", "title": "Developer Remediation Report"},
    "compliance": {"report_type": "full", "audience": "audit", "tone": "formal", "title": "Compliance and Audit Evidence Report"},
    "supplier": {"report_type": "supplier", "audience": "supplier", "tone": "formal", "title": "Supplier Risk Report"},
    "customer": {"report_type": "supplier", "audience": "supplier", "tone": "concise", "title": "Customer-Facing Security Summary"},
    "release": {"report_type": "release", "audience": "security", "tone": "formal", "title": "Release Decision Memo"},
    "fuzzing": {"report_type": "fuzzing", "audience": "engineering", "tone": "detailed", "title": "Fuzzing Results Report"},
    "lifecycle": {"report_type": "lifecycle", "audience": "security", "tone": "detailed", "title": "Lifecycle Intelligence Report"},
}

DEFAULT_SPEC = {
    "report_type": "full",
    "audience": "engineering",
    "tone": "detailed",
    "title": "Full Security Engineering Report",
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_read(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {} if default is None else default


def _json_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    tmp.replace(path)


def _safe_variant(value: str) -> str:
    value = re.sub(r"[^a-z0-9_-]+", "-", value.strip().lower()).strip("-")
    if value not in VARIANTS:
        raise ValueError(f"Unsupported report variant: {value}. Choose one of: {', '.join(sorted(VARIANTS))}")
    return value


def _relative_evidence_root(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def _resolve_sbom(job_dir: Path, explicit: str = "") -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.is_absolute() else ROOT / p
    status = _json_read(job_dir / "status.json", {})
    value = status.get("input_file")
    if value:
        p = Path(value)
        return p if p.is_absolute() else ROOT / p
    candidates = sorted((job_dir / "input").glob("*")) if (job_dir / "input").exists() else []
    return candidates[0] if candidates else None


def _render_alias_sections(markdown: str, variant: str, title: str) -> str:
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        lines[0] = f"# {title}"
    else:
        lines.insert(0, f"# {title}")

    additions = {
        "developer": """
## Developer Fix Workflow

1. Reproduce each applicable finding in the owning repository or build.
2. Upgrade, replace, remove, or constrain the affected dependency.
3. Run unit, integration, compatibility, and security regression tests.
4. Regenerate the SBOM and rerun this workflow.
5. Close the finding only after the new evidence verifies the fix.
""",
        "compliance": """
## Control and Audit Considerations

- Preserve the source SBOM, policy decision, report metadata, and checksums together.
- Treat missing evidence as incomplete rather than as a passing control.
- Record approvers, exceptions, compensating controls, and expiration dates outside this advisory report.
- Verify that retained evidence maps to the organization's actual control framework and scope.
""",
        "customer": """
## Customer Communication Guidance

This summary is intentionally sanitized. Internal file paths, raw prompts, detailed exploit notes, credentials, and non-public implementation details remain in the internal evidence package.
""",
    }
    if variant in additions:
        lines.append(additions[variant].strip())
    text = "\n".join(lines).rstrip() + "\n"
    if variant == "customer":
        # Remove the detailed local evidence path list from a customer-facing copy.
        text = re.sub(
            r"\n## Evidence used\n.*?(?=\n## AI limitations|\Z)",
            "\n## Evidence used\n\nDetailed evidence is retained internally and can be shared through an approved disclosure process.\n",
            text,
            flags=re.S,
        )
        text = text.replace(str(ROOT), "[internal-workspace]")
    return text


def _write_html_from_markdown(markdown: str, target: Path) -> None:
    try:
        from sbomops.ai_report_writer import markdown_to_html
        target.write_text(markdown_to_html(markdown), encoding="utf-8")
    except Exception:
        import html
        target.write_text("<!doctype html><html><body><pre>" + html.escape(markdown) + "</pre></body></html>\n", encoding="utf-8")


def _invoke_writer(
    *,
    job_dir: Path,
    output_dir: Path,
    spec: Mapping[str, str],
    provider: str,
    model: str,
    sbom: Path | None,
) -> Dict[str, Any]:
    from sbomops import ai_report_writer

    args = SimpleNamespace(
        command="generate",
        sbom=str(sbom) if sbom else "",
        project=str(_json_read(job_dir / "status.json", {}).get("options", {}).get("project_id", "")),
        report_type=spec["report_type"],
        audience=spec["audience"],
        tone=spec["tone"],
        provider=provider or "none",
        model=model or "",
        timeout=60,
        out_dir=str(output_dir),
        evidence_roots=_relative_evidence_root(job_dir / "results"),
    )
    return ai_report_writer.generate(args)


def write_options_manifest(job_dir: Path) -> Path:
    target = job_dir / "results" / "ai-reports" / "report-options.json"
    payload = {
        "generated_at": now_iso(),
        "default": {
            "name": "engineering",
            "title": DEFAULT_SPEC["title"],
            "automatic": True,
            "path": "results/ai-reports/engineering/full-security-report.md",
        },
        "variants": [
            {
                "name": name,
                "title": spec["title"],
                "automatic": False,
                "cli": f"python -m sbomops.reporting_runtime variant --job-dir {job_dir} --type {name}",
            }
            for name, spec in sorted(VARIANTS.items())
        ],
        "behavior": {
            "scan_and_report_states_are_independent": True,
            "report_provider_failure_does_not_fail_scan": True,
            "same_run_evidence_is_reused": True,
        },
    }
    _json_write(target, payload)
    return target


def _update_job_reporting(job_dir: Path, reporting: Mapping[str, Any]) -> None:
    status_path = job_dir / "status.json"
    if not status_path.exists():
        return
    status = _json_read(status_path, {})
    status["reporting"] = dict(reporting)
    status["updated_at"] = now_iso()
    _json_write(status_path, status)


def generate_default_for_job(job_dir: Path | str, *, provider: str = "none", model: str = "", sbom: str = "") -> Dict[str, Any]:
    job_dir = Path(job_dir).resolve()
    out = job_dir / "results" / "ai-reports" / "engineering"
    out.mkdir(parents=True, exist_ok=True)
    started = now_iso()
    options_path = write_options_manifest(job_dir)
    try:
        meta = _invoke_writer(job_dir=job_dir, output_dir=out, spec=DEFAULT_SPEC, provider=provider, model=model, sbom=_resolve_sbom(job_dir, sbom))
        report_path = out / "full-security-report.md"
        payload = {
            "state": "generated",
            "automatic": True,
            "started_at": started,
            "completed_at": now_iso(),
            "default_variant": "engineering",
            "default_report": str(report_path),
            "options_manifest": str(options_path),
            "provider": meta.get("provider", {}),
            "available_variants": sorted(VARIANTS),
        }
        _json_write(out / "automatic-report-status.json", payload)
        _update_job_reporting(job_dir, payload)
        return payload
    except Exception as exc:
        payload = {
            "state": "failed",
            "automatic": True,
            "started_at": started,
            "completed_at": now_iso(),
            "error": str(exc),
            "scan_state_unchanged": True,
            "options_manifest": str(options_path),
            "available_variants": sorted(VARIANTS),
        }
        _json_write(out / "automatic-report-status.json", payload)
        _update_job_reporting(job_dir, payload)
        raise


def generate_variant(
    job_dir: Path | str,
    variant: str,
    *,
    provider: str = "none",
    model: str = "",
    sbom: str = "",
) -> Dict[str, Any]:
    job_dir = Path(job_dir).resolve()
    variant = _safe_variant(variant)
    spec = VARIANTS[variant]
    out = job_dir / "results" / "ai-reports" / "variants" / variant
    out.mkdir(parents=True, exist_ok=True)
    meta = _invoke_writer(job_dir=job_dir, output_dir=out, spec=spec, provider=provider, model=model, sbom=_resolve_sbom(job_dir, sbom))

    markdown_files = sorted(out.glob("*.md"))
    markdown_files = [p for p in markdown_files if not p.name.endswith(".prompt.md")]
    if markdown_files:
        source = markdown_files[0]
        requested_md = out / f"{variant}-report.md"
        rendered = _render_alias_sections(source.read_text(encoding="utf-8", errors="replace"), variant, spec["title"])
        requested_md.write_text(rendered, encoding="utf-8")
        _write_html_from_markdown(rendered, out / f"{variant}-report.html")
    else:
        requested_md = out / f"{variant}-report.md"

    variant_meta = {
        "generated_at": now_iso(),
        "variant": variant,
        "title": spec["title"],
        "source_report_type": spec["report_type"],
        "audience": spec["audience"],
        "tone": spec["tone"],
        "provider": meta.get("provider", {}),
        "markdown": str(requested_md),
        "html": str(out / f"{variant}-report.html"),
        "same_run_evidence_reused": True,
    }
    _json_write(out / "variant-metadata.json", variant_meta)
    write_options_manifest(job_dir)

    status_path = job_dir / "status.json"
    if status_path.exists():
        status = _json_read(status_path, {})
        reporting = status.setdefault("reporting", {})
        generated = reporting.setdefault("generated_variants", {})
        generated[variant] = variant_meta
        reporting["available_variants"] = sorted(VARIANTS)
        status["updated_at"] = now_iso()
        _json_write(status_path, status)

    # Keep the downloadable evidence archive synchronized with newly generated
    # report variants. A variant reuses the completed run and must not require
    # another scan, but it is still part of the job evidence package.
    try:
        from sbomops.workbench import job_runner
        bundle = job_runner.create_evidence_zip(job_dir.name)
        if status_path.exists():
            status = _json_read(status_path, {})
            try:
                status["bundle"] = str(bundle.resolve().relative_to(ROOT.resolve()))
            except Exception:
                status["bundle"] = str(bundle)
            status["updated_at"] = now_iso()
            _json_write(status_path, status)
        variant_meta["evidence_bundle_refreshed"] = True
    except Exception as exc:
        variant_meta["evidence_bundle_refreshed"] = False
        variant_meta["evidence_bundle_warning"] = str(exc)
        _json_write(out / "variant-metadata.json", variant_meta)
    return variant_meta


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Automatic job reporting and report variants")
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("default", "variant", "options"):
        p = sub.add_parser(name)
        p.add_argument("--job-dir", required=True)
        p.add_argument("--provider", default="none")
        p.add_argument("--model", default="")
        p.add_argument("--sbom", default="")
        if name == "variant":
            p.add_argument("--type", required=True, choices=sorted(VARIANTS))
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "default":
        result = generate_default_for_job(args.job_dir, provider=args.provider, model=args.model, sbom=args.sbom)
    elif args.command == "variant":
        result = generate_variant(args.job_dir, args.type, provider=args.provider, model=args.model, sbom=args.sbom)
    else:
        result = {"options_manifest": str(write_options_manifest(Path(args.job_dir).resolve()))}
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
