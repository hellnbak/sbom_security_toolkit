#!/usr/bin/env python3
"""Evidence-bound AI report writer for SBOM Security Toolkit.

The report writer extracts facts from existing local artifacts and then either:
- writes a prompt-only report pack for human review, or
- calls an optional configured AI provider to draft narrative text.

AI never creates findings, accepts risk, or approves releases. Reports include
metadata and the extracted fact bundle used to generate the narrative.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "reports" / "ai"

REPORT_TYPES = {
    "executive": "Executive Summary",
    "engineering": "Engineering Remediation Report",
    "supplier": "Supplier / Vendor Risk Report",
    "release": "Release Decision Memo",
    "fuzzing": "Fuzzing Summary Report",
    "lifecycle": "Lifecycle Intelligence Report",
    "full": "Full Security Report",
}
AUDIENCES = {"executive", "engineering", "security", "supplier", "audit"}
TONES = {"concise", "detailed", "formal", "action-oriented"}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_slug(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip().lower()).strip("-._")
    return s or "report"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def read_text_limited(path: Path, limit: int = 12000) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    return text[:limit]


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def normalize_component_name(c: Dict[str, Any]) -> str:
    return c.get("name") or c.get("bom-ref") or c.get("bom_ref") or c.get("purl") or c.get("group") or "unknown-component"


def parse_sbom(sbom: Path | None) -> Dict[str, Any]:
    if not sbom:
        return {}
    p = sbom if sbom.is_absolute() else ROOT / sbom
    if not p.exists():
        return {"path": str(sbom), "error": "SBOM path not found"}
    payload: Dict[str, Any] = {"path": relative(p), "size_bytes": p.stat().st_size}
    try:
        data = load_json(p)
    except Exception as exc:
        payload["error"] = f"Only JSON SBOM parsing is supported by the report fact extractor: {exc}"
        return payload
    payload["bom_format"] = data.get("bomFormat") or data.get("spdxVersion") or data.get("SPDXID") or "unknown"
    payload["spec_version"] = data.get("specVersion") or data.get("spdxVersion") or "unknown"
    comps = data.get("components") or data.get("packages") or []
    if not isinstance(comps, list):
        comps = []
    payload["component_count"] = len(comps)
    ecosystems: Dict[str, int] = {}
    missing = {"version": 0, "license": 0, "supplier": 0}
    samples = []
    for c in comps[:5000]:
        if not isinstance(c, dict):
            continue
        purl = c.get("purl") or c.get("externalRefs", [{}])[0].get("referenceLocator") if isinstance(c.get("externalRefs"), list) and c.get("externalRefs") else ""
        eco = "unknown"
        if isinstance(purl, str) and purl.startswith("pkg:"):
            eco = purl.split("/", 1)[0].replace("pkg:", "")
        elif c.get("type"):
            eco = str(c.get("type"))
        ecosystems[eco] = ecosystems.get(eco, 0) + 1
        if not c.get("versionInfo") and not c.get("version"):
            missing["version"] += 1
        if not c.get("licenseConcluded") and not c.get("licenseDeclared") and not c.get("licenses"):
            missing["license"] += 1
        if not c.get("supplier") and not c.get("publisher"):
            missing["supplier"] += 1
        if len(samples) < 20:
            samples.append({"name": normalize_component_name(c), "version": c.get("version") or c.get("versionInfo") or "", "purl": c.get("purl", "")})
    payload["ecosystems"] = dict(sorted(ecosystems.items(), key=lambda x: (-x[1], x[0]))[:20])
    payload["missing_metadata"] = missing
    payload["sample_components"] = samples
    return payload


def latest_files(patterns: Iterable[str], limit: int = 20) -> List[Path]:
    seen: Dict[str, Path] = {}
    for pattern in patterns:
        for p in ROOT.glob(pattern):
            if p.is_file():
                seen[str(p.resolve())] = p
    return sorted(seen.values(), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]


def summarize_json(path: Path) -> Dict[str, Any]:
    try:
        data = load_json(path)
    except Exception:
        return {"path": relative(path), "type": "json", "error": "parse_failed"}
    summary: Dict[str, Any] = {"path": relative(path), "type": "json"}
    if isinstance(data, dict):
        summary["keys"] = list(data.keys())[:30]
        for key in ["decision", "status", "state", "summary", "total", "counts", "by_severity", "by_status", "sla", "generated_at", "project", "reports", "findings", "results", "lifecycle_findings", "records"]:
            if key in data:
                value = data[key]
                summary[key] = value if not isinstance(value, (list, dict)) else shrink(value)
    elif isinstance(data, list):
        summary["items"] = len(data)
        summary["sample"] = shrink(data[:10])
    return summary


def shrink(value: Any, max_items: int = 10, max_chars: int = 4000) -> Any:
    if isinstance(value, dict):
        return {k: shrink(v, max_items, max_chars) for k, v in list(value.items())[:max_items]}
    if isinstance(value, list):
        return [shrink(v, max_items, max_chars) for v in value[:max_items]]
    if isinstance(value, str):
        return value[:max_chars]
    return value


def collect_findings(project: str = "") -> Dict[str, Any]:
    findings_files = latest_files(["findings/findings-db.json", "reports/findings/*.json", "reports/**/findings*.json"], limit=10)
    facts: Dict[str, Any] = {"files": [], "counts": {}, "samples": []}
    for p in findings_files:
        s = summarize_json(p)
        facts["files"].append(s)
        try:
            data = load_json(p)
        except Exception:
            continue
        items = data.get("findings") if isinstance(data, dict) else data if isinstance(data, list) else []
        if not isinstance(items, list):
            continue
        for f in items:
            if not isinstance(f, dict):
                continue
            if project and f.get("project") not in {project, "", None}:
                continue
            sev = str(f.get("severity") or "unknown").lower()
            status = str(f.get("status") or "unknown").lower()
            facts["counts"][f"severity:{sev}"] = facts["counts"].get(f"severity:{sev}", 0) + 1
            facts["counts"][f"status:{status}"] = facts["counts"].get(f"status:{status}", 0) + 1
            if len(facts["samples"]) < 25:
                facts["samples"].append(shrink({
                    "id": f.get("finding_id") or f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "status": f.get("status"),
                    "component": f.get("component") or f.get("package"),
                    "owner": f.get("owner"),
                    "due_date": f.get("due_date"),
                    "source": f.get("source"),
                }))
    return facts


def collect_artifact_facts(extra_roots: List[str] | None = None) -> Dict[str, Any]:
    patterns = [
        "reports/**/*.json", "reports/**/*.md", "reports/**/*.sarif",
        "release-evidence/**/*.json", "release-evidence/**/*.md",
        "ui/storage/jobs/*/results/**/*.json", "ui/storage/jobs/*/results/**/*.md",
        "projects/**/*.json", "projects/**/*.md",
        "fuzzing/reports/**/*.json", "fuzzing/reports/**/*.md",
    ]
    absolute_extra_files = []
    for root in extra_roots or []:
        root = root.strip()
        if not root:
            continue
        root_path = Path(root)
        if root_path.is_absolute():
            if root_path.exists():
                for suffix in ("*.json", "*.md", "*.sarif", "*.txt", "*.log"):
                    absolute_extra_files.extend(root_path.rglob(suffix))
        else:
            patterns.extend([f"{root}/**/*.json", f"{root}/**/*.md", f"{root}/**/*.sarif", f"{root}/**/*.txt", f"{root}/**/*.log"])
    files = latest_files(patterns, limit=35)
    files = sorted({p.resolve(): p for p in [*files, *absolute_extra_files]}.values(), key=lambda p: p.stat().st_mtime, reverse=True)[:35]
    artifacts = []
    for p in files:
        suffix = p.suffix.lower()
        if suffix in {".json", ".sarif"}:
            artifacts.append(summarize_json(p))
        elif suffix in {".md", ".txt", ".log"}:
            text = read_text_limited(p, 2500)
            artifacts.append({"path": relative(p), "type": suffix.lstrip("."), "preview": text})
    return {"artifact_count": len(artifacts), "artifacts": artifacts}


def collect_facts(args: argparse.Namespace) -> Dict[str, Any]:
    sbom_path = Path(args.sbom) if getattr(args, "sbom", "") else None
    project = getattr(args, "project", "") or ""
    facts = {
        "metadata": {
            "generated_at": now_iso(),
            "tool": "SBOM Security Toolkit",
            "report_type": getattr(args, "report_type", "full"),
            "audience": getattr(args, "audience", "security"),
            "tone": getattr(args, "tone", "action-oriented"),
            "project": project,
            "evidence_bound": True,
            "ai_limitations": "AI-generated narrative is based only on extracted local evidence. AI does not approve releases, accept risk, suppress findings, or mark findings fixed.",
        },
        "sbom": parse_sbom(sbom_path),
        "findings": collect_findings(project),
        "artifacts": collect_artifact_facts(getattr(args, "evidence_roots", "").split(",") if getattr(args, "evidence_roots", "") else []),
    }
    return facts


def decision_hint(facts: Dict[str, Any]) -> str:
    counts = facts.get("findings", {}).get("counts", {})
    critical = counts.get("severity:critical", 0)
    high = counts.get("severity:high", 0)
    overdue = counts.get("status:overdue", 0)
    if critical or overdue:
        return "Block or require explicit exception review"
    if high:
        return "Warn and require remediation plan"
    return "Pass or monitor, subject to policy"


def build_prompt(facts: Dict[str, Any], report_type: str, audience: str, tone: str) -> str:
    title = REPORT_TYPES.get(report_type, REPORT_TYPES["full"])
    fact_text = json.dumps(shrink(facts, max_items=18, max_chars=12000), indent=2, sort_keys=True)
    return f"""You are generating an evidence-bound security report for SBOM/security operations.

Report type: {title}
Audience: {audience}
Tone: {tone}

Hard rules:
- Use only the facts in the JSON evidence bundle below.
- Do not invent CVEs, versions, owners, due dates, fixed versions, policies, or external facts.
- Do not approve risk acceptance, suppress findings, mark findings fixed, or authorize release.
- State uncertainty plainly when evidence is missing.
- Include concrete next actions and verification steps when the evidence supports them.
- Include a short "Evidence used" section listing artifact paths from the facts.

Evidence facts JSON:
```json
{fact_text}
```

Return a Markdown report with these sections when relevant:
1. Summary
2. What changed or what was analyzed
3. Key risks
4. Recommended actions
5. Owners / SLAs / tickets, if present
6. Verification steps
7. Evidence used
8. AI limitations
"""


def deterministic_report(facts: Dict[str, Any], report_type: str, audience: str, tone: str, provider_text: str = "") -> str:
    title = REPORT_TYPES.get(report_type, REPORT_TYPES["full"])
    sbom = facts.get("sbom", {})
    counts = facts.get("findings", {}).get("counts", {})
    samples = facts.get("findings", {}).get("samples", [])
    artifacts = facts.get("artifacts", {}).get("artifacts", [])
    lines = [
        f"# {title}",
        "",
        f"Generated: `{facts['metadata']['generated_at']}`",
        f"Audience: `{audience}`  ",
        f"Tone: `{tone}`  ",
        "",
        "## Summary",
        "",
        f"This report is generated from local SBOM Security Toolkit evidence. Suggested release posture: **{decision_hint(facts)}**.",
        "",
    ]
    if sbom:
        lines.extend([
            "## What was analyzed",
            "",
            f"- SBOM: `{sbom.get('path', 'not provided')}`",
            f"- Format: `{sbom.get('bom_format', 'unknown')}` `{sbom.get('spec_version', '')}`".rstrip(),
            f"- Components: `{sbom.get('component_count', 'unknown')}`",
            f"- Ecosystems: `{json.dumps(sbom.get('ecosystems', {}), sort_keys=True)}`",
            f"- Missing metadata: `{json.dumps(sbom.get('missing_metadata', {}), sort_keys=True)}`",
            "",
        ])
    lines.extend(["## Key risks", ""])
    if counts:
        for k, v in sorted(counts.items()):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- No normalized findings counts were available in the collected evidence.")
    lines.append("")
    if samples:
        lines.extend(["## Representative findings", ""])
        for f in samples[:12]:
            lines.append(f"- **{f.get('severity','unknown')}** `{f.get('id','')}` {f.get('title') or f.get('component') or 'finding'} — owner: `{f.get('owner') or 'unassigned'}`, status: `{f.get('status') or 'unknown'}`")
        lines.append("")
    if provider_text.strip():
        lines.extend(["## AI-generated narrative", "", provider_text.strip(), ""])
    lines.extend([
        "## Recommended actions",
        "",
        "1. Review critical/high or release-blocking findings first.",
        "2. Assign owners and due dates for unassigned findings.",
        "3. Use remediation plans and verification recipes before closing findings.",
        "4. Re-run analysis after fixes and attach the new evidence bundle.",
        "5. Use explicit, expiring exceptions for any accepted residual risk.",
        "",
        "## Verification steps",
        "",
        "- Re-scan the updated SBOM or repository.",
        "- Confirm vulnerable or unsupported versions are removed or justified.",
        "- Confirm release decision, lifecycle intelligence, findings dashboard, and fuzzing summaries no longer show unresolved blockers.",
        "- Keep evidence bundle and report artifacts attached to tickets or release records.",
        "",
        "## Evidence used",
        "",
    ])
    for a in artifacts[:25]:
        lines.append(f"- `{a.get('path')}`")
    if not artifacts:
        lines.append("- No additional report artifacts were found.")
    lines.extend([
        "",
        "## AI limitations",
        "",
        "AI-generated narrative, when present, is advisory and evidence-bound. AI did not approve the release, accept risk, suppress findings, or mark findings fixed.",
        "",
    ])
    return "\n".join(lines)


def markdown_to_html(md: str) -> str:
    # Lightweight HTML preview without external dependencies.
    out = ["<!doctype html><html><head><meta charset='utf-8'><title>AI Report</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;max-width:980px;margin:40px auto;line-height:1.55;color:#172033}pre,code{background:#f3f4f6;border-radius:6px}pre{padding:12px;overflow:auto}h1,h2,h3{color:#111827}li{margin:6px 0}</style></head><body>"]
    in_list = False
    for line in md.splitlines():
        if line.startswith("# "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{html.escape(line[2:])}</li>")
        elif re.match(r"^\d+\. ", line):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<p>{html.escape(line)}</p>")
        elif not line.strip():
            if in_list: out.append("</ul>"); in_list = False
            out.append("")
        else:
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<p>{html.escape(line)}</p>")
    if in_list: out.append("</ul>")
    out.append("</body></html>")
    return "\n".join(out)


def call_provider(prompt: str, provider: str, model: str, timeout: int) -> Tuple[str, Dict[str, Any]]:
    if provider in {"", "none", "prompt-only", "prompt"}:
        return "", {"provider": "none", "model": model or "none", "used_network": False, "ok": True, "mode": "prompt-only"}
    try:
        from ai_fuzz.tools.providers import complete
        result = complete(prompt, provider=provider, model=model or None, timeout=timeout)
        return result.text or "", {
            "provider": result.provider,
            "model": result.model,
            "used_network": result.used_network,
            "ok": result.error is None,
            "error": result.error,
        }
    except Exception as exc:
        return "", {"provider": provider, "model": model, "used_network": True, "ok": False, "error": str(exc)}


def generate(args: argparse.Namespace) -> Dict[str, Any]:
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    report_type = args.report_type
    audience = args.audience
    tone = args.tone
    facts = collect_facts(args)
    prompt = build_prompt(facts, report_type, audience, tone)
    ai_text, provider_meta = call_provider(prompt, args.provider, args.model, args.timeout)
    md = deterministic_report(facts, report_type, audience, tone, provider_text=ai_text)
    slug = safe_slug(REPORT_TYPES.get(report_type, report_type))
    md_path = out_dir / f"{slug}.md"
    html_path = out_dir / f"{slug}.html"
    facts_path = out_dir / "report-input-facts.json"
    prompt_path = out_dir / f"{slug}.prompt.md"
    meta_path = out_dir / "report-generation-metadata.json"
    json_summary_path = out_dir / f"{slug}.summary.json"
    facts_path.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    prompt_path.write_text(prompt, encoding="utf-8")
    md_path.write_text(md, encoding="utf-8")
    html_path.write_text(markdown_to_html(md), encoding="utf-8")
    meta = {
        "generated_at": now_iso(),
        "report_type": report_type,
        "report_title": REPORT_TYPES.get(report_type, report_type),
        "audience": audience,
        "tone": tone,
        "provider": provider_meta,
        "evidence_bound": True,
        "outputs": {"markdown": relative(md_path), "html": relative(html_path), "facts": relative(facts_path), "prompt": relative(prompt_path), "summary_json": relative(json_summary_path)},
        "safety": {
            "ai_advisory_only": True,
            "ai_approves_release": False,
            "ai_accepts_risk": False,
            "ai_suppresses_findings": False,
            "ai_marks_fixed": False,
        },
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json_summary_path.write_text(json.dumps({"metadata": meta, "summary": {"decision_hint": decision_hint(facts), "finding_counts": facts.get("findings", {}).get("counts", {}), "sbom": facts.get("sbom", {})}}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate evidence-bound AI-assisted text reports from SBOM Security Toolkit artifacts")
    ap.add_argument("command", nargs="?", default="generate", choices=["generate", "facts", "templates", "smoke"])
    ap.add_argument("--sbom", default="", help="Optional SBOM path to include in the fact bundle")
    ap.add_argument("--project", default="", help="Optional project filter")
    ap.add_argument("--report-type", default="full", choices=sorted(REPORT_TYPES.keys()))
    ap.add_argument("--audience", default="security", choices=sorted(AUDIENCES))
    ap.add_argument("--tone", default="action-oriented", choices=sorted(TONES))
    ap.add_argument("--provider", default="none", help="none, bedrock, ollama, glm, or openai-compatible")
    ap.add_argument("--model", default="")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT.relative_to(ROOT)))
    ap.add_argument("--evidence-roots", default="", help="Comma-separated additional evidence roots")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.command == "templates":
        print(json.dumps({"report_types": REPORT_TYPES, "audiences": sorted(AUDIENCES), "tones": sorted(TONES)}, indent=2, sort_keys=True))
        return 0
    if args.command == "facts":
        facts = collect_facts(args)
        out = Path(args.out_dir)
        if not out.is_absolute(): out = ROOT / out
        out.mkdir(parents=True, exist_ok=True)
        fp = out / "report-input-facts.json"
        fp.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"facts": relative(fp)}, indent=2))
        return 0
    if args.command == "smoke":
        if not args.sbom:
            args.sbom = "test-sboms/example-spdx-2.3.json"
        args.provider = "none"
        args.report_type = "full"
    meta = generate(args)
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
