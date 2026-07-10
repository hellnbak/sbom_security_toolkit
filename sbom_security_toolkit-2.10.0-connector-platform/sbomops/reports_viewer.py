#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
REPORT_INDEX = ROOT / "reports" / "report-index.json"
REPORT_INDEX_MD = ROOT / "reports" / "report-index.md"
DEFAULT_ROOTS = [
    ROOT / "reports",
    ROOT / "release-evidence",
    ROOT / "ui" / "storage" / "jobs",
    ROOT / "findings",
    ROOT / "fuzzing" / "reports",
    ROOT / "projects",
]
REPORT_SUFFIXES = {".json", ".md", ".txt", ".html", ".htm", ".csv", ".sarif", ".yml", ".yaml", ".xml"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist"}
MAX_PREVIEW_BYTES = 256 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def is_report_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.endswith((".pyc", ".pyo")):
        return False
    if path.suffix.lower() in REPORT_SUFFIXES:
        return True
    # Evidence/result files often have no useful suffix but recognizable names.
    return path.name in {"status.json", "logs.txt", "fuzz-run-summary.md", "fuzz-run-summary.json"}


def classify_report(path: Path) -> str:
    rel = safe_rel(path)
    name = path.name.lower()
    if "sarif" in rel or path.suffix.lower() == ".sarif":
        return "SARIF"
    if "openvex" in rel or "vex" in rel:
        return "OpenVEX / VEX"
    if "findings" in rel or "remediation" in rel or "ticket" in name:
        return "Findings & remediation"
    if "fuzz" in rel or "metamorphic" in rel or "roundtrip" in rel:
        return "Fuzzing"
    if "dependency-health" in rel or "unsupported" in rel:
        return "Dependency health"
    if "policy" in rel or "release-decision" in rel:
        return "Policy / release decision"
    if "minimum" in rel or "quality" in rel or "score" in rel:
        return "SBOM quality"
    if "jira" in rel or "defectdojo" in rel or "integrations" in rel:
        return "Integrations"
    if "jobs" in rel or name == "status.json" or name == "logs.txt":
        return "Job evidence"
    if "project" in rel or "trend" in rel or "delta" in rel:
        return "Project history"
    return "General report"


def title_for(path: Path) -> str:
    stem = path.stem.replace("-", " ").replace("_", " ").strip()
    return stem.title() if stem else path.name


def iter_report_files(roots: Iterable[Path]) -> Iterable[Path]:
    seen = set()
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            candidates = [root]
        else:
            candidates = []
            for p in root.rglob("*"):
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                candidates.append(p)
        for path in candidates:
            try:
                resolved = path.resolve()
            except Exception:
                continue
            if resolved in seen or not is_report_file(path):
                continue
            seen.add(resolved)
            yield path


def report_record(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    rel = safe_rel(path)
    return {
        "id": rel,
        "title": title_for(path),
        "category": classify_report(path),
        "path": rel,
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "extension": path.suffix.lower() or "",
        "mime_type": mimetypes.guess_type(str(path))[0] or "text/plain",
    }


def index_reports(args: argparse.Namespace) -> Dict[str, Any]:
    roots = [ROOT / r for r in getattr(args, "roots", [])] if getattr(args, "roots", None) else DEFAULT_ROOTS
    records = sorted((report_record(p) for p in iter_report_files(roots)), key=lambda r: (r["category"], r["path"]))
    out = Path(getattr(args, "out", "") or REPORT_INDEX)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated_at": now(), "report_count": len(records), "reports": records}
    out.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md = Path(getattr(args, "markdown", "") or REPORT_INDEX_MD)
    md.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# SBOM Security Toolkit report index", "", f"Generated: {payload['generated_at']}", f"Reports: {len(records)}", ""]
    current = None
    for r in records:
        if r["category"] != current:
            current = r["category"]
            lines.extend(["", f"## {current}", ""])
        lines.append(f"- **{r['title']}** — `{r['path']}` ({r['size_bytes']} bytes)")
    md.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return {"index": str(out), "markdown": str(md), "reports": len(records)}


def resolve_report(report_id: str) -> Path:
    candidate = (ROOT / report_id).resolve()
    root = ROOT.resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("Report path is outside the toolkit workspace")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(report_id)
    if not is_report_file(candidate):
        raise ValueError("Selected file is not a supported report type")
    return candidate


def read_report(report_id: str, max_bytes: int = MAX_PREVIEW_BYTES) -> Dict[str, Any]:
    path = resolve_report(report_id)
    raw = path.read_bytes()[:max_bytes]
    truncated = path.stat().st_size > len(raw)
    text = raw.decode("utf-8", errors="replace")
    parsed: Any = None
    if path.suffix.lower() in {".json", ".sarif"} or path.name.endswith(".json"):
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
    elif path.suffix.lower() == ".csv":
        try:
            parsed = list(csv.DictReader(text.splitlines()))[:100]
        except Exception:
            parsed = None
    return {"report": report_record(path), "text": text, "parsed": parsed, "truncated": truncated, "max_bytes": max_bytes}


def main() -> int:
    ap = argparse.ArgumentParser(description="Index and view local SBOM Security Toolkit reports without downloading evidence bundles")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("index")
    p.add_argument("--root", dest="roots", action="append", help="Relative root to scan. May be supplied multiple times.")
    p.add_argument("--out", default=str(REPORT_INDEX))
    p.add_argument("--markdown", default=str(REPORT_INDEX_MD))
    p.set_defaults(fn=index_reports)
    p = sub.add_parser("view")
    p.add_argument("report_id")
    p.add_argument("--max-bytes", type=int, default=MAX_PREVIEW_BYTES)
    def _view(args: argparse.Namespace) -> Dict[str, Any]:
        return read_report(args.report_id, args.max_bytes)
    p.set_defaults(fn=_view)
    args = ap.parse_args()
    result = args.fn(args)
    print(json.dumps(result, indent=2, sort_keys=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
