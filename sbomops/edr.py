#!/usr/bin/env python3
"""Exploitability Decision Records for human-reviewed VEX evidence."""
from __future__ import annotations
import argparse, datetime, re
from pathlib import Path
from .common import write_markdown, write_json

VALID = {"affected", "not_affected", "fixed", "under_investigation"}


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip("-")[:120]


def create(args):
    status = args.status
    if status not in VALID:
        raise SystemExit(f"status must be one of: {', '.join(sorted(VALID))}")
    today = datetime.date.today().isoformat()
    data = {
        "cve": args.cve.upper(), "component": args.component, "status": status,
        "justification": args.justification or "TBD - human review required",
        "evidence_reviewed": args.evidence or [], "scanner_source": args.scanner_source or "",
        "runtime_exposure": args.runtime_exposure or "unknown", "reviewer": args.reviewer or "TBD",
        "review_date": today, "expiration_date": args.expiration_date or "TBD"
    }
    name = f"{slug(data['cve'])}-{slug(data['component'])}.md"
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    path = out / name
    md = f"""# Exploitability Decision Record: {data['cve']}

| Field | Value |
|---|---|
| CVE | {data['cve']} |
| Component | {data['component']} |
| Status | {data['status']} |
| Justification | {data['justification']} |
| Runtime exposure | {data['runtime_exposure']} |
| Scanner/source | {data['scanner_source']} |
| Reviewer | {data['reviewer']} |
| Review date | {data['review_date']} |
| Expiration date | {data['expiration_date']} |

## Evidence reviewed

"""
    md += "\n".join(f"- {e}" for e in data["evidence_reviewed"]) if data["evidence_reviewed"] else "- TBD\n"
    md += "\n\n## Human-review warning\n\nDo not convert this record into VEX `not_affected` without technical evidence and approval.\n"
    write_markdown(path, md)
    write_json(out / f"{path.stem}.json", data)
    print(path)


def validate(args):
    text = Path(args.record).read_text(encoding="utf-8", errors="replace")
    required = ["CVE", "Component", "Status", "Justification", "Reviewer", "Review date"]
    missing = [x for x in required if x not in text]
    status = "PASS" if not missing else "FAIL"
    result = {"status": status, "missing": missing, "record": args.record}
    write_json(args.out, result)
    print(f"EDR validation: {status}")


def main():
    ap = argparse.ArgumentParser(description="Create/validate exploitability decision records.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--cve", required=True); c.add_argument("--component", required=True); c.add_argument("--status", default="under_investigation")
    c.add_argument("--justification"); c.add_argument("--evidence", action="append"); c.add_argument("--scanner-source"); c.add_argument("--runtime-exposure")
    c.add_argument("--reviewer"); c.add_argument("--expiration-date"); c.add_argument("--out-dir", default="exploitability-records")
    v = sub.add_parser("validate"); v.add_argument("record"); v.add_argument("--out", default="reports/edr-validation.json")
    args = ap.parse_args()
    if args.cmd == "create": create(args)
    else: validate(args)

if __name__ == "__main__":
    main()
