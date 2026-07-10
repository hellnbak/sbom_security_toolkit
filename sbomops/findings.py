#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from .common import parse_components
from .integrations import component_findings

ROOT = Path(__file__).resolve().parents[1]
FINDINGS_DIR = ROOT / "findings"
DB = FINDINGS_DIR / "findings.json"
EXCEPTIONS = FINDINGS_DIR / "exceptions.json"
CAMPAIGNS = FINDINGS_DIR / "campaigns.json"
REPORTS = ROOT / "reports" / "findings"

SEVERITY_SLA_DAYS = {
    "critical": 15,
    "high": 30,
    "medium": 45,
    "low": 90,
    "info": 180,
    "warning": 45,
    "error": 15,
    "note": 180,
}

STATUS_OPEN = {"new", "triaged", "assigned", "in_progress", "candidate_fixed", "reopened"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def write_text(path: Path, data: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    return path


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return default


def load_db() -> Dict[str, Any]:
    ensure_dirs()
    db = read_json(DB, {"version": 1, "updated_at": now(), "findings": []})
    db.setdefault("findings", [])
    return db


def save_db(db: Dict[str, Any]) -> Path:
    db["updated_at"] = now()
    return write_json(DB, db)


def slug(s: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(s)).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out or "unknown"


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(str(p or "") for p in parts).encode()).hexdigest()[:20]


def normalize_severity(level: str, rule_id: str = "") -> str:
    l = (level or "").lower()
    rid = (rule_id or "").lower()
    if l in {"critical", "high", "medium", "low", "info"}:
        return l
    if "critical" in rid or l == "error":
        return "critical"
    if l == "warning":
        return "medium"
    if l == "note":
        return "info"
    return "medium"


def due_date(first_seen: str, severity: str, source: str = "") -> str:
    days = SEVERITY_SLA_DAYS.get((severity or "medium").lower(), 45)
    if source in {"policy", "release"}:
        days = min(days, 7)
    try:
        dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)
    return (dt + timedelta(days=days)).date().isoformat()


def infer_ecosystem(purl: str, component: str = "") -> str:
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:maven/"):
        return "maven"
    if purl.startswith("pkg:golang/"):
        return "go"
    if purl.startswith("pkg:cargo/"):
        return "cargo"
    if purl.startswith("pkg:nuget/"):
        return "nuget"
    if purl.startswith("pkg:composer/"):
        return "composer"
    return "unknown"


def default_owner(component: str, purl: str, owners_file: str = "owners.yml") -> str:
    p = ROOT / owners_file
    if yaml and p.exists():
        data = yaml.safe_load(p.read_text()) or {}
        owners = data.get("owners", data) if isinstance(data, dict) else {}
        packages = owners.get("packages", {}) if isinstance(owners, dict) else {}
        ecosystems = owners.get("ecosystems", {}) if isinstance(owners, dict) else {}
        eco = infer_ecosystem(purl, component)
        key1 = f"{eco}:{component}"
        for key in (key1, component, purl):
            if isinstance(packages, dict) and key in packages:
                return str(packages[key])
        if isinstance(ecosystems, dict) and eco in ecosystems:
            return str(ecosystems[eco])
    return "unassigned"


def remediation_commands(ecosystem: str, name: str, version: str, fixed_version: str = "") -> List[str]:
    target = fixed_version or "<safe-version>"
    if ecosystem == "npm":
        return [f"npm install {name}@{target}", "npm test", "npm audit --omit=dev"]
    if ecosystem == "pypi":
        return [f"pip install --upgrade {name}=={target}", "pip freeze > requirements.txt", "pytest"]
    if ecosystem == "maven":
        return [f"mvn versions:use-dep-version -Dincludes={name} -DdepVersion={target}", "mvn test"]
    if ecosystem == "go":
        return [f"go get {name}@{target}", "go mod tidy", "go test ./..."]
    if ecosystem == "cargo":
        return [f"cargo update -p {name} --precise {target}", "cargo test"]
    if ecosystem == "nuget":
        return [f"dotnet add package {name} --version {target}", "dotnet test"]
    if ecosystem == "composer":
        return [f"composer require {name}:{target}", "composer test"]
    return ["Update or replace the affected dependency using the ecosystem package manager.", "Regenerate the SBOM.", "Re-run SBOM Security Toolkit verification."]


def breaking_change_risk(version: str, fixed_version: str = "") -> str:
    if not fixed_version or not version:
        return "unknown"
    try:
        cur = [int(x) for x in version.split(".")[:3] if x.isdigit()]
        tgt = [int(x) for x in fixed_version.split(".")[:3] if x.isdigit()]
        if cur and tgt and tgt[0] > cur[0]:
            return "high"
        if len(cur) > 1 and len(tgt) > 1 and tgt[1] > cur[1]:
            return "medium"
        return "low"
    except Exception:
        return "unknown"


def build_remediation(f: Dict[str, Any], fixed_version: str = "") -> Dict[str, Any]:
    name = f.get("component") or f.get("package") or "unknown"
    version = f.get("version") or ""
    purl = f.get("purl") or ""
    ecosystem = f.get("ecosystem") or infer_ecosystem(purl, name)
    source = f.get("source", "finding")
    severity = f.get("severity", "medium")
    risk_to_leave = "critical" if severity in {"critical", "high"} else "moderate" if severity == "medium" else "low"
    fix_risk = breaking_change_risk(version, fixed_version)
    if source in {"dependency-health", "unsupported"} or "unsupported" in (f.get("title", "") + f.get("rule_id", "")).lower():
        recommended = "Replace, upgrade to a maintained release, or risk-accept temporarily with an expiry date if no maintained fix exists."
        playbook = "unsupported-dependency"
    elif source in {"fuzzing", "scanner-disagreement"}:
        recommended = "Reproduce the case, add a regression test, fix parser/scanner behavior, and verify with the original fuzz input."
        playbook = "fuzzing-or-scanner-finding"
    elif source in {"policy", "release"}:
        recommended = "Resolve the blocking policy condition or attach an approved time-bound release exception."
        playbook = "release-policy-failure"
    else:
        recommended = "Upgrade to the minimum safe version, regenerate lockfiles/SBOM, run tests, and verify the finding is gone."
        playbook = "vulnerability-or-quality-finding"
    return {
        "finding_id": f.get("finding_id"),
        "component": name,
        "current_version": version,
        "minimum_safe_version": fixed_version or "unknown",
        "recommended_target_version": fixed_version or "latest stable safe version confirmed by scanner/vendor",
        "ecosystem": ecosystem,
        "upgrade_type": "unknown" if not fixed_version else breaking_change_risk(version, fixed_version),
        "breaking_change_risk": fix_risk,
        "risk_to_leave_unfixed": risk_to_leave,
        "risk_to_fix": fix_risk,
        "recommended_action": recommended,
        "playbook": playbook,
        "commands": remediation_commands(ecosystem, name, version, fixed_version),
        "verification_steps": [
            "Regenerate the SBOM after remediation.",
            "Re-run the same SBOM Security Toolkit workflow that found the issue.",
            "Confirm the affected component/version is removed or updated.",
            "Confirm policy/release decision no longer blocks, or that the exception remains valid.",
            "Attach the new evidence bundle to the finding or ticket.",
        ],
        "rollback_guidance": [
            "Keep the previous lockfile/package manifest available for rollback.",
            "Roll back only if tests or runtime validation fail.",
            "Do not roll back without reassessing exposure if the original issue is critical or exploitable.",
        ],
        "compensating_controls": [
            "Disable or restrict use of the vulnerable feature path where practical.",
            "Restrict network exposure for affected services.",
            "Increase monitoring and alerting for the affected component or service.",
            "Pin a safer transitive dependency if the vulnerable package is indirect.",
            "Use a time-bound risk acceptance only when a direct fix is not available.",
        ],
        "acceptance_criteria": [
            "Affected version is no longer present in the SBOM.",
            "Tests relevant to the owning service pass.",
            "A new scan shows the finding as candidate_fixed or verified.",
            "Any ticket includes evidence bundle links and verification output.",
        ],
    }


def make_finding(project: str, raw: Dict[str, Any], sbom: str, owner: str = "") -> Dict[str, Any]:
    rule = raw.get("rule_id") or raw.get("source") or "SST-FINDING"
    component = raw.get("component") or raw.get("name") or raw.get("package") or "unknown"
    version = raw.get("version") or ""
    purl = raw.get("purl") or ""
    source = raw.get("source") or ("dependency-health" if "unsupported" in rule.lower() else "sbom-analysis")
    sev = normalize_severity(raw.get("severity") or raw.get("level") or "medium", rule)
    fid = fingerprint(project, rule, component, version, purl)
    first = now()
    return {
        "finding_id": fid,
        "fingerprint": fid,
        "project": project,
        "source": source,
        "rule_id": rule,
        "title": raw.get("title") or rule,
        "description": raw.get("message") or raw.get("description") or "",
        "severity": sev,
        "status": "new",
        "owner": owner or default_owner(component, purl),
        "component": component,
        "version": version,
        "purl": purl,
        "ecosystem": infer_ecosystem(purl, component),
        "first_seen": first,
        "last_seen": first,
        "due_date": due_date(first, sev, source),
        "evidence": {"sbom": sbom},
        "ticket": {},
        "exception": {},
        "remediation": {},
        "history": [{"at": first, "action": "created", "detail": "Imported from SBOM Security Toolkit analysis."}],
    }


def upsert_findings(project: str, raws: Iterable[Dict[str, Any]], sbom: str, owner: str = "") -> Dict[str, Any]:
    db = load_db()
    existing = {f.get("finding_id"): f for f in db["findings"]}
    imported = 0
    updated = 0
    seen_ids = set()
    for raw in raws:
        f = make_finding(project, raw, sbom, owner=owner)
        fid = f["finding_id"]
        seen_ids.add(fid)
        if fid in existing:
            cur = existing[fid]
            cur["last_seen"] = now()
            cur["severity"] = f["severity"]
            cur["description"] = f["description"]
            cur["evidence"] = {**cur.get("evidence", {}), **f["evidence"]}
            if cur.get("status") in {"fixed", "verified"}:
                cur["status"] = "reopened"
                cur.setdefault("history", []).append({"at": now(), "action": "reopened", "detail": "Finding reappeared in a later scan."})
            else:
                cur.setdefault("history", []).append({"at": now(), "action": "seen", "detail": "Finding observed in scan."})
            updated += 1
        else:
            db["findings"].append(f)
            existing[fid] = f
            imported += 1
    # candidate-fixed for open findings in project not seen this run when importing a full SBOM view
    for f in db["findings"]:
        if f.get("project") == project and f.get("finding_id") not in seen_ids and f.get("status") in STATUS_OPEN:
            f["status"] = "candidate_fixed"
            f.setdefault("history", []).append({"at": now(), "action": "candidate_fixed", "detail": "Not observed in latest imported scan; verification required."})
    save_db(db)
    return {"imported": imported, "updated": updated, "candidate_fixed_marked": sum(1 for f in db["findings"] if f.get("project") == project and f.get("status") == "candidate_fixed"), "database": str(DB)}


def import_sbom(args: argparse.Namespace) -> Dict[str, Any]:
    raws = component_findings(args.sbom)
    result = upsert_findings(args.project, raws, args.sbom, owner=args.owner)
    write_json(REPORTS / "last-import.json", {"generated_at": now(), **result})
    return result


def get_finding(fid: str) -> Dict[str, Any]:
    for f in load_db().get("findings", []):
        if f.get("finding_id") == fid or f.get("fingerprint") == fid:
            return f
    raise SystemExit(f"Finding not found: {fid}")


def list_findings(args: argparse.Namespace) -> Dict[str, Any]:
    findings = load_db().get("findings", [])
    if args.project:
        findings = [f for f in findings if f.get("project") == args.project]
    if args.status:
        statuses = set(args.status.split(","))
        findings = [f for f in findings if f.get("status") in statuses]
    if args.owner:
        findings = [f for f in findings if f.get("owner") == args.owner]
    if args.severity:
        sevs = set(args.severity.split(","))
        findings = [f for f in findings if f.get("severity") in sevs]
    rows = findings[: args.limit]
    out = {"count": len(findings), "returned": len(rows), "findings": rows}
    if args.out:
        write_json(Path(args.out), out)
    return out


def update_finding(args: argparse.Namespace) -> Dict[str, Any]:
    db = load_db()
    updated = None
    for f in db["findings"]:
        if f.get("finding_id") == args.finding_id:
            if args.status:
                f["status"] = args.status
            if args.owner:
                f["owner"] = args.owner
            if args.ticket_url:
                f.setdefault("ticket", {})["url"] = args.ticket_url
            f.setdefault("history", []).append({"at": now(), "action": "updated", "detail": f"status={args.status or ''} owner={args.owner or ''}"})
            updated = f
            break
    if not updated:
        raise SystemExit(f"Finding not found: {args.finding_id}")
    save_db(db)
    return updated


def accept_or_suppress(args: argparse.Namespace, status: str) -> Dict[str, Any]:
    db = load_db()
    out = None
    for f in db["findings"]:
        if f.get("finding_id") == args.finding_id:
            f["status"] = status
            f["exception"] = {
                "type": status,
                "reason": args.reason,
                "owner": args.owner or f.get("owner"),
                "expires_at": args.expires_at,
                "conditions": args.conditions,
                "created_at": now(),
            }
            f.setdefault("history", []).append({"at": now(), "action": status, "detail": args.reason})
            out = f
            break
    if not out:
        raise SystemExit(f"Finding not found: {args.finding_id}")
    save_db(db)
    return out


def verify(args: argparse.Namespace) -> Dict[str, Any]:
    # Re-import current SBOM if provided, then verify candidate_fixed findings for project.
    if args.sbom:
        import_sbom(argparse.Namespace(sbom=args.sbom, project=args.project, owner=""))
    db = load_db()
    verified = []
    for f in db["findings"]:
        if args.project and f.get("project") != args.project:
            continue
        if f.get("status") == "candidate_fixed":
            f["status"] = "verified"
            f["fixed_at"] = now()
            f.setdefault("history", []).append({"at": now(), "action": "verified", "detail": "Candidate-fixed finding verified by workflow."})
            verified.append(f.get("finding_id"))
    save_db(db)
    return {"verified": len(verified), "finding_ids": verified, "database": str(DB)}


def generate_remediation(args: argparse.Namespace) -> Dict[str, Any]:
    db = load_db()
    updated = []
    for f in db["findings"]:
        if args.finding_id and f.get("finding_id") != args.finding_id:
            continue
        if args.project and f.get("project") != args.project:
            continue
        if f.get("status") in {"verified", "suppressed"} and not args.include_closed:
            continue
        f["remediation"] = build_remediation(f, fixed_version=args.fixed_version)
        f.setdefault("history", []).append({"at": now(), "action": "remediation_plan", "detail": "Generated remediation plan."})
        updated.append(f)
    save_db(db)
    out = {"generated_at": now(), "count": len(updated), "findings": updated}
    write_json(REPORTS / "remediation-plans.json", out)
    write_text(REPORTS / "remediation-plans.md", remediation_markdown(updated))
    return {"count": len(updated), "json": str(REPORTS / "remediation-plans.json"), "markdown": str(REPORTS / "remediation-plans.md")}


def remediation_markdown(findings: List[Dict[str, Any]]) -> str:
    lines = ["# Remediation plans", "", f"Generated: {now()}", ""]
    for f in findings:
        r = f.get("remediation", {})
        lines += [
            f"## {f.get('title')} ({f.get('finding_id')})",
            "",
            f"- Project: `{f.get('project')}`",
            f"- Severity: `{f.get('severity')}`",
            f"- Owner: `{f.get('owner')}`",
            f"- Component: `{f.get('component')}` `{f.get('version')}`",
            f"- Recommended action: {r.get('recommended_action','')}",
            f"- Breaking-change risk: `{r.get('breaking_change_risk','unknown')}`",
            "",
            "### Suggested commands",
            "",
        ]
        lines += [f"```bash\n{cmd}\n```" for cmd in r.get("commands", [])[:5]]
        lines += ["", "### Verification", ""] + [f"- {x}" for x in r.get("verification_steps", [])] + [""]
    return "\n".join(lines)


def ticket_text(args: argparse.Namespace) -> Dict[str, Any]:
    f = get_finding(args.finding_id)
    r = f.get("remediation") or build_remediation(f, fixed_version=args.fixed_version)
    title = f"[{f.get('severity','medium').upper()}] {f.get('title')} - {f.get('component')}"
    body = f"""## Summary
{f.get('description')}

## Affected component
- Component: `{f.get('component')}`
- Version: `{f.get('version')}`
- PURL: `{f.get('purl')}`
- Source: `{f.get('source')}`
- Owner: `{f.get('owner')}`
- Due date: `{f.get('due_date')}`

## Recommended remediation
{r.get('recommended_action')}

## Suggested commands
{chr(10).join('- `' + c + '`' for c in r.get('commands', []))}

## Acceptance criteria
{chr(10).join('- ' + c for c in r.get('acceptance_criteria', []))}

## Verification steps
{chr(10).join('- ' + c for c in r.get('verification_steps', []))}

## Evidence
{json.dumps(f.get('evidence', {}), indent=2)}
"""
    out = {"title": title, "body": body, "finding_id": f.get("finding_id")}
    write_json(REPORTS / "ticket-template.json", out)
    write_text(REPORTS / "ticket-template.md", f"# {title}\n\n{body}\n")
    return {"json": str(REPORTS / "ticket-template.json"), "markdown": str(REPORTS / "ticket-template.md")}


def sla_report(args: argparse.Namespace) -> Dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    rows = []
    for f in load_db().get("findings", []):
        if args.project and f.get("project") != args.project:
            continue
        if f.get("status") not in STATUS_OPEN:
            continue
        due = f.get("due_date") or due_date(f.get("first_seen", now()), f.get("severity", "medium"), f.get("source", ""))
        try:
            due_d = datetime.fromisoformat(due).date()
            days = (due_d - today).days
        except Exception:
            days = 9999
        rows.append({**f, "days_until_due": days, "sla_state": "overdue" if days < 0 else "due-soon" if days <= 7 else "within-sla"})
    summary = {"overdue": sum(1 for r in rows if r["sla_state"] == "overdue"), "due_soon": sum(1 for r in rows if r["sla_state"] == "due-soon"), "within_sla": sum(1 for r in rows if r["sla_state"] == "within-sla")}
    out = {"generated_at": now(), "summary": summary, "findings": rows}
    write_json(REPORTS / "sla-report.json", out)
    return out


def dashboard(args: argparse.Namespace) -> Dict[str, Any]:
    findings = load_db().get("findings", [])
    if args.project:
        findings = [f for f in findings if f.get("project") == args.project]
    by_status: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_owner: Dict[str, int] = {}
    for f in findings:
        by_status[f.get("status", "unknown")] = by_status.get(f.get("status", "unknown"), 0) + 1
        by_severity[f.get("severity", "unknown")] = by_severity.get(f.get("severity", "unknown"), 0) + 1
        by_owner[f.get("owner", "unassigned")] = by_owner.get(f.get("owner", "unassigned"), 0) + 1
    sla = sla_report(argparse.Namespace(project=args.project))
    out = {"generated_at": now(), "project": args.project or "all", "total": len(findings), "by_status": by_status, "by_severity": by_severity, "by_owner": by_owner, "sla": sla.get("summary", {})}
    write_json(REPORTS / "dashboard.json", out)
    write_text(REPORTS / "dashboard.md", dashboard_md(out))
    return out


def dashboard_md(data: Dict[str, Any]) -> str:
    lines = ["# Findings dashboard", "", f"Generated: {data.get('generated_at')}", "", f"Total findings: **{data.get('total')}**", "", "## By status", ""]
    lines += [f"- {k}: {v}" for k, v in sorted(data.get("by_status", {}).items())]
    lines += ["", "## By severity", ""] + [f"- {k}: {v}" for k, v in sorted(data.get("by_severity", {}).items())]
    lines += ["", "## By owner", ""] + [f"- {k}: {v}" for k, v in sorted(data.get("by_owner", {}).items())]
    lines += ["", "## SLA", ""] + [f"- {k}: {v}" for k, v in sorted(data.get("sla", {}).items())]
    return "\n".join(lines) + "\n"


def next_actions(args: argparse.Namespace) -> Dict[str, Any]:
    rows = []
    for f in load_db().get("findings", []):
        if args.project and f.get("project") != args.project:
            continue
        if f.get("status") not in STATUS_OPEN | {"risk_accepted"}:
            continue
        score = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}.get(f.get("severity", "medium"), 50)
        if f.get("status") == "candidate_fixed": score += 30
        if f.get("owner") in {"", "unassigned"}: score += 20
        if f.get("status") == "risk_accepted": score -= 20
        due = f.get("due_date", "9999-12-31")
        rows.append({"priority": score, "finding_id": f.get("finding_id"), "title": f.get("title"), "owner": f.get("owner"), "status": f.get("status"), "severity": f.get("severity"), "due_date": due, "next_action": infer_next_action(f)})
    rows.sort(key=lambda r: (-r["priority"], r["due_date"]))
    out = {"generated_at": now(), "actions": rows[: args.limit]}
    write_json(REPORTS / "next-actions.json", out)
    write_text(REPORTS / "next-actions.md", "# Next best actions\n\n" + "\n".join(f"{i+1}. **{r['next_action']}** — {r['title']} (`{r['finding_id']}`) owner `{r['owner']}`" for i, r in enumerate(out["actions"])) + "\n")
    return out


def infer_next_action(f: Dict[str, Any]) -> str:
    if f.get("status") == "candidate_fixed":
        return "Verify fixed with a new scan and evidence bundle"
    if f.get("owner") in {"", "unassigned"}:
        return "Assign an owner"
    if f.get("severity") in {"critical", "high"}:
        return "Create or update remediation ticket"
    if f.get("status") == "risk_accepted":
        return "Review exception expiry and conditions"
    return "Triage and generate remediation plan"


def create_campaign(args: argparse.Namespace) -> Dict[str, Any]:
    data = read_json(CAMPAIGNS, {"campaigns": []})
    cid = slug(args.name)
    campaign = {"campaign_id": cid, "name": args.name, "project": args.project, "description": args.description, "finding_ids": [x.strip() for x in args.finding_ids.split(",") if x.strip()], "owner": args.owner, "created_at": now(), "status": "active"}
    data["campaigns"] = [c for c in data.get("campaigns", []) if c.get("campaign_id") != cid] + [campaign]
    write_json(CAMPAIGNS, data)
    return campaign


def campaigns(args: argparse.Namespace) -> Dict[str, Any]:
    data = read_json(CAMPAIGNS, {"campaigns": []})
    findings = {f.get("finding_id"): f for f in load_db().get("findings", [])}
    summaries = []
    for c in data.get("campaigns", []):
        fs = [findings[i] for i in c.get("finding_ids", []) if i in findings]
        summaries.append({**c, "total": len(fs), "fixed": sum(1 for f in fs if f.get("status") in {"fixed", "verified"}), "open": sum(1 for f in fs if f.get("status") in STATUS_OPEN), "risk_accepted": sum(1 for f in fs if f.get("status") == "risk_accepted")})
    return {"campaigns": summaries}


def export_report(args: argparse.Namespace) -> Dict[str, Any]:
    data = list_findings(argparse.Namespace(project=args.project, status=args.status, owner="", severity="", limit=100000, out=""))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "findings-export.json", data)
    with (out_dir / "findings-export.csv").open("w", newline="", encoding="utf-8") as fh:
        cols = ["finding_id", "project", "severity", "status", "owner", "source", "component", "version", "title", "due_date"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for f in data["findings"]:
            w.writerow({k: f.get(k, "") for k in cols})
    write_text(out_dir / "findings-report.md", dashboard_md(dashboard(argparse.Namespace(project=args.project))))
    return {"json": str(out_dir / "findings-export.json"), "csv": str(out_dir / "findings-export.csv"), "markdown": str(out_dir / "findings-report.md"), "count": data["count"]}


def smoke(args: argparse.Namespace) -> Dict[str, Any]:
    project = args.project
    result = import_sbom(argparse.Namespace(sbom=args.sbom, project=project, owner="platform-security"))
    dash = dashboard(argparse.Namespace(project=project))
    rem = generate_remediation(argparse.Namespace(project=project, finding_id="", fixed_version="", include_closed=True))
    actions = next_actions(argparse.Namespace(project=project, limit=10))
    report = export_report(argparse.Namespace(project=project, status="", out_dir="reports/findings-smoke"))
    return {"import": result, "dashboard": dash, "remediation": rem, "next_actions": len(actions.get("actions", [])), "export": report}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Findings and remediation operations for SBOM Security Toolkit.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import-sbom"); p.add_argument("--sbom", required=True); p.add_argument("--project", default="default-project"); p.add_argument("--owner", default=""); p.set_defaults(func=import_sbom)
    p = sub.add_parser("list"); p.add_argument("--project", default=""); p.add_argument("--status", default=""); p.add_argument("--owner", default=""); p.add_argument("--severity", default=""); p.add_argument("--limit", type=int, default=50); p.add_argument("--out", default=""); p.set_defaults(func=list_findings)
    p = sub.add_parser("show"); p.add_argument("finding_id"); p.set_defaults(func=lambda a: get_finding(a.finding_id))
    p = sub.add_parser("update"); p.add_argument("--finding-id", required=True); p.add_argument("--status", default=""); p.add_argument("--owner", default=""); p.add_argument("--ticket-url", default=""); p.set_defaults(func=update_finding)
    p = sub.add_parser("assign"); p.add_argument("--finding-id", required=True); p.add_argument("--owner", required=True); p.set_defaults(func=lambda a: update_finding(argparse.Namespace(finding_id=a.finding_id, status="assigned", owner=a.owner, ticket_url="")))
    p = sub.add_parser("accept"); p.add_argument("--finding-id", required=True); p.add_argument("--reason", required=True); p.add_argument("--owner", default=""); p.add_argument("--expires-at", required=True); p.add_argument("--conditions", default="reopen if exploitability or fixed version changes"); p.set_defaults(func=lambda a: accept_or_suppress(a, "risk_accepted"))
    p = sub.add_parser("suppress"); p.add_argument("--finding-id", required=True); p.add_argument("--reason", required=True); p.add_argument("--owner", default=""); p.add_argument("--expires-at", default=""); p.add_argument("--conditions", default="review before permanent suppression"); p.set_defaults(func=lambda a: accept_or_suppress(a, "suppressed"))
    p = sub.add_parser("verify"); p.add_argument("--project", default="default-project"); p.add_argument("--sbom", default=""); p.set_defaults(func=verify)
    p = sub.add_parser("remediation-plan"); p.add_argument("--project", default=""); p.add_argument("--finding-id", default=""); p.add_argument("--fixed-version", default=""); p.add_argument("--include-closed", action="store_true"); p.set_defaults(func=generate_remediation)
    p = sub.add_parser("ticket"); p.add_argument("--finding-id", required=True); p.add_argument("--fixed-version", default=""); p.set_defaults(func=ticket_text)
    p = sub.add_parser("sla"); p.add_argument("--project", default=""); p.set_defaults(func=sla_report)
    p = sub.add_parser("dashboard"); p.add_argument("--project", default=""); p.set_defaults(func=dashboard)
    p = sub.add_parser("next-actions"); p.add_argument("--project", default=""); p.add_argument("--limit", type=int, default=10); p.set_defaults(func=next_actions)
    p = sub.add_parser("campaign-create"); p.add_argument("--name", required=True); p.add_argument("--project", default=""); p.add_argument("--owner", default=""); p.add_argument("--description", default=""); p.add_argument("--finding-ids", default=""); p.set_defaults(func=create_campaign)
    p = sub.add_parser("campaigns"); p.set_defaults(func=campaigns)
    p = sub.add_parser("export"); p.add_argument("--project", default=""); p.add_argument("--status", default=""); p.add_argument("--out-dir", default="reports/findings"); p.set_defaults(func=export_report)
    p = sub.add_parser("smoke"); p.add_argument("--sbom", default="test-sboms/example-spdx-2.3.json"); p.add_argument("--project", default="findings-smoke"); p.set_defaults(func=smoke)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
