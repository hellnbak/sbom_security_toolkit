#!/usr/bin/env python3
"""Deterministic release assurance with VEX, exceptions, provenance, and context."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .release_common import load_data, now, write_json

DECISIONS = {"PASS": 0, "PASS_WITH_WARNINGS": 2, "APPROVAL_REQUIRED": 3, "BLOCK": 4, "INCOMPLETE_EVIDENCE": 5, "ERROR": 10}
SEVERITY = {"unknown": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}


def normalize_findings(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "matches", "items"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = []
    out = []
    for raw in data or []:
        if not isinstance(raw, dict):
            continue
        vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else {}
        art = raw.get("artifact") if isinstance(raw.get("artifact"), dict) else {}
        sev = str(raw.get("severity") or vuln.get("severity") or "unknown").lower()
        try:
            cvss = float(raw.get("cvss") or vuln.get("cvss") or vuln.get("cvssScore") or 0)
        except Exception:
            cvss = 0.0
        try:
            epss = float(raw.get("epss") or vuln.get("epss") or 0)
        except Exception:
            epss = 0.0
        out.append({
            "id": raw.get("id") or raw.get("vulnerability_id") or vuln.get("id") or raw.get("cve") or "UNKNOWN",
            "component": raw.get("component") or raw.get("package") or raw.get("component_name") or art.get("name") or "",
            "version": raw.get("version") or art.get("version") or "",
            "purl": raw.get("purl") or art.get("purl") or "",
            "severity": sev,
            "cvss": cvss,
            "epss": epss,
            "kev": bool(raw.get("kev") or raw.get("cisa_kev") or raw.get("known_exploited") or vuln.get("kev")),
            "fix_available": bool(raw.get("fix_available") or raw.get("fixAvailable") or vuln.get("fix_available")),
            "age_days": int(raw.get("age_days") or raw.get("vulnerability_age_days") or 0),
            "direct": bool(raw.get("direct", False)),
            "reachable": raw.get("reachable"),
            "environment": raw.get("environment") or "",
            "raw": raw,
        })
    return out


def vex_index(data: Any) -> dict[tuple[str, str], dict]:
    items = []
    if isinstance(data, dict):
        items = data.get("statements") or data.get("vulnerabilities") or data.get("status") or []
    elif isinstance(data, list):
        items = data
    out = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        vid = item.get("vulnerability") or item.get("id") or item.get("vulnerability_id")
        if isinstance(vid, dict):
            vid = vid.get("id")
        product = item.get("product") or item.get("component") or item.get("purl") or "*"
        products = product if isinstance(product, list) else [product]
        for value in products:
            out[(str(vid), str(value))] = item
    return out


def exception_index(data: Any) -> list[dict]:
    if isinstance(data, dict):
        return data.get("exceptions") or data.get("items") or []
    return data or []


def active_exception(finding: dict, exceptions: list[dict], rule_id: str, at: datetime) -> dict | None:
    for item in exceptions:
        spec = item.get("spec", item)
        expires = spec.get("expires") or spec.get("expires_at")
        if expires:
            try:
                if datetime.fromisoformat(str(expires).replace("Z", "+00:00")) <= at:
                    continue
            except Exception:
                continue
        if str(spec.get("status", "approved")).lower() not in {"approved", "active"}:
            continue
        if spec.get("rule") and spec.get("rule") != rule_id:
            continue
        if spec.get("vulnerability") and spec.get("vulnerability") != finding.get("id"):
            continue
        if spec.get("component") and spec.get("component") != finding.get("component"):
            continue
        if spec.get("purl") and spec.get("purl") != finding.get("purl"):
            continue
        if any(spec.get(k) for k in ("rule", "vulnerability", "component", "purl", "project")):
            return item
    return None


def matches(rule: dict, finding: dict, context: dict) -> bool:
    if rule.get("severity") and SEVERITY.get(finding["severity"], 0) < SEVERITY.get(str(rule["severity"]).lower(), 0):
        return False
    if "fixAvailable" in rule and bool(rule["fixAvailable"]) != finding["fix_available"]:
        return False
    if "kev" in rule and bool(rule["kev"]) != finding["kev"]:
        return False
    if rule.get("epss", {}).get("greaterThan") is not None and finding["epss"] <= float(rule["epss"]["greaterThan"]):
        return False
    if rule.get("cvss", {}).get("greaterThan") is not None and finding["cvss"] <= float(rule["cvss"]["greaterThan"]):
        return False
    if rule.get("ageDays", {}).get("greaterThan") is not None and finding["age_days"] <= int(rule["ageDays"]["greaterThan"]):
        return False
    if "direct" in rule and bool(rule["direct"]) != finding["direct"]:
        return False
    if "reachable" in rule and rule["reachable"] != finding["reachable"]:
        return False
    environment = rule.get("environment")
    return not environment or environment in {finding.get("environment"), context.get("environment")}


def _legacy_policy(policy: dict) -> dict:
    """Convert the compact v2.14 policy format to the v2.9 policy contract."""
    if "spec" in policy or "metadata" in policy:
        return policy
    rules = policy.get("release_assurance") or policy.get("assurance") or policy
    spec: dict[str, Any] = {"deny": [], "requireApproval": [], "warn": [], "requireEvidence": {}}
    if rules.get("block_severity"):
        spec["deny"].append({"id": "severity-block", "severity": rules["block_severity"]})
    if rules.get("block_kev", True):
        spec["deny"].append({"id": "known-exploited", "kev": True})
    if rules.get("approval_severity"):
        spec["requireApproval"].append({"id": "severity-approval", "severity": rules["approval_severity"]})
    if rules.get("warn_severity"):
        spec["warn"].append({"id": "severity-warning", "severity": rules["warn_severity"]})
    spec["requireEvidence"] = {
        "provenance": bool(rules.get("require_provenance")),
        "vex": bool(rules.get("require_vex")),
        "context": bool(rules.get("require_context")),
    }
    return {"metadata": {"name": "legacy-release-assurance"}, "spec": spec}


def _evaluate_core(policy: dict, findings: list[dict], vex: dict, exceptions: list[dict], provenance: dict, context: dict, vex_supplied: bool = True) -> dict:
    policy = _legacy_policy(policy or {})
    spec = policy.get("spec", policy)
    violations: list[dict] = []
    approvals: list[dict] = []
    warnings: list[dict] = []
    excluded = 0
    at = datetime.now(timezone.utc)
    required = spec.get("requireEvidence", {})
    missing = []
    if required.get("provenance") and not provenance:
        missing.append("provenance")
    if required.get("signedArtifact") and not provenance.get("artifact_signature_verified"):
        missing.append("verified artifact signature")
    if required.get("signedSbom") and not provenance.get("sbom_signature_verified"):
        missing.append("verified SBOM signature")
    if required.get("builderIdentity") and not provenance.get("builder_identity"):
        missing.append("builder identity")
    if required.get("vex") and not vex_supplied:
        missing.append("vex")
    if required.get("context") and not context:
        missing.append("organizational context")
    for finding in findings:
        vx = vex.get((finding["id"], finding.get("purl") or "*")) or vex.get((finding["id"], "*"))
        state = str((vx or {}).get("status") or (vx or {}).get("analysis", {}).get("state") or "").lower()
        if state in {"not_affected", "not affected", "false_positive", "resolved", "fixed"}:
            excluded += 1
            continue
        for bucket, target in (("deny", violations), ("requireApproval", approvals), ("warn", warnings)):
            for index, rule in enumerate(spec.get(bucket, []) or []):
                if not isinstance(rule, dict) or not matches(rule, finding, context):
                    continue
                rule_id = rule.get("id") or f"{bucket}-{index + 1}"
                exception = active_exception(finding, exceptions, rule_id, at)
                item = {"rule": rule_id, "finding": {k: v for k, v in finding.items() if k != "raw"}, "message": rule.get("message") or f"{finding['id']} matched {rule_id}"}
                if exception:
                    item["exception"] = exception.get("metadata", {}).get("id") or exception.get("id")
                    warnings.append(item)
                else:
                    target.append(item)
                break
    if missing:
        decision = "INCOMPLETE_EVIDENCE"
    elif violations:
        decision = "BLOCK"
    elif approvals:
        decision = "APPROVAL_REQUIRED"
    elif warnings:
        decision = "PASS_WITH_WARNINGS"
    else:
        decision = "PASS"
    return {
        "schema_version": "1.0",
        "decision": decision,
        "exit_code": DECISIONS[decision],
        "policy": policy.get("metadata", {}).get("name") or policy.get("name") or "unnamed-policy",
        "evaluated_at": now(),
        "context": context,
        "summary": {
            "findings": len(findings),
            "input_findings": len(findings),
            "applicable_findings": len(findings) - excluded,
            "excluded_findings": excluded,
            "violations": len(violations),
            "approvals": len(approvals),
            "warnings": len(warnings),
            "missing_evidence": missing,
        },
        "violations": violations,
        "approvals_required": approvals,
        "warnings": warnings,
        "provenance": provenance,
    }


def evaluate(policy_or_args, findings=None, vex=None, exceptions=None, provenance=None, context=None) -> dict:
    """Evaluate either the library contract or an argparse Namespace contract."""
    if isinstance(policy_or_args, argparse.Namespace):
        args = policy_or_args
        result = _evaluate_core(
            load_data(args.policy, {}),
            normalize_findings(load_data(args.findings, [])),
            vex_index(load_data(getattr(args, "vex", None), {})),
            exception_index(load_data(getattr(args, "exceptions", None), [])),
            load_data(getattr(args, "provenance", None), {}) or {},
            load_data(getattr(args, "context", None), {}) or {},
            vex_supplied=bool(getattr(args, "vex", None)),
        )
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        write_json(out / "release-decision.json", result)
        write_json(out / "policy-decision.json", result)
        (out / "release-decision.md").write_text(render(result) + "\n", encoding="utf-8")
        (out / "policy-decision.md").write_text(render(result) + "\n", encoding="utf-8")
        return result
    return _evaluate_core(policy_or_args or {}, findings or [], vex or {}, exceptions or [], provenance or {}, context or {})


def render(result: dict) -> str:
    lines = ["# Release Assurance Decision", "", f"**Decision:** {result['decision']}", f"**Policy:** {result['policy']}", f"**Evaluated:** {result['evaluated_at']}", ""]
    if result["summary"]["missing_evidence"]:
        lines += ["## Missing evidence", ""] + [f"- {x}" for x in result["summary"]["missing_evidence"]] + [""]
    for title, key in (("Blocking violations", "violations"), ("Approvals required", "approvals_required"), ("Warnings", "warnings")):
        lines += [f"## {title}", ""]
        lines += [f"- **{x['rule']}** — {x['message']}" + (f" (exception: {x['exception']})" if x.get("exception") else "") for x in result[key]] or ["- None"]
        lines.append("")
    return "\n".join(lines)


def should_fail(decision: str, threshold: str) -> bool:
    sets = {
        "block": {"BLOCK", "INCOMPLETE_EVIDENCE", "ERROR"},
        "approval": {"BLOCK", "INCOMPLETE_EVIDENCE", "ERROR", "APPROVAL_REQUIRED"},
        "warning": set(DECISIONS) - {"PASS"},
        "never": set(),
    }
    return decision in sets.get(threshold, sets["block"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate release assurance policy over vulnerability and supply-chain evidence")
    ap.add_argument("--policy", required=True); ap.add_argument("--findings", required=True); ap.add_argument("--vex"); ap.add_argument("--exceptions"); ap.add_argument("--provenance"); ap.add_argument("--context")
    ap.add_argument("--out-dir", default="reports/release-assurance"); ap.add_argument("--fail-on", choices=["block", "approval", "warning", "never"], default="block")
    args = ap.parse_args(argv)
    try:
        result = evaluate(args)
    except Exception as exc:
        print(f"assurance error: {exc}", file=sys.stderr)
        return 10
    print(json.dumps(result, indent=2))
    return result["exit_code"] if should_fail(result["decision"], args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
