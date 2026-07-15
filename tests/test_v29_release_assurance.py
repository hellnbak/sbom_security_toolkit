from datetime import datetime, timedelta, timezone
from sbomops.assurance import evaluate, normalize_findings, vex_index

POLICY = {"metadata": {"name": "test"}, "spec": {"deny": [{"id": "kev", "kev": True}, {"id": "critical", "severity": "critical", "fixAvailable": True}], "requireApproval": [{"id": "aged-high", "severity": "high", "ageDays": {"greaterThan": 30}}], "warn": [{"id": "medium", "severity": "medium"}]}}


def test_blocks_kev():
    result = evaluate(POLICY, normalize_findings([{"id": "CVE-1", "severity": "high", "kev": True}]), {}, [], {}, {})
    assert result["decision"] == "BLOCK" and result["exit_code"] == 4


def test_vex_not_affected_suppresses():
    vx = vex_index({"statements": [{"vulnerability": "CVE-1", "product": "pkg:pypi/a@1", "status": "not_affected"}]})
    result = evaluate(POLICY, normalize_findings([{"id": "CVE-1", "purl": "pkg:pypi/a@1", "severity": "critical", "fix_available": True}]), vx, [], {}, {})
    assert result["decision"] == "PASS"


def test_approved_active_exception_warns_instead_of_blocks():
    expires = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    exceptions = [{"metadata": {"id": "RISK-1"}, "spec": {"status": "approved", "rule": "kev", "vulnerability": "CVE-1", "expires": expires}}]
    result = evaluate(POLICY, normalize_findings([{"id": "CVE-1", "severity": "high", "kev": True}]), {}, exceptions, {}, {})
    assert result["decision"] == "PASS_WITH_WARNINGS"
    assert result["warnings"][0]["exception"] == "RISK-1"


def test_required_provenance_is_incomplete():
    policy = {"metadata": {"name": "signed"}, "spec": {"requireEvidence": {"provenance": True, "builderIdentity": True}}}
    result = evaluate(policy, [], {}, [], {}, {})
    assert result["decision"] == "INCOMPLETE_EVIDENCE"
