from __future__ import annotations

import argparse
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_version_metadata_is_consistent(self):
        import sbomops
        from sbomops.__version__ import __version__

        self.assertEqual(__version__, "2.14.2")
        self.assertIn('version = "2.14.2"', (ROOT / "pyproject.toml").read_text())
        self.assertIn("Current release: **v2.14.2", (ROOT / "README.md").read_text())
        self.assertIn("PYTHON ?= python3", (ROOT / "Makefile").read_text())

    def test_current_capability_modules_are_importable(self):
        from sbomops import assurance, connectors, evidence_bundle, org_model, provenance, risk_exceptions
        from sbomops.workbench import server, ux

        self.assertTrue(callable(assurance.evaluate))
        self.assertTrue(callable(connectors.parser))
        self.assertTrue(callable(evidence_bundle.main))
        self.assertTrue(callable(org_model.validate))
        self.assertTrue(callable(provenance.main))
        self.assertTrue(callable(risk_exceptions.main))
        self.assertEqual(len(ux.SCAN_PROFILES), 6)
        self.assertEqual(len(ux.TASKS), 7)
        self.assertTrue(hasattr(server.Handler, "welcome_page"))
        self.assertTrue(hasattr(server.Handler, "workflows_run"))


class ReleaseAssuranceTests(unittest.TestCase):
    def test_vex_excludes_critical_finding(self):
        from sbomops.assurance import evaluate

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.yml"
            findings = root / "findings.json"
            vex = root / "vex.json"
            context = root / "context.yml"
            provenance = root / "provenance.json"
            exceptions = root / "exceptions.yml"
            policy.write_text("release_assurance:\n  block_severity: critical\n  approval_severity: high\n  warn_severity: medium\n  require_vex: true\n  require_context: true\n  require_provenance: true\n")
            findings.write_text(json.dumps({"findings": [
                {"id": "CVE-DEMO-1", "severity": "critical", "component": "parser"},
                {"id": "CVE-DEMO-2", "severity": "medium", "component": "helper"},
            ]}))
            vex.write_text(json.dumps({"statements": [{"vulnerability": "CVE-DEMO-1", "status": "not_affected"}]}))
            context.write_text("project: demo\n")
            provenance.write_text(json.dumps({"status": "PASS"}))
            exceptions.write_text("version: 1\nexceptions: []\n")
            args = argparse.Namespace(
                policy=str(policy), findings=str(findings), vex=str(vex), exceptions=str(exceptions),
                provenance=str(provenance), context=str(context), out_dir=str(root / "out"), fail_on="never",
            )
            result = evaluate(args)
            self.assertEqual(result["decision"], "PASS_WITH_WARNINGS")
            self.assertEqual(result["summary"]["excluded_findings"], 1)
            self.assertEqual(result["summary"]["applicable_findings"], 1)
            self.assertTrue((root / "out" / "release-decision.json").exists())


class ConnectorAndUxTests(unittest.TestCase):
    def test_connector_configuration_stores_secret_reference_only(self):
        from sbomops.connectors import configure

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "connectors.yml"
            args = argparse.Namespace(
                config=str(cfg), name="snyk-test", type="snyk", base_url="https://api.snyk.io",
                token_env="SNYK_TOKEN", project="demo", mode="read-only", disabled=False,
            )
            result = configure(args)
            text = cfg.read_text()
            self.assertIn("SNYK_TOKEN", text)
            self.assertNotIn("github_" + "pat_", text)
            self.assertEqual(result["connector"]["token_env"], "<redacted>")

    def test_support_bundle_redacts_secret_fields(self):
        from sbomops.workbench import ux

        marker = ux.UX_DIR / "reconciled-test-secret.json"
        marker.write_text(json.dumps({"api_key": "do-not-include", "nested": {"token": "also-secret", "safe": "ok"}}))
        try:
            with tempfile.TemporaryDirectory() as td:
                bundle = ux.support_bundle(Path(td) / "support.zip")
                with zipfile.ZipFile(bundle) as archive:
                    data = json.loads(archive.read("reconciled-test-secret.json"))
                self.assertEqual(data["api_key"], "<redacted>")
                self.assertEqual(data["nested"]["token"], "<redacted>")
                self.assertEqual(data["nested"]["safe"], "ok")
        finally:
            marker.unlink(missing_ok=True)


class GuidedWorkflowTests(unittest.TestCase):
    def test_outcome_tasks_map_to_executable_workflows(self):
        from sbomops.wizard_runtime import task_to_workflow

        expected = {
            "analyze-sbom": "analyze",
            "analyze-repository": "repo-analyze",
            "release-review": "release-review",
            "supplier-review": "supplier-intake",
            "dependency-review": "dependency-health",
            "fuzz-test": "fuzz-all-timed",
            "compare-evidence": "scanner-compare",
        }
        for task, workflow in expected.items():
            self.assertEqual(task_to_workflow(task), workflow)

    def test_release_review_is_a_real_job_runner_workflow(self):
        from sbomops.workbench.job_runner import WORKFLOWS

        self.assertIn("release-review", WORKFLOWS)
        source = (ROOT / "sbomops" / "workbench" / "job_runner.py").read_text()
        self.assertIn('if workflow == "release-review"', source)
        self.assertIn('"Deterministic release assurance"', source)


if __name__ == "__main__":
    unittest.main()
