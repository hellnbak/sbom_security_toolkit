from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class ReportingRuntimeTests(unittest.TestCase):
    def test_default_report_contract_and_options(self):
        from sbomops import reporting_runtime

        with tempfile.TemporaryDirectory() as td:
            job = Path(td)
            (job / "input").mkdir()
            (job / "results").mkdir()
            sbom = job / "input" / "sample.json"
            sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}\n')
            (job / "status.json").write_text(json.dumps({"job_id": "test", "state": "completed", "input_file": str(sbom), "options": {}}))

            def fake_generate(args):
                out = Path(args.out_dir)
                out.mkdir(parents=True, exist_ok=True)
                (out / "full-security-report.md").write_text("# Full Security Report\n\nEvidence-bound.\n")
                (out / "full-security-report.html").write_text("<h1>Full Security Report</h1>")
                return {"provider": {"provider": "none", "ok": True}}

            with mock.patch("sbomops.ai_report_writer.generate", side_effect=fake_generate):
                result = reporting_runtime.generate_default_for_job(job)

            self.assertEqual(result["state"], "generated")
            self.assertTrue((job / "results" / "ai-reports" / "engineering" / "full-security-report.md").exists())
            options = json.loads((job / "results" / "ai-reports" / "report-options.json").read_text())
            self.assertTrue(options["behavior"]["report_provider_failure_does_not_fail_scan"])
            self.assertIn("executive", {item["name"] for item in options["variants"]})
            status = json.loads((job / "status.json").read_text())
            self.assertEqual(status["reporting"]["state"], "generated")

    def test_customer_variant_is_sanitized(self):
        from sbomops import reporting_runtime

        with tempfile.TemporaryDirectory() as td:
            job = Path(td)
            (job / "input").mkdir()
            (job / "results").mkdir()
            sbom = job / "input" / "sample.json"
            sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}\n')
            (job / "status.json").write_text(json.dumps({"job_id": "test", "state": "completed", "input_file": str(sbom), "options": {}}))

            def fake_generate(args):
                out = Path(args.out_dir)
                out.mkdir(parents=True, exist_ok=True)
                (out / "supplier-vendor-risk-report.md").write_text("# Supplier Report\n\n## Evidence used\n\n- `/private/internal/path.json`\n\n## AI limitations\n\nAdvisory.\n")
                return {"provider": {"provider": "none", "ok": True}}

            with mock.patch("sbomops.ai_report_writer.generate", side_effect=fake_generate):
                result = reporting_runtime.generate_variant(job, "customer")

            output = Path(result["markdown"]).read_text()
            self.assertIn("Customer-Facing Security Summary", output)
            self.assertIn("retained internally", output)
            self.assertNotIn("/private/internal/path.json", output)


class WizardRuntimeTests(unittest.TestCase):
    def test_task_mapping(self):
        from sbomops.wizard_runtime import task_to_workflow

        self.assertEqual(task_to_workflow("repository security review"), "repo-analyze")
        self.assertEqual(task_to_workflow("supplier risk"), "supplier-intake")
        self.assertEqual(task_to_workflow("unsupported dependency review"), "dependency-health")
        self.assertEqual(task_to_workflow("run fuzz tests"), "fuzz-all-timed")

    def test_execution_contract_requires_auto_report(self):
        from sbomops.wizard_runtime import write_execution_contract

        with tempfile.TemporaryDirectory() as td:
            target = write_execution_contract(Path(td), {"workflow": "analyze", "workflow_label": "Analysis"})
            payload = json.loads(target.read_text())
            self.assertTrue(payload["automatic_report_required"])
            self.assertTrue(payload["report_failure_is_non_blocking"])
            self.assertIn("SBOM quality", payload["will_execute"])


class DemoRuntimeTests(unittest.TestCase):
    def test_demo_sbom_is_explicitly_synthetic(self):
        from sbomops import demo_runtime

        path = demo_runtime.ensure_demo_sbom()
        payload = json.loads(path.read_text())
        properties = {p["name"]: p["value"] for p in payload["metadata"]["properties"]}
        self.assertEqual(properties["sst:demo"], "true")
        self.assertEqual(properties["sst:data-classification"], "synthetic-only")
        self.assertGreaterEqual(len(payload["components"]), 5)
        self.assertGreaterEqual(len(payload["vulnerabilities"]), 2)


class RuntimeHookTests(unittest.TestCase):
    def test_reporting_failure_does_not_change_scan_state(self):
        from sbomops.workbench.runtime_hooks import install_runtime_hooks

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jobs = root / "ui" / "storage" / "jobs"
            jobs.mkdir(parents=True)
            status_by_id = {}

            def job_dir(job_id):
                return jobs / job_id

            def write_status(job_id, data):
                d = job_dir(job_id)
                d.mkdir(parents=True, exist_ok=True)
                status_by_id[job_id] = json.loads(json.dumps(data, default=str))
                (d / "status.json").write_text(json.dumps(status_by_id[job_id]))

            def read_status(job_id):
                return json.loads(json.dumps(status_by_id[job_id]))

            def original_create(workflow, upload, **kwargs):
                job_id = "job-1"
                d = job_dir(job_id)
                (d / "input").mkdir(parents=True, exist_ok=True)
                (d / "results").mkdir(parents=True, exist_ok=True)
                copied = d / "input" / upload.name
                copied.write_bytes(upload.read_bytes())
                write_status(job_id, {"job_id": job_id, "workflow": workflow, "workflow_label": workflow, "state": "queued", "input_file": str(copied), "options": kwargs.get("options", {}), "steps": []})
                return job_id

            def original_run(job_id):
                status = read_status(job_id)
                status.update({"state": "completed", "exit_code": 0, "steps": [{"name": "real scan", "returncode": 0}]})
                write_status(job_id, status)

            def create_zip(job_id):
                p = job_dir(job_id) / "evidence.zip"
                p.write_bytes(b"zip")
                return p

            namespace = {
                "WORKFLOWS": {"analyze": "Analyze"},
                "create_job": original_create,
                "run_job": original_run,
                "read_status": read_status,
                "write_status": write_status,
                "append_log": lambda *_: None,
                "job_dir": job_dir,
                "create_evidence_zip": create_zip,
                "ROOT": root,
            }
            install_runtime_hooks(namespace)
            source = root / "sample.json"
            source.write_text("{}")
            job_id = namespace["create_job"]("quick-scan", source)

            with mock.patch("sbomops.reporting_runtime.generate_default_for_job", side_effect=RuntimeError("provider unavailable")):
                namespace["run_job"](job_id)

            status = read_status(job_id)
            self.assertEqual(status["state"], "completed")
            report_step = status["steps"][-1]
            self.assertFalse(report_step["blocking"])
            self.assertEqual(report_step["returncode"], 1)
            self.assertTrue(report_step["scan_state_unchanged"])


if __name__ == "__main__":
    unittest.main()
