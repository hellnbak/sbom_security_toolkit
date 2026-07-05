import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sbomops.repo_intake import detect_ecosystems, internal_cyclonedx, compare_generated_sboms
from sbomops.workbench.job_runner import WORKFLOWS, REPO_WORKFLOWS, safe_name, ALLOWED_SUFFIXES

ROOT = Path(__file__).resolve().parents[1]
DEMO_REPO = ROOT / 'test-repos' / 'demo-mixed'

class RepoIntakeTests(unittest.TestCase):
    def test_detect_ecosystems(self):
        data = detect_ecosystems(DEMO_REPO)
        self.assertIn('javascript/npm', data['ecosystems'])
        self.assertIn('python', data['ecosystems'])
        self.assertIn('go', data['ecosystems'])
        self.assertIn('container', data['ecosystems'])

    def test_internal_sbom_generation(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'internal.cdx.json'
            internal_cyclonedx(DEMO_REPO, out)
            bom = json.loads(out.read_text())
            self.assertEqual(bom['bomFormat'], 'CycloneDX')
            self.assertGreaterEqual(len(bom.get('components', [])), 3)

    def test_generator_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            internal_cyclonedx(DEMO_REPO, d / 'internal.cdx.json')
            report = compare_generated_sboms(d, d / 'comparison.json')
            self.assertIn('internal.cdx.json', report['files'])

    def test_cli_analyze_static(self):
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run([sys.executable, '-m', 'sbomops.repo_intake', 'analyze', str(DEMO_REPO), '--out-dir', td, '--generators', 'internal', '--no-scan'], cwd=ROOT, text=True, capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((Path(td) / 'generated-sboms' / 'internal.cdx.json').exists())
            self.assertTrue((Path(td) / 'repo-intake-summary.md').exists())

    def test_workbench_repo_workflows(self):
        for workflow in ['repo-analyze', 'repo-sbom', 'repo-scan', 'repo-fuzz', 'repo-evidence']:
            self.assertIn(workflow, WORKFLOWS)
            self.assertIn(workflow, REPO_WORKFLOWS)
        self.assertIn('.zip', ALLOWED_SUFFIXES)

if __name__ == '__main__':
    unittest.main()
