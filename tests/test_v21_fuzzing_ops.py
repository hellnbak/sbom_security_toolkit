from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

class V21FuzzingOpsTests(unittest.TestCase):
    def run_cmd(self, *args):
        return subprocess.run([sys.executable, *args], cwd=ROOT, text=True, capture_output=True, timeout=60)

    def test_intelligence_runs(self):
        proc = self.run_cmd('fuzzing/intelligence/intelligence_score.py', '--inputs', 'test-sboms/clean', '--out-dir', 'reports/test-intelligence')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((ROOT / 'reports/test-intelligence/intelligence.json').exists())

    def test_vex_logic_generation(self):
        proc = self.run_cmd('fuzzing/vex_logic/vex_logic_fuzz.py', '--out-dir', 'reports/test-vex-logic')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((ROOT / 'reports/test-vex-logic/manifest.json').exists())

    def test_harness_audit_runs(self):
        proc = self.run_cmd('fuzzing/harness/audit.py', 'fuzzing/engines/python/targets/cyclonedx_json_atheris.py', '--out', 'reports/test-harness-audit.json')
        self.assertIn(proc.returncode, (0, 1))
        self.assertTrue((ROOT / 'reports/test-harness-audit.json').exists())

if __name__ == '__main__':
    unittest.main()
