import json
import tempfile
import unittest
from pathlib import Path

from sbomops.workbench.job_runner import safe_name, WORKFLOWS, scanner_status

class WorkbenchTests(unittest.TestCase):
    def test_safe_name_strips_paths_and_unsafe_chars(self):
        self.assertEqual(safe_name('../../bad name.json'), 'bad_name.json')
        self.assertTrue(safe_name('x' * 300 + '.json').endswith('.json') or len(safe_name('x' * 300 + '.json')) <= 180)

    def test_workflows_include_expected_actions(self):
        for name in ['analyze', 'score', 'minimum-elements', 'policy', 'supplier-intake', 'supplier-questions', 'report', 'redact']:
            self.assertIn(name, WORKFLOWS)

    def test_scanner_status_shape(self):
        rows = scanner_status()
        self.assertTrue(rows)
        self.assertIn('tool', rows[0])
        self.assertIn('available', rows[0])

if __name__ == '__main__':
    unittest.main()
