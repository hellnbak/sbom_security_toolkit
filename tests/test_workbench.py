import unittest

from sbomops.workbench.job_runner import safe_name, WORKFLOWS, FUZZ_WORKFLOWS, scanner_status


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


class WorkbenchFuzzingLabTests(unittest.TestCase):
    def test_fuzz_workflows_exposed(self):
        expected = [
            'fuzz-roundtrip',
            'fuzz-metamorphic',
            'fuzz-oracles',
            'fuzz-toolchain',
            'fuzz-generate-cyclonedx',
            'fuzz-all-local',
            'ai-fuzz-eval',
        ]
        for workflow in expected:
            self.assertIn(workflow, FUZZ_WORKFLOWS)

    def test_ai_mutation_plan_is_fuzz_lab_workflow(self):
        self.assertIn('ai-mutation-plan', FUZZ_WORKFLOWS)


if __name__ == '__main__':
    unittest.main()
