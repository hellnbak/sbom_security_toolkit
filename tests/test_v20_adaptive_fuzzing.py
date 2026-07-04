import json, subprocess, sys, unittest
from pathlib import Path

class V20AdaptiveFuzzingTests(unittest.TestCase):
    def test_expected_files_exist(self):
        for p in [
            'fuzzing/kb/schema.sql',
            'fuzzing/kb/fuzz_kb.py',
            'fuzzing/planner/fuzz_plan.py',
            'fuzzing/benchmarks/run_benchmark.py',
            'fuzzing/compatibility/scanner_compatibility.py',
            'fuzzing/truthset/scanner_truthset.py',
            'fuzzing/replay/create_replay_pack.py',
            '.fuzz/build.sh',
            '.github/workflows/clusterfuzzlite-pr.yml',
        ]:
            self.assertTrue(Path(p).exists(), p)
    def test_truthset_manifest(self):
        data=json.loads(Path('test-sboms/truthset/manifest.json').read_text())
        self.assertGreaterEqual(len(data['cases']), 3)
    def test_kb_init_and_summary(self):
        db=Path('reports/test/fuzz-kb.sqlite')
        out=Path('reports/test/fuzz-kb-summary.json')
        subprocess.check_call([sys.executable,'fuzzing/kb/fuzz_kb.py','--db',str(db),'init'])
        subprocess.check_call([sys.executable,'fuzzing/kb/fuzz_kb.py','--db',str(db),'summary','--out',str(out)])
        self.assertTrue(out.exists())
    def test_no_research_report_generator(self):
        self.assertFalse(Path('fuzzing/research').exists())

if __name__ == '__main__':
    unittest.main()
