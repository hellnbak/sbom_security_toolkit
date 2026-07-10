from pathlib import Path
import json
import tempfile
import unittest
from sbomops.normalize import normalized_doc
from sbomops.common import parse_components

class V17Tests(unittest.TestCase):
    def test_normalize_minimal_cyclonedx(self):
        doc = normalized_doc('test-sboms/clean/minimal-cyclonedx.json')
        self.assertIn('components', doc)
        self.assertIn('stats', doc)

    def test_schema_generator_outputs_valid_json(self):
        import subprocess, sys
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_call([sys.executable, 'fuzzing/schema/cyclonedx_schema_generator.py', '--out', d, '--count', '1'])
            files=list(Path(d).glob('*.json'))
            self.assertEqual(len(files), 1)
            data=json.loads(files[0].read_text())
            self.assertEqual(data['bomFormat'], 'CycloneDX')

if __name__ == '__main__':
    unittest.main()
