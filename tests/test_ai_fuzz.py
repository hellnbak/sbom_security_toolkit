from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ai_fuzz.tools.validators import redact_text, validate_seed
from ai_fuzz.tools.ai_fuzz import seed_doc


class AIFuzzTests(unittest.TestCase):
    def test_redact_text_masks_obvious_tokens(self):
        text = 'api_key="secret-value" password=letmein /Users/alice/private/project'
        redacted = redact_text(text)
        self.assertIn('<REDACTED>', redacted)
        self.assertIn('/Users/<user>/<path>', redacted)
        self.assertNotIn('secret-value', redacted)

    def test_seed_doc_cyclonedx_valid_json_shape(self):
        doc = seed_doc('cyclonedx', 'dependency-cycles', 1)
        self.assertEqual(doc['bomFormat'], 'CycloneDX')
        self.assertIn('components', doc)
        self.assertIn('dependencies', doc)

    def test_seed_validation_detects_cyclonedx(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'seed.json'
            p.write_text(json.dumps(seed_doc('cyclonedx', 'license-edge-cases', 1)))
            result = validate_seed(p)
            self.assertTrue(result['valid_json'])
            self.assertEqual(result['format'], 'CycloneDX')
            self.assertEqual(result['errors'], [])


if __name__ == '__main__':
    unittest.main()
