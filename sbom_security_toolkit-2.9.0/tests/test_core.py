import json
import tempfile
import unittest
from pathlib import Path

from sbomops.common import parse_components, component_stats
from sbomops.score_sbom import score
from sbomops.minimum_elements import evaluate
from sbomops.supplier_questions import build_questions

ROOT = Path(__file__).resolve().parents[1]
SBOM = ROOT / "test-sboms" / "clean" / "minimal-cyclonedx.json"
SUPPLIER = ROOT / "test-sboms" / "supplier-intake" / "incomplete-supplier-sbom.json"

class ToolkitCoreTests(unittest.TestCase):
    def test_parse_components(self):
        fmt, comps, meta = parse_components(SBOM)
        self.assertEqual(fmt, "cyclonedx-json")
        self.assertGreater(len(comps), 0)

    def test_quality_score_bounds(self):
        fmt, comps, meta = parse_components(SBOM)
        value = score(component_stats(comps, meta))
        self.assertGreaterEqual(value, 0)
        self.assertLessEqual(value, 100)

    def test_minimum_elements(self):
        result = evaluate(str(SBOM))
        self.assertIn(result["status"], {"PASS", "PARTIAL", "FAIL"})
        self.assertTrue(result["findings"])

    def test_supplier_questions(self):
        result = build_questions(str(SUPPLIER))
        self.assertTrue(result["questions"])

if __name__ == "__main__":
    unittest.main()
