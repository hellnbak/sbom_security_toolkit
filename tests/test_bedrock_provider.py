from __future__ import annotations
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class BedrockProviderTests(unittest.TestCase):
    def test_bedrock_alias_defaults(self):
        from ai_fuzz.tools.providers import provider_defaults
        provider, model = provider_defaults("bedrock", "example-model")
        self.assertEqual(provider, "bedrock")
        self.assertEqual(model, "example-model")

    def test_bedrock_docs_and_config_exist(self):
        self.assertTrue((ROOT / "ai_fuzz/config/bedrock.yml").exists())
        self.assertTrue((ROOT / "docs/integrations/BEDROCK-AI-PROVIDER.md").exists())
        self.assertTrue((ROOT / "requirements-ai-aws.txt").exists())

    def test_workbench_exposes_bedrock(self):
        text = (ROOT / "sbomops/workbench/server.py").read_text()
        self.assertIn("value='bedrock'", text)
        self.assertIn("AI-assisted fuzz case generation", text)

    def test_ai_fuzz_analysis_cli_module_exists(self):
        text = (ROOT / "sbomops/cli.py").read_text()
        self.assertIn('"ai-fuzz-analysis"', text)

if __name__ == "__main__":
    unittest.main()
