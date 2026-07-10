from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from ai_fuzz.tools.providers import provider_defaults, complete

ROOT = Path(__file__).resolve().parents[1]


class GLMProviderTests(unittest.TestCase):
    def test_glm_alias_defaults(self):
        provider, model = provider_defaults("glm", None)
        self.assertEqual(provider, "glm")
        self.assertEqual(model, "glm-5.2")

    def test_glm_model_override(self):
        provider, model = provider_defaults("glm", "custom-glm")
        self.assertEqual(provider, "glm")
        self.assertEqual(model, "custom-glm")

    def test_prompt_only_still_default(self):
        result = complete("Return OK", provider="none")
        self.assertEqual(result.provider, "none")
        self.assertFalse(result.used_network)

    def test_glm_docs_and_configs_exist(self):
        self.assertTrue((ROOT / "docs/integrations/GLM-LOCAL-MODELS.md").exists())
        self.assertTrue((ROOT / "ai_fuzz/config/glm-5.2-local.yml").exists())
        self.assertTrue((ROOT / "ai_fuzz/config/glm-ollama.yml").exists())

    def test_provider_test_prompt_mode(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "provider-test.json")
            result = subprocess.run(
                [sys.executable, "-m", "ai_fuzz.tools.provider_test", "--provider", "none", "--out", out],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("provider=none", result.stdout)
            self.assertTrue(Path(out).exists())


if __name__ == "__main__":
    unittest.main()
