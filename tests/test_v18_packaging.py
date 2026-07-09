from __future__ import annotations
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class V18PackagingTests(unittest.TestCase):
    def test_version_module(self):
        from sbomops.__version__ import __version__
        self.assertEqual(__version__, "2.7.2")

    def test_cli_version(self):
        result = subprocess.run([sys.executable, "-m", "sbomops.cli", "version"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "2.7.2")

    def test_packaging_files_exist(self):
        for rel in ["pyproject.toml", "requirements.txt", "setup.sh", "install.sh", "DATA-SAFETY.md", "docs/INSTALL.md", "docs/DEMO.md", "docs/RELEASE.md"]:
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_demo_sboms_exist(self):
        demo = ROOT / "test-sboms" / "demo"
        self.assertTrue((demo / "good-sbom.json").exists())
        self.assertTrue((demo / "supplier-sbom-needs-followup.json").exists())

    def test_preflight_script_syntax(self):
        result = subprocess.run(["bash", "-n", "scripts/preflight-release.sh"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == "__main__":
    unittest.main()
