from __future__ import annotations
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

class CloudModeTests(unittest.TestCase):
    def test_cloud_config_generation(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "cloud-config.json"
            subprocess.check_call([sys.executable, "-m", "sbomops.cloud", "init-config", "--output", str(out)])
            data = json.loads(out.read_text())
            self.assertEqual(data["mode"], "server")
            self.assertIn("safety", data)
            self.assertFalse(data["safety"]["execute_project_code"])
            self.assertFalse(data["safety"]["log_secrets"])

    def test_cloud_doctor_runs(self):
        output = subprocess.check_output([sys.executable, "-m", "sbomops.cloud", "doctor"], text=True)
        data = json.loads(output)
        self.assertIn("tools", data)
        self.assertIn("safety_defaults", data)

    def test_cloud_docs_and_compose_present(self):
        self.assertTrue(Path("docs/cloud/CLOUD-MODE.md").exists())
        self.assertTrue(Path("docker/docker-compose.cloud.yml").exists())
        self.assertTrue(Path("cloud/.env.example").exists())

if __name__ == "__main__":
    unittest.main()
