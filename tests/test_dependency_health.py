import json
import subprocess
import sys
from pathlib import Path


def test_dependency_health_detects_stale_metadata(tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{
            "type": "library",
            "name": "example-lib",
            "version": "1.0.0",
            "purl": "pkg:npm/example-lib@1.0.0",
            "properties": [{"name": "sst:last_release_date", "value": "2020-01-01"}]
        }]
    }))
    out = tmp_path / "out"
    proc = subprocess.run([sys.executable, "-m", "sbomops.dependency_health", str(sbom), "--out-dir", str(out), "--stale-days", "365"], text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    data = json.loads((out / "dependency-health.json").read_text())
    assert data["summary"]["component_count"] == 1
    assert data["components"][0]["risk"] in {"high", "medium"}
    assert (out / "dependency-health.md").exists()


def test_dependency_health_parses_cyclonedx_xml(tmp_path):
    sbom = tmp_path / "bom.xml"
    sbom.write_text("""<?xml version='1.0'?>
<bom xmlns='http://cyclonedx.org/schema/bom/1.5'>
  <components>
    <component type='library'>
      <name>xml-lib</name><version>1.0.0</version><purl>pkg:pypi/xml-lib@1.0.0</purl>
    </component>
  </components>
</bom>""")
    out = tmp_path / "out"
    proc = subprocess.run([sys.executable, "-m", "sbomops.dependency_health", str(sbom), "--out-dir", str(out)], text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    data = json.loads((out / "dependency-health.json").read_text())
    assert data["components"][0]["name"] == "xml-lib"
