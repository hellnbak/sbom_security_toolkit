# Demo Guide

Run the full local demo:

```bash
make setup
source .venv/bin/activate
make demo-full
make ui-server
```

Open <http://127.0.0.1:8080> and upload one of the files in `test-sboms/demo/`.

Recommended demo flow:

1. Upload `good-sbom.json` and run full analysis.
2. Upload `supplier-sbom-needs-followup.json` and generate supplier questions.
3. Run `make fuzz-all-local` to show fuzzing status and semantic checks.
4. Download the evidence bundle from the workbench or inspect `reports/demo/`.
