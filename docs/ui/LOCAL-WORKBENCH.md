# Local SBOM Workbench UI

The Local SBOM Workbench is a single-user, localhost-only web interface for running SBOM Security Toolkit workflows without sending SBOMs to a cloud service.

## Start the UI

```bash
make ui-server
```

Open:

```text
http://127.0.0.1:8080
```

## What it supports

- Upload CycloneDX/SPDX SBOM files (`.json`, `.xml`, `.spdx`, `.txt`)
- Run SBOM quality scoring
- Run CISA/NTIA-style minimum-elements checks
- Run policy checks
- Run supplier intake and supplier-question generation
- Generate report bundles
- Run redaction
- Run scanner comparison when optional scanners are installed
- Generate release-evidence bundles
- View job status and logs
- Download a zip evidence bundle
- Delete local job output
- Check optional scanner/tool availability

## Safety model

The UI is intentionally local-first:

- Binds to `127.0.0.1` by default
- No authentication
- No database
- No cloud uploads
- Files are stored under `ui/storage/`
- Per-job directories isolate input, logs, and results
- Upload size and extension checks are enforced
- Network-enabled behavior is opt-in at the workflow level

Do not expose this UI directly to the internet. It is meant for local lab/workbench use.

## Storage layout

```text
ui/storage/
  uploads/
  jobs/
    <job-id>/
      input/
      results/
      logs.txt
      status.json
      evidence-bundle.zip
```

Clean local UI data:

```bash
make ui-clean
```

## Recommended workflow

1. Start `make ui-server`.
2. Upload an SBOM.
3. Choose **Full SBOM analysis**.
4. Review job status and logs.
5. Download the evidence bundle.
6. Delete the job when done.
