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
- Launch Fuzzing Lab workflows from the browser
- Configure fuzzing options such as seed count, edge-case type, budget profile, AI provider/model, including optional AWS Bedrock, and local Dependency-Track URL
- Review recent fuzzing logs on `/fuzzing/logs`

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

## Recommended SBOM workflow

1. Start `make ui-server`.
2. Upload an SBOM.
3. Choose **Full SBOM analysis**.
4. Review job status and logs.
5. Download the evidence bundle.
6. Delete the job when done.

## Fuzzing Lab

Open:

```text
http://127.0.0.1:8080/fuzzing
```

The Fuzzing Lab lets you upload a seed SBOM and run local fuzzing workflows from the browser. Supported categories include:

- structure-preserving SBOM mutation,
- round-trip semantic checks,
- metamorphic SBOM checks,
- semantic oracle checks,
- scanner/toolchain fuzzing,
- stateful Dependency-Track dry-run workflow fuzzing,
- scanner metamorphic testing,
- schema-aware CycloneDX/SPDX/VEX seed generation,
- fuzzing budget profiles,
- coverage and status summaries,
- replay-pack generation,
- AI-assisted corpus review, harness repair prompts, mutation plans, fuzz campaigns, and provider evaluation.

The Fuzzing Lab form supports workflow options such as seed count, time limit per fuzzing step/library, run target groups, edge-case profile, budget profile, local Dependency-Track URL, AI provider/model, including optional AWS Bedrock, AI scenario/goal, and harness target. Use the timed all-fuzzing workflow when you want the workbench to run all available local fuzzing modes with the same per-step time budget. AI-assisted workflows remain advisory and review-gated.

### Fuzzing logs

Open:

```text
http://127.0.0.1:8080/fuzzing/logs
```

This page shows recent fuzzing and AI-fuzzing jobs with their latest logs, newest first. Each job also has a detailed status page with step exit codes, workflow options, generated results, and a downloadable evidence bundle.

## Repository Intake tab

The local workbench includes a Repository Intake tab for starting from source code instead of a pre-built SBOM.

Supported inputs:

- repository `.zip` or `.tar.gz` archive upload
- local path on the machine running the workbench
- HTTPS GitHub URL, including private repositories when a token is provided

Private GitHub token handling:

- tokens pasted into the UI are held only in process memory for the current background job
- tokens are not written to `status.json`, logs, reports, or evidence bundles
- remote Git clone is explicit opt-in
- the clone helper avoids placing tokens in the Git URL or command line

Repository Intake workflows can generate SBOMs, compare SBOM generator output, run locally installed vulnerability scanners, optionally fuzz the generated SBOM, and create a downloadable evidence bundle.


## AI-assisted fuzz cases for Full SBOM Analysis

The upload workflow can optionally enable AI-assisted fuzz case generation for Full SBOM Analysis. Modes are `suggest` and `generate-run`. Provider choices include prompt-only, AWS Bedrock, GLM, Ollama, and OpenAI-compatible endpoints. AI output is advisory; generated cases are validated before execution and are not promoted automatically.
