# v2.14.2 Validation Record

Validation date: **2026-07-15**

## Installation and packaging

Validated:

```bash
python3 setup.py --name --version
```

Result:

```text
sbom-security-toolkit
2.14.2
```

The release includes both `pyproject.toml` and a compatibility `setup.py`. The latter addresses editable installation on macOS environments starting with pip 21.2.x. The recommended installation still upgrades pip, setuptools, and wheel inside the virtual environment before installing `.[dev]`.

## Source and fast validation

```bash
make test-fast
```

Results:

- Python compilation passed.
- CLI version returned `2.14.2`.
- Shell syntax validation passed.
- Repository JSON validation passed, excluding intentionally malformed/corpus fixtures.
- Product doctor completed and wrote its local report.

## Complete regression suite

```bash
make reconciled-test
```

Result: **91 tests passed**.

Coverage included:

- core SBOM parsing, quality, and supplier operations;
- repository intake and internal SBOM generation;
- cloud/provider scaffolding;
- adaptive and operational fuzzing helpers;
- the v2.9 release-assurance and VEX contracts;
- the v2.10 connector registry, write guards, and TLS safety controls;
- the v2.11 Workbench navigation and GUI capability coverage;
- the v2.12 guided experience;
- v2.14 automatic reporting, wizard execution, and demo contracts;
- v2.14.2 installation compatibility, restored repository files, safe updater behavior, runtime ignore rules, YAML dependency errors, and preflight behavior.

## Offline integrations

```bash
make test-integration-offline
```

Results:

- Integration smoke: 6 checks, all passed.
- Evidence-bound AI report smoke passed in prompt-only mode.
- Offline lifecycle intelligence passed.
- Reports index generation passed.

## Live demo and reporting

```bash
make demo-live
```

The synthetic demo completed through the normal job runner with **nine steps**. Verified artifacts included:

- explicitly synthetic CycloneDX input;
- execution contract, job status, and logs;
- SBOM quality, minimum-elements, policy, supplier, report, and UI outputs;
- demo manifest and run summary;
- automatic Full Security Engineering Report in Markdown and HTML;
- report fact bundle and generation metadata;
- downloadable evidence archive.

An executive variant was generated from the same completed run:

```bash
make report-variant \
  JOB_DIR=ui/storage/jobs/<job-id> \
  REPORT_VARIANT=executive
```

The refreshed evidence archive contained both the default engineering report and the executive report artifacts.

## Preflight before and after demo execution

```bash
make preflight-release
make demo-live
make preflight-release
```

Both preflight runs passed. The second run confirms that untracked local demo output no longer creates a false release failure. The preflight still rejects runtime evidence when it is tracked by Git or listed in the release manifest.

## Non-destructive updater

`scripts/apply-release-safe.sh` was executed against a temporary Git checkout containing a destination-only tracked file. Validation confirmed that:

- the destination-only file remained present;
- v2.14.2 files were copied successfully;
- repository capability files were restored;
- version metadata became `2.14.2`;
- the updater recorded a pre-application Git status file and binary patch;
- no destination mirror or delete operation was used.

## Security and packaging hygiene

Validated through release preflight:

- Python caches were removed;
- generated runtime files were not tracked or packaged;
- no files exceeded the 20 MB source-package limit;
- common live-secret patterns were not detected in source content;
- company-specific internal terms were not detected;
- connector examples use environment-variable references rather than secret values.

## Not validated live

The following require external infrastructure, credentials, or services and were not exercised as live operations:

- Jira and DefectDojo writes;
- live Snyk, Dependency-Track, GitHub, or webhook connector calls;
- Bedrock, Ollama, GLM, or OpenAI-compatible narrative generation;
- cosign signing or verification with a real key;
- Kubernetes/Helm deployment;
- Postgres/Redis/object-storage cloud mode;
- Docker-based language fuzzing engines.

These remain explicit opt-in paths. Their offline configuration, dry-run, or payload-generation paths are covered where available.
