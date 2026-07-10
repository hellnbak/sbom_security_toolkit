# Repository Intake and SBOM Build Pipeline

Repository Intake lets SBOM Security Toolkit start from source instead of requiring a pre-built SBOM.

Supported inputs:

- local repository directory
- repository `.zip` or `.tar.gz` archive
- HTTPS GitHub URL, including private repositories when a token is provided

The default pipeline is static-first. It detects manifest and lock files, generates SBOMs with available local tools, compares generator output, runs vulnerability scanners when installed, and can fuzz the generated SBOM. It does **not** run project install scripts, build scripts, tests, or arbitrary project code by default.

## CLI examples

```bash
make repo-intake REPO_SOURCE=./my-app
make repo-sbom REPO_SOURCE=./my-app REPO_GENERATORS=internal,syft
make repo-fuzz REPO_SOURCE=./my-app TIME_BUDGET=60
```

Private GitHub repository example:

```bash
export GITHUB_TOKEN=github_pat_xxx
make repo-intake REPO_SOURCE=https://github.com/org/private-repo.git ALLOW_REMOTE=1 GITHUB_TOKEN_ENV=GITHUB_TOKEN
```

Or with the CLI:

```bash
sst repo analyze https://github.com/org/private-repo.git --allow-remote --github-token-env GITHUB_TOKEN --out-dir reports/private-repo
```

## GitHub token handling

For command-line use, tokens are read from an environment variable. For the local web UI, a pasted token is held only in process memory for the current job and is not written to job status files, logs, or reports. The toolkit avoids putting the token in the Git URL or command line.

Recommended token scope is the minimum needed to read the target repository. Do not commit tokens, paste them into issue reports, or include them in evidence bundles.

## Outputs

A repository intake job writes:

- `detected-ecosystems.json`
- `generated-sboms/`
- `generator-comparison.json`
- `vuln-scan-results/`
- `sbom-quality/`
- `minimum-elements/`
- `policy/`
- optional `fuzzing-results/`
- `repo-intake-summary.md`

## Tooling model

The internal SBOM generator is a conservative fallback based on manifest/lockfile parsing. When installed, the toolkit can also orchestrate Syft, cdxgen, Trivy, Grype, and OSV-Scanner. The toolkit does not replace those tools; it coordinates them, compares results, and packages evidence.
