# Quick Start

Launch `sst workbench` and open `http://127.0.0.1:8080/welcome` for the guided setup wizard.

# Quick Start — SBOM Security Toolkit v2.12.0

## Install locally

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -e ".[dev]"
```

Verify the installation:

```bash
sst version
sst doctor
sst --help
```

## Start the Workbench

```bash
sst workbench
```

Open <http://127.0.0.1:8080/dashboard>.

Recommended first workflow:

1. Open **Scans** or **Repository Intake**.
2. Upload an SBOM, select a local repository/archive, or provide a GitHub repository.
3. Run analysis.
4. Review **Findings** and **Release Decisions**.
5. Use **Security Controls** for VEX, provenance, evidence, organization context, or remediation.
6. Generate a report or evidence bundle.

## Analyze an existing SBOM

```bash
sst analyze --help
sst score --help
sst minimum-elements --help
sst dependency-health --help
```

Test files are available under `test-sboms/`.

## Analyze a repository

```bash
sst repo-intake --help
```

Repository intake can detect ecosystems, use installed generators/scanners, compare generated SBOMs, evaluate dependency health, optionally fuzz results, and package evidence.

## Configure connectors

```bash
cp configs/connectors.example.yml configs/connectors.yml
sst connectors list
sst connectors smoke
```

Live network calls require explicit `--send`; write operations additionally require write enablement in connector configuration. Store tokens in the referenced environment variables.

## Release assurance and governance

```bash
sst release-assurance --help
sst risk-exceptions --help
sst vex --help
sst provenance --help
sst evidence-bundle --help
sst org-model --help
sst remediation --help
```

The Workbench exposes these functions under **Release Decisions**, **Exceptions**, **Evidence**, and **Security Controls**.

## Reports

```bash
sst ai-report --help
sst reports index
```

AI providers are optional. Prompt-only/local operation remains available, and generated narrative is always advisory.

## Validate the package

```bash
python3 -m compileall sbomops ai_fuzz fuzzing
pytest -q
```

See `VALIDATION.md` for bounded test groups and known behavior of subprocess-heavy legacy tests.
