# v2.2.5 - Structure-Preserving Fuzzing Stability

## Fixes

- Fixed structure-preserving SBOM mutation when normalized CycloneDX XML components contain `hashes` as a count instead of a list.
- Improved normalized component `bom_ref` / `bom-ref` handling during mutation.
- Confirmed the Workbench `test-all-components` debugging workflow now passes the previously failing structure-preserving mutation step for CycloneDX XML uploads.

## Notes

This patch is intended to be pushed together with the unpushed v2.2.0-v2.2.4 changes. It keeps the README, CHANGELOG, release notes, package metadata, and Makefile aligned to v2.2.5.


## v2.2.4 - Dependency Health UI Clarity

- Made unsupported/out-of-date dependency analysis explicit in the Workbench workflow dropdown for uploaded SBOMs.
- Made repository dependency-health analysis explicit in the Repository Intake workflow dropdown.
- Added stale-threshold controls to the uploaded-SBOM workflow form.
- Clarified that dependency-health checks identify deprecated, abandoned, stale, unpinned, or unsupported-risk dependencies.
- Network-backed registry enrichment remains opt-in.

## v2.2.3 - Fuzzing Workflow Verification and Workbench Stability

- Verified the Fuzzing Lab workflows against both CycloneDX JSON and CycloneDX XML inputs.
- Fixed `make fuzz-evil-supplier`, which previously passed an obsolete positional argument and failed.
- Added `scripts/smoke-fuzz-workflows.sh` and `make fuzz-workflow-smoke` to exercise the major fuzzing workflows locally.
- Made Docker-dependent `fuzz-python`, `fuzz-js`, `fuzz-php`, and `fuzz-smoke` skip cleanly when Docker is not installed instead of failing with `docker: command not found`.
- Updated timed fuzzing Make targets so `COUNT` and `TIME_BUDGET` are propagated consistently.
- Changed workbench status writes to atomic temp-file replacement to avoid transient partial `status.json` reads while jobs are running.
- README updated to reflect v2.2.3 and to separate v2.2.1 dependency health from v2.2.2 fuzzing observability.

## v2.2.2 - Fuzzing Observability Fixes

- Added `fuzz-run-summary.json` and `fuzz-run-summary.md` to every Fuzzing Lab job.
- Evidence bundles now capture final completed/failed job status instead of stale pre-completion state.
- Metamorphic SBOM fuzzing reports input stats, transform count, generated artifacts, and guidance explaining deterministic semantic checks versus timed all-mode fuzzing.
- CycloneDX XML inputs are normalized for JSON-oriented fuzzing workflows.

## v2.2.1 - Dependency Health and Unsupported Dependency Review

Adds a conservative dependency health analysis layer for uploaded SBOMs and repository-generated SBOMs.

Highlights:

- New `dependency-health` workflow for CycloneDX JSON/XML and SPDX JSON SBOMs.
- New `repo-dependency-health` workflow for repository-generated SBOMs.
- Web UI support for repository dependency-health checks, stale-day threshold configuration, and optional registry enrichment.
- Detection signals include explicit deprecation/abandonment/EOL metadata where available, SBOM support-status properties, last-release/update age, missing exact versions, and unpinned/range versions.
- Optional network enrichment for npm, PyPI, crates.io, and Packagist using public registry metadata.
- Reports generated as JSON, Markdown, and CSV.

Important interpretation rule:

- No updates in 365 days is not automatically end-of-life. It is a review trigger. Some mature libraries intentionally change rarely. Explicit maintainer/vendor EOL or deprecation metadata should carry more weight than stale-update heuristics.

---


## v2.2.0 - Repository Intake and SBOM Build Pipeline

Adds repository-to-SBOM workflows so users can start from source code instead of requiring a pre-built SBOM.

Highlights:

- Repository Intake tab in the local workbench UI.
- Local path, repository archive upload, and HTTPS GitHub repository intake.
- Optional GitHub token support for private repositories; tokens are held only in process memory for the job and are not written to status files or logs.
- Static ecosystem detection for npm, Python, Go, Maven, Gradle, Rust, Composer, Ruby, .NET, containers, and GitHub Actions.
- Internal static CycloneDX fallback generator from manifests/lock files.
- Orchestration for Syft, cdxgen, Trivy, Grype, and OSV-Scanner when installed.
- SBOM generator comparison report.
- Optional vulnerability scanning and fuzzing of generated SBOMs.
- Repository evidence bundle output.
- CLI and Make targets: `repo-intake`, `repo-sbom`, `repo-scan`, `repo-fuzz`, `repo-evidence`, and `sst repo analyze`.

Safety model:

- No project install/build scripts are run by default.
- Remote cloning is explicit opt-in.
- GitHub tokens are passed through environment variables or transient UI process memory.

# v2.1.1 - Fuzzing Lab Time Limits and Format-Tolerant Runs

This patch fixes the Fuzzing Lab before the v2.1 line is considered final.

Added/fixed:

- Restored browser controls for fuzzing run time limits.
- Added a **run all timed fuzzing** workflow that runs available local fuzzing efforts with a user-set time limit per step/library.
- Added run-target controls for timed runs, including SBOM/scanner/AI and optional Python/JavaScript/PHP engine groups when Docker is available.
- Hardened JSON-oriented fuzzing workflows so CycloneDX XML, SPDX tag-value, and other supported non-JSON SBOMs are normalized before semantic/round-trip/metamorphic fuzzing instead of crashing with `JSONDecodeError`.
- Added workbench tests for timed fuzzing exposure and XML normalization.
- Updated README and UI docs to reflect the actual Fuzzing Lab behavior.

# v2.1.0 - Intelligent Fuzzing Operations

This release expands the Fuzzing Lab into a more adaptive local fuzzing operations environment and updates the README to match the shipped feature set.

## Added

- Fuzzing intelligence scoring.
- Corpus promotion recommendations.
- Harness quality audit.
- AI generate-check-fix harness quality loop.
- AI seed-generator synthesis and test workflow.
- Runnable grammar-mutator scaffold.
- Method-targeted coverage hints.
- Semantic format-diff fuzzing.
- Vulnerability matching fuzzing.
- VEX contradiction and logic fuzzing.
- Evil supplier SBOM scenario suite.
- AI fuzzing provider red-team checks.
- ClusterFuzzLite result import and local CI dashboard.
- Fuzz finding lifecycle tracking.
- Fuzzing Lab visualization dashboard.
- Web UI updates for additional fuzzing workflows, workflow options, logs, and dashboard access.
- CLI and Make targets for the new fuzzing operations workflows.

## Safety model

AI remains optional, advisory, and review-gated. The default provider mode is prompt-only. AI-generated harnesses, seed generators, and campaign ideas are saved for review and are not executed or promoted automatically.

---

# v2.0.1 - Fuzzing Lab UI Enhancements

This patch release expands the local Workbench UI with browser-driven fuzzing workflows and a dedicated fuzzing log view.

Added:

- richer Fuzzing Lab page with upload-driven fuzzing workflow selection,
- UI options for seed count, edge-case profile, budget profile, Dependency-Track URL, AI provider/model/scenario/goal, and harness-repair target,
- browser-launchable fuzzing workflows for structured mutation, round-trip checks, metamorphic checks, semantic oracles, scanner/toolchain fuzzing, stateful Dependency-Track dry runs, scanner metamorphic testing, schema-aware seed generation, budget profiles, coverage/status reports, replay packs, and AI corpus/harness workflows,
- dedicated `/fuzzing/logs` page showing recent fuzzing and AI-fuzzing job logs,
- job detail display of workflow options used for the run,
- tests for Fuzzing Lab workflow exposure and logging/filter behavior.

Safety model remains local-first: jobs run under `ui/storage/jobs`, uploaded files are isolated per job, AI workflows remain review-gated, and scanner/network behavior stays opt-in.

---

# v2.0.0 - Adaptive Fuzzing + SBOM Experience Alignment

This release adds adaptive, measurable fuzzing workflows while keeping the project local-first and review-driven.

Added:

- local SQLite fuzzing knowledge base,
- fuzz campaign recommendation planner,
- AI harness loop and multi-agent fuzz-loop prompt workflow,
- grammar files for CycloneDX, SPDX tag-value, purl, license expressions, and VEX,
- protobuf-model converter scaffolding,
- fuzz benchmark and benchmark comparison,
- scanner compatibility matrix,
- curated scanner truth-set tests,
- replay-pack generation for findings,
- Fuzzing Lab workbench workflows,
- safe AI provider evaluation,
- ClusterFuzzLite PR/nightly scaffolding,
- README alignment with actual shipped features.

Intentionally not added:

- executable semantic bug-class profiles from the previous roadmap item #11,
- public fuzzing research-report generation.


# v1.9.0 - Agent Workflow Integrations and Claude Skills

Added:

- Optional Claude Skill under `integrations/claude-skills/sbom-security-toolkit/`.
- Claude Skill resources for command reference, safety rules, workflow mapping, and report interpretation.
- Claude Skill helper scripts for running analysis, listing reports, and triaging fuzzing crashes.
- Provider-neutral agent prompt packs under `integrations/agent-prompts/`.
- Optional GLM local/OpenAI-compatible model profile for AI-assisted fuzzing.
- GLM reference configs under `ai_fuzz/config/`.
- `make ai-provider-test` and `sst ai-provider-test` for provider smoke testing.
- `docs/integrations/CLAUDE-SKILLS.md` with installation, safety, and usage guidance.
- `docs/integrations/GLM-LOCAL-MODELS.md` with local GLM setup patterns and safety guidance.
- Release notes and README positioning clarifying that agent/model workflows are optional and do not replace deterministic toolkit checks.

This release keeps the toolkit local-first and provider-neutral. AI/agent integrations, including Claude Skills and the optional GLM profile, are advisory workflow helpers only: deterministic tooling validates results and humans approve decisions.

---

# v1.8.0 - Usability, Packaging, and Release Hardening

Added:

- Editable Python package metadata via `pyproject.toml`.
- `sst` console-script entrypoint with `sst version`.
- `make setup`, `make install`, `make demo-full`, `make coverage`, `make preflight-release`, and `make release`.
- Dockerfile and Docker Compose profile for the local SBOM Workbench.
- Optional Docker Compose profile scaffolds for Dependency-Track and GUAC demos.
- GitHub Actions for tests, validation, fuzz smoke checks, and release evidence artifacts.
- GitHub issue templates, pull request template, and Dependabot configuration.
- `DATA-SAFETY.md` and release preflight scanning for generated artifacts, cache files, large files, secrets, and known company/customer-specific terms.
- `docs/INSTALL.md`, `docs/DEMO.md`, and `docs/RELEASE.md`.
- Synthetic demo SBOM set under `test-sboms/demo/`.
- Placeholder UI/docs assets under `docs/assets/` for future screenshot replacement.
- Additional tests for versioning, CLI routing, data safety docs, and release scripts.

This release focuses on making the toolkit easier to clone, install, demo, validate, package, and safely publish.

---

## v1.4.0 - SBOM Intake and Evidence Release

Added:

- One-command project analysis: `make analyze PROJECT=...`
- CISA/NTIA-style SBOM minimum-elements checker
- Supplier questionnaire and follow-up email generation
- Scanner confidence scoring across vulnerability reports
- Exploitability Decision Records for human-reviewed VEX evidence
- SBOM redaction/privacy mode for safe sharing
- Local SBOM watch mode with delta reports
- `sst` CLI wrapper via `python3 -m sbomops.cli`
- Static UI bundle with `data.json`
- Runnable GUAC demo scaffold
- Artifact checksum/sign/verify workflow with optional cosign support
- Unit tests for core parsing, scoring, minimum-elements, and supplier-question workflows

# SBOM Security Toolkit - Multi-Ecosystem Fuzzing Release
## Version 2.0 - 2026-07-02

## 🎉 What's New

### Multi-Language Fuzzing Support
**3 fuzzing engines ready to use:**
- ✅ **PHP** - php-fuzzer with AST instrumentation (27 targets included)
- ✅ **JavaScript/TypeScript** - Jazzer.js with V8 native coverage (4 targets included)
- ✅ **Python** - Atheris with libFuzzer (4 targets included)

### SBOM Format Support
**Now supports multiple SBOM formats:**
- ✅ CycloneDX XML (all versions 1.3-1.6)
- ✅ CycloneDX JSON (all versions 1.3-1.6)
- ✅ SPDX JSON (2.x and 3.x)
- ✅ SPDX RDF/XML (convert to JSON first)

### Automatic Ecosystem Detection
The toolkit now:
- Reads any supported SBOM format
- Detects which ecosystems are present (composer, npm, pypi, etc.)
- Automatically routes to the appropriate fuzzing engine(s)
- Runs multiple engines in sequence for multi-language SBOMs

### Smart Target Generation
Claude Code integration:
- Analyzes SBOM components
- Picks high-value fuzzing targets (parsers, validators, template engines)
- Writes harnesses following engine-specific patterns
- Creates seed corpora automatically

---

## 📦 What's Included

### Core Components
```
fuzzing/engines/
├── php/              - 27 PHP targets ready to fuzz
├── javascript/       - 4 JavaScript/TypeScript targets
└── python/          - 4 Python targets

orchestrate.sh         - Main entry point (updated)
extract-components.py  - SBOM parser (SPDX support added)
test-multi-ecosystem.sh - Smoke tests
```

### Documentation
```
MULTI-ECOSYSTEM-FUZZING.md  - Implementation guide
SBOM-FORMAT-SUPPORT.md      - Format compatibility
DEPLOYMENT-SUMMARY.txt      - Test results
fuzzing/ARCHITECTURE.md     - Design principles
fuzzing/README-ENGINES.md   - Per-engine docs
```

### Example Files
```
test-sboms/example-spdx-2.3.json - Test SPDX file
vuln-scan/cyclonedx-sbom.xml     - Example CycloneDX SBOM
```

---

## 🚀 Quick Start

### 1. Extract the Archive
```bash
unzip sbom-toolkit-multi-ecosystem-20260702.zip
cd sbom-security-toolkit
```

### 2. Test All Engines
```bash
./test-multi-ecosystem.sh
```

Expected output:
```
✓ PASS: Found ecosystems
✓ PASS: PHP engine builds
✓ PASS: JavaScript engine builds
✓ PASS: Python engine builds
```

### 3. Run the Pipeline
```bash
# Quick scan + triage only (no fuzzing)
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml --skip-fuzz

# Full pipeline with fuzzing (5 min per target)
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml

# Quick fuzzing test (1 min per target)
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml --budget 60 --skip-new-targets
```

### 4. Check Results
```bash
# View AI triage
cat runs/*/ai-triage.md

# View fuzzing crashes
ls runs/*/findings-*/*/crash-*.txt

# View summary
cat runs/*/SUMMARY.md
```

---

## 📋 Prerequisites

### Required
- **Docker** - For running fuzzing engines
- **Python 3** - For SBOM parsing and ecosystem detection
- **Bash** - For orchestration scripts

### Optional (for full functionality)
- **Claude Code CLI** - For automatic target generation (Stage 3)
  - Install: `npm install -g @anthropic-ai/claude-code`
- **AWS Bedrock** or **Anthropic API** - For AI triage (Stage 2)
  - Set `CLAUDE_BACKEND=bedrock` or `ANTHROPIC_API_KEY`

### Fuzzing Engines Run in Docker
No need to install:
- php-fuzzer
- Jazzer.js
- Atheris

They're all containerized and installed during `docker build`.

---

## 🎯 Usage Examples

### Example 1: CycloneDX SBOM
```bash
# Generate SBOM with Syft
syft packages . -o cyclonedx-json > sbom.json

# Run analysis
./orchestrate.sh sbom.json
```

### Example 2: SPDX SBOM
```bash
# Generate SBOM with Syft
syft packages . -o spdx-json > sbom.spdx.json

# Run analysis (same command!)
./orchestrate.sh sbom.spdx.json
```

### Example 3: Multi-Language Project
```bash
# Your SBOM has: 50 PHP + 30 JS + 20 Python packages
./orchestrate.sh path/to/sbom.json

# The toolkit automatically:
# 1. Detects all 3 ecosystems
# 2. Generates targets for each
# 3. Runs php-fuzzer + Jazzer.js + Atheris
# 4. Consolidates results
```

### Example 4: CI Integration
```bash
# Unattended mode (no prompts)
./orchestrate.sh sbom.json --auto --budget 60 --skip-new-targets

# Exit code 0 = no crashes
# Exit code 1 = crashes found
```

---

## 🔍 What Each Stage Does

### Stage 1: Vulnerability Scan (2-3 min)
- OSV-Scanner + Trivy scan all ecosystems
- Finds known CVEs from multiple databases
- Outputs: reports, SARIF, CycloneDX VEX

### Stage 2: AI Triage (30-90 sec)
- Claude prioritizes findings (P0/P1/P2/P3)
- Suggests gating conditions to verify
- Outputs: `ai-triage.md` with actionable priorities

### Stage 3: Target Generation (2-5 min per ecosystem)
- Claude Code analyzes SBOM components
- Picks 5 high-value targets per ecosystem
- Writes harnesses + seed corpora
- Pins exact versions from SBOM

### Stage 4: Fuzzing (depends on --budget)
- Runs coverage-guided fuzzing
- Default: 5 min per target
- Finds crashes, hangs, memory issues
- Outputs: `findings-<ecosystem>/`

### Stage 5: Summary
- Consolidates results across all ecosystems
- Lists crashes by ecosystem
- Reminds what needs human review

---

## ⚙️ Configuration

### Environment Variables
```bash
# Claude backend (for AI triage)
export CLAUDE_BACKEND=bedrock           # AWS Bedrock
# OR
export ANTHROPIC_API_KEY="your_anthropic_api_key_here"  # Direct API

# Optional: override model
export CLAUDE_MODEL="claude-3-5-sonnet-20241022-v2:0"

# Optional: AWS region (if using Bedrock)
export AWS_REGION=us-east-1
```

### Command-Line Flags
```bash
--auto                  # Unattended mode (skip prompts)
--budget SECONDS        # Fuzzing time per target (default 300)
--skip-new-targets      # Don't generate new targets
--skip-fuzz            # Stop after scan + triage
```

---

## 📊 Performance

### Build Time (First Run)
- PHP engine: ~30 seconds
- JavaScript engine: ~20 seconds
- Python engine: ~45 seconds (compiles Atheris)

### Runtime
**Small SBOM (91 PHP components):**
- Scan: ~3 minutes
- AI triage: ~1 minute
- Target generation: ~5 minutes
- Fuzzing (5 targets): ~25 minutes
- **Total: ~35 minutes**

**Multi-ecosystem SBOM (50 PHP + 30 JS + 20 Python):**
- Scan: ~3 minutes
- AI triage: ~1 minute
- Target generation: ~15 minutes
- Fuzzing (13 targets): ~65 minutes
- **Total: ~85 minutes**

### Cost Estimates
- **AWS Bedrock:** ~$0.50 per full run (triage + target gen)
- **Compute:** Negligible compared to security value

---

## 🐛 Troubleshooting

### "Docker build failed"
```bash
# Check Docker is installed and running
docker --version
docker ps

# Ensure you have permissions
sudo usermod -aG docker $USER
newgrp docker
```

### "No engine for X ecosystem"
Not all ecosystems have fuzzing engines yet:
- ✅ Supported: composer, npm, pypi
- 🚧 Templated: maven, golang, cargo
- ❌ Not yet: gem, nuget

Stage 1 (CVE scan) still works for all ecosystems.

### "Ecosystem detection failed"
Your SBOM might not have PURLs. Check:
```bash
python3 extract-components.py path/to/sbom.json
# Should show "purl": "pkg:ecosystem/..." fields
```

If missing, use a tool that emits PURLs (Syft, cdxgen).

### "Claude Code not found"
Stage 3 (target generation) requires Claude Code CLI:
```bash
npm install -g @anthropic-ai/claude-code
```

Or skip it:
```bash
./orchestrate.sh sbom.xml --skip-new-targets
```

---

## 🔒 Security Note

This toolkit finds security vulnerabilities. Results should be:
1. **Triaged** - Confirm crashes are exploitable
2. **Reported** - File upstream with minimized PoC
3. **Fixed** - Update vulnerable dependencies
4. **Monitored** - Run regularly on dependency updates

**Do not** run this on production systems or with untrusted SBOMs.

---

## 📝 Example Output

### AI Triage
```markdown
## P0 — Patch Immediately
• Laravel 11.35.0 - CRLF injection in email validation
• Laravel 11.35.0 - HTTP header injection

## P1 — Patch This Sprint
• league/commonmark 2.6.0 - XSS via Attributes Extension
```

### Fuzzing Results
```
findings-php/
  commonmark/
    corpus/           - Grown corpus (persistent)
    crash-abc123.txt  - Crash-triggering input
    fuzz.log         - Fuzzer output

findings-javascript/
  marked/
    corpus/
    crash-xyz456.txt
```

---

## 🆘 Getting Help

### Documentation
1. Start with `MULTI-ECOSYSTEM-FUZZING.md`
2. Check `SBOM-FORMAT-SUPPORT.md` for format issues
3. Read `fuzzing/README-ENGINES.md` for engine specifics
4. See `fuzzing/ARCHITECTURE.md` for design details

### Common Issues
- Missing Docker → Install Docker
- No PURLs in SBOM → Use Syft or cdxgen
- Wrong SPDX format → Convert to JSON first
- Crashes not minimized → See engine docs for commands

---

## 📜 License

See `LICENSE` file for full license text.

Core components:
- This toolkit: FSL-1.1-ALv2; converts to Apache-2.0 under the Future License terms
- php-fuzzer: MIT
- Jazzer.js: Apache-2.0
- Atheris: Apache-2.0

---

## 🎯 Next Steps

1. **Test it:**
   ```bash
   ./test-multi-ecosystem.sh
   ```

2. **Run it:**
   ```bash
   ./orchestrate.sh vuln-scan/cyclonedx-sbom.xml
   ```

3. **Review results:**
   ```bash
   cat runs/*/ai-triage.md
   cat runs/*/SUMMARY.md
   ```

4. **Address findings:**
   - Update vulnerable dependencies
   - Minimize and triage any crashes
   - Report real bugs upstream

5. **Integrate:**
   - Add to CI pipeline
   - Schedule weekly scans
   - Monitor for new vulnerabilities

---

## 📞 Support

For issues or questions:
- Check documentation files first
- Review example SBOMs in `test-sboms/`
- Run smoke tests: `./test-multi-ecosystem.sh`

---

**Version:** 2.0  
**Release Date:** 2026-07-02  
**Status:** Production ready  
**Tested:** Real vulnerabilities found in actual SBOMs

Enjoy comprehensive SBOM security analysis across multiple languages! 🚀

## Fuzzing Enhancement Update

This package now includes an expanded fuzzing subsystem:

- Added SBOM-specific Python/Atheris targets for CycloneDX JSON, SPDX JSON, package-url strings, and SPDX-style license expressions.
- Added JavaScript/Jazzer.js SBOM parser targets for CycloneDX JSON, SPDX JSON, and package-url strings.
- Added `make fuzz-smoke`, `make fuzz-nightly`, `make fuzz-deep`, `make fuzz-repro`, `make fuzz-scorecard`, `make fuzz-corpus`, and `make fuzz-differential` commands.
- Added crash metadata and reproducer scaffolding.
- Added corpus generation, mutation, minimization, and local AI seed-suggestion helpers.
- Added a differential SBOM parser/scanner harness for locally installed tools.
- Added GitHub Actions templates for PR smoke fuzzing and scheduled nightly fuzzing.
- Added continuous fuzzing documentation and ClusterFuzzLite starter templates.

## v1.2.0 - SBOM Operations Workbench Additions

Added:

- SBOM quality scoring.
- Policy-as-code release gates.
- Supplier SBOM intake mode.
- CycloneDX VEX helper commands.
- Vulnerability prioritization reports.
- Scanner comparison scaffolding.
- OpenSSF Scorecard wrapper scaffolding.
- GUAC-friendly graph export scaffold.
- AI triage prompt templates and guarded deterministic triage summary.
- Release evidence bundle workflow.
- Static local dashboard generator.
- Additional demo SBOMs and policies.

The UI remains intentionally static/local for now to avoid introducing authentication, database, and hosting risks before the CLI workflows stabilize.

## Advanced fuzzing expansion

Added a deeper SBOM fuzzing layer with structure-preserving mutators, semantic oracles, round-trip and metamorphic test harnesses, campaign profiles, regression corpus management, crash deduplication, malicious metadata scenario generation, local-only Dependency-Track API fuzzing scaffolding, and a proto model scaffold for future native structured fuzzing.

## v1.5.0 - Local SBOM Workbench UI

Adds a localhost-only SBOM workbench for uploading SBOMs, running toolkit workflows, tracking jobs, viewing logs/results, checking optional scanner availability, and downloading evidence bundles.

Highlights:

- `make ui-server` starts the local web UI on `127.0.0.1:8080`.
- Upload support for `.json`, `.xml`, `.spdx`, and `.txt` SBOMs.
- Workflow buttons for full analysis, quality scoring, minimum elements, policy checks, supplier intake, supplier questions, report generation, redaction, scanner comparison, and release evidence.
- Simple background job runner using local filesystem state only.
- Per-job evidence bundle downloads.
- Scanner availability page for Syft, Trivy, Grype, OSV-Scanner, cosign, Docker, and Git.
- Local-first safety model: no database, no cloud upload, localhost bind by default, size/type checks, sanitized filenames, per-job directories, and delete controls.

See `docs/ui/LOCAL-WORKBENCH.md`.

## v1.6.0 - AI-Assisted Fuzzing Workflows

Added a guarded AI-assisted fuzzing layer:

- Prompt-only default mode requiring no API keys or network model.
- Optional local Ollama and OpenAI-compatible endpoint provider hooks.
- AI seed generation for CycloneDX/SPDX edge cases with deterministic fallback seeds.
- AI mutation-plan generation for structure-preserving SBOM fuzzing.
- AI oracle suggestions for semantic fuzzing invariants.
- AI crash triage summaries.
- AI regression-test and fuzz-harness draft generation.
- AI coverage-gap suggestions.
- AI campaign profile generation.
- AI scanner-disagreement explanations.
- Review queues under `ai_fuzz/review/` with accept/reject/list commands.
- Incoming AI-generated corpus area under `fuzzing/corpus/ai/`.
- Workbench workflow entries for AI seed, mutation-plan, and campaign drafts.

Safety model: AI proposes, deterministic tools validate, humans approve. Generated artifacts are advisory and are not executed or promoted automatically.


## v1.7 Preview: Coverage-Guided Fuzzing Lab and SBOM Experience

This version adds schema-aware SBOM seed generators, AFL++ scaffolding, scanner/toolchain fuzzing, stateful local Dependency-Track workflow fuzzing, scanner metamorphic testing, fuzzing dictionaries, budget profiles, bug-class campaigns, advisory draft generation, and an all-local fuzzing command.

It also improves the SBOM user experience with commands to explain, normalize, repair, diff, and export SBOM inventories so users can better understand what an SBOM contains before feeding it into scanners or supplier workflows.

Key commands:

```bash
make fuzz-all-local SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-generate-cyclonedx EDGE=dependency-cycle COUNT=25
make fuzz-toolchain SBOM=test-sboms/clean/minimal-cyclonedx.json
make sbom-experience SBOM=test-sboms/clean/minimal-cyclonedx.json
```
