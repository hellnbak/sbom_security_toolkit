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
