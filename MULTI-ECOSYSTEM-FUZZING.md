# Multi-Ecosystem Fuzzing — Implementation Summary

**Date:** 2026-07-02  
**Status:** ✅ PHP, JavaScript, Python engines ready to use

## What Changed

The SBOM security toolkit now supports **coverage-guided fuzzing for multiple programming language ecosystems**, not just PHP.

### Before
- Only PHP/Composer components could be fuzzed
- Other ecosystems got CVE scanning but no fuzzing
- Manual setup required for each new language

### After
- **3 engines ready:** PHP (php-fuzzer), JavaScript (Jazzer.js), Python (Atheris)
- **3 engines templated:** Java (Jazzer), Go (native), Rust (cargo-fuzz)
- **Automatic detection:** orchestrate.sh reads SBOM and runs appropriate engines
- **Modular architecture:** Each engine is isolated in its own container
- **Common interface:** All engines follow same contract (run.sh, TIME_BUDGET, FINDINGS)

---

## Quick Start

### Run Everything (Auto-Detect Ecosystems)
```bash
./orchestrate.sh path/to/sbom.xml
```

Output:
```
Ecosystem → Engine mapping:
  composer (91 components) → engines/php ✓
  npm (42 components) → engines/javascript ✓
  pypi (15 components) → engines/python ✓

[Stage 3.composer] Generating targets for composer...
[Stage 3.npm] Generating targets for npm...
[Stage 3.pypi] Generating targets for pypi...

[Stage 4.composer] Fuzzing composer components...
[Stage 4.npm] Fuzzing npm components...
[Stage 4.pypi] Fuzzing python components...
```

Results land in:
- `runs/<timestamp>/findings-php/`
- `runs/<timestamp>/findings-javascript/`
- `runs/<timestamp>/findings-python/`

### Run One Engine Manually
```bash
cd fuzzing/engines/javascript
docker build -t sbom-fuzzer-javascript .
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-javascript
```

---

## Architecture

```
fuzzing/
├── engines/
│   ├── php/              # php-fuzzer (nikic/PHP-Fuzzer)
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── composer.json
│   │   ├── targets/      # .php harness files
│   │   └── corpus/       # seed inputs
│   │
│   ├── javascript/       # Jazzer.js (CodeIntelligence)
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── package.json
│   │   ├── targets/      # .js/.ts harness files
│   │   └── corpus/
│   │
│   └── python/           # Atheris (Google)
│       ├── Dockerfile
│       ├── run.sh
│       ├── requirements.txt
│       ├── targets/      # .py harness files
│       └── corpus/
│
├── detect-ecosystems.py  # Maps PURL types to engines
├── ARCHITECTURE.md       # Design doc
└── README-ENGINES.md     # Per-engine docs
```

**Key principle:** Each engine is fully self-contained. No shared dependencies, no cross-contamination.

---

## Engines Implemented

### ✅ PHP (php-fuzzer)
- **Status:** Ready (pre-existing, refactored to new structure)
- **Coverage:** AST-level via php-parser
- **Example targets:** Markdown, YAML, URI parsing, HTTP messages
- **Speed:** Medium (interpreted language overhead)

### ✅ JavaScript/TypeScript (Jazzer.js)
- **Status:** Ready (newly implemented)
- **Coverage:** V8 native instrumentation
- **Example targets:** marked, js-yaml, ajv (JSON Schema), semver
- **Speed:** Fast (native coverage)

### ✅ Python (Atheris)
- **Status:** Ready (newly implemented)
- **Coverage:** libFuzzer + Python C API
- **Example targets:** PyYAML, Jinja2, jsonschema, urllib3
- **Speed:** Slow (Python overhead, but still effective)

### 🚧 Java/JVM (Jazzer)
- **Status:** Template exists, needs testing
- **Coverage:** JVM bytecode instrumentation
- **Good for:** XML/JSON parsers, protobuf, serialization

### 🚧 Go (native)
- **Status:** Template exists, needs testing
- **Coverage:** Built into Go 1.18+ toolchain
- **Good for:** Parsers, encoders, crypto

### 🚧 Rust (cargo-fuzz)
- **Status:** Template exists, needs testing
- **Coverage:** LLVM libFuzzer
- **Good for:** Parsers, regex, compression

---

## Example Targets Provided

### PHP
- `commonmark.php` — Markdown → HTML parsing
- `php_parser.php` — Full PHP grammar parser
- `psr7_uri.php` — URI parsing (SSRF surface)
- `psr7_message.php` — HTTP message parsing
- `symfony_yaml.php` — YAML parser (billion laughs, stack overflow)
- `email_validator.php` — RFC email validation

### JavaScript
- `marked.js` — Markdown parser
- `ajv.js` — JSON Schema validator (ReDoS surface)
- `yaml.js` — js-yaml (billion laughs, deep nesting)
- `semver.js` — Semantic version parsing

### Python
- `pyyaml_fuzz.py` — YAML parser
- `jinja2_fuzz.py` — Template engine (injection surface)
- `jsonschema_fuzz.py` — JSON Schema validator
- `urllib_fuzz.py` — URL parsing

Each target includes 3-5 seed inputs to bootstrap the fuzzer.

---

## How It Works

### Stage 1: Detect Ecosystems
```bash
python3 fuzzing/detect-ecosystems.py runs/<timestamp>/components.json
```

Output format: `ecosystem:count:engine`
```
composer:91:php
npm:42:javascript
pypi:15:python
gem:5:none
```

### Stage 2: Generate Targets (Claude Code)
For each ecosystem with an available engine:
1. Read existing targets as examples
2. Filter SBOM to ecosystem-specific components
3. Prompt Claude Code: "Pick 5 high-value targets, write harnesses"
4. Claude adds dependencies at exact SBOM versions
5. Claude writes targets following engine pattern
6. Claude creates seed corpus

### Stage 3: Build Images
```bash
docker build -t sbom-fuzzer-php engines/php
docker build -t sbom-fuzzer-javascript engines/javascript
docker build -t sbom-fuzzer-python engines/python
```

Each engine installs its fuzzing tool + SBOM dependencies in isolation.

### Stage 4: Fuzz
```bash
docker run --rm \
  -e TIME_BUDGET=300 \
  -v "$RUN_DIR/findings-php:/fuzz/findings" \
  sbom-fuzzer-php
```

Each engine runs sequentially (fuzzing is CPU-bound, parallelism helps less than you'd think).

Output structure:
```
findings-php/
  commonmark/
    corpus/           # Persistent, grows across runs
    crash-ABC123.txt  # Crash-triggering input
    fuzz.log
```

---

## Common Interface

Every engine's `run.sh` must:

**Accept:**
- `TIME_BUDGET` env var (seconds per target, default 300)
- `FINDINGS` env var (output directory, default `/fuzz/findings`)
- Optional `$1` arg (single target name to run)

**Produce:**
- `$FINDINGS/<target>/corpus/` — persistent corpus
- `$FINDINGS/<target>/crash-*.txt` — crash inputs
- `$FINDINGS/<target>/fuzz.log` — fuzzer output

**Exit codes:**
- `0` — completed budget, no crashes
- `1` — crash(es) found (still success from fuzzing POV)
- `2+` — setup/config error

This contract means `orchestrate.sh` can treat all engines uniformly.

---

## Target Selection Criteria

Claude Code is prompted to pick targets that:

### ✅ High Value
- Parse untrusted input formats (Markdown, YAML, JSON, XML, URIs)
- Handle user-generated content (sanitizers, validators)
- Process uploaded files (image decoders, archive extractors)
- Parse complex grammars (template engines, SQL builders)
- Have historical CVEs (YAML parsers, HTTP parsers)

### ❌ Low Value
- Logging libraries (output-only)
- dependency-injection containers (no parsing logic)
- CLI tools (not in request path)
- Framework glue (trivial wrappers)
- Simple value objects (getters/setters)

---

## Testing the Implementation

### Smoke Test (Quick Validation)
```bash
# Test ecosystem detection
python3 fuzzing/detect-ecosystems.py vuln-scan/cyclonedx-sbom.xml

# Test one engine
cd fuzzing/engines/javascript
docker build -t sbom-fuzzer-javascript .
docker run --rm -v "$PWD/findings:/fuzz/findings" -e TIME_BUDGET=60 \
  sbom-fuzzer-javascript marked

# Check for output
ls findings/marked/corpus/
```

### Full Pipeline Test
```bash
# Run with short budget
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml --budget 60

# Check results
cat runs/*/SUMMARY.md
ls runs/*/findings-*
```

---

## What's Next

### Ready to Use Now
1. Run `./orchestrate.sh` on any SBOM
2. PHP, JavaScript, Python components will fuzz automatically
3. Review generated targets before trusting long-term
4. Triage any crashes found

### Future Work (Optional)
1. **Test Java/Go/Rust engines:** Templates exist, need real-world validation
2. **Add more example targets:** Current set covers parsers well, could add more crypto/image/archive targets
3. **Continuous fuzzing:** Run in CI on every dependency update
4. **Corpus sharing:** Maintain a central corpus repo for common libraries
5. **Crash deduplication:** Cluster crashes by stack trace before reporting

---

## Cost & Performance

### Build Time
- PHP: ~30s (composer install)
- JavaScript: ~20s (npm install)
- Python: ~45s (compile Atheris + pip install)

### Fuzz Time (per target)
- Default: 300s (5 min) — finds shallow bugs
- Recommended: 3600s (1 hour) — decent coverage
- Deep dive: 14400s (4 hours) — thorough

### Resource Usage
- CPU: 1 core per target (100% utilization)
- Memory: 500MB-2GB per target
- Disk: Corpus grows ~10-100MB per target

### Example Run (Mixed SBOM)
- 91 PHP components → 5 targets selected → 25 min
- 42 JS components → 5 targets selected → 25 min
- 15 Python components → 3 targets selected → 15 min
- **Total: ~65 min** (at 5 min/target)

Scale with `--budget`:
- `--budget 60` → 13 min total (smoke test)
- `--budget 3600` → 13 hours total (deep)

---

## Limitations

### By Design
- **No app-level fuzzing:** Libraries fuzzed in isolation, not your app
- **No state fuzzing:** Stateless input → output only
- **Version-pinned:** Fuzz deployed versions, not latest
- **No cross-language:** Each engine fuzzes its own ecosystem

### Technical
- **Interpreted overhead:** Python/PHP slower than native
- **Container overhead:** ~200ms startup per target
- **No deterministic replay:** Some crashes are timing/environment dependent

---

## References

- Architecture: `fuzzing/ARCHITECTURE.md`
- Engine docs: `fuzzing/README-ENGINES.md`
- PHP engine: `fuzzing/engines/php/`
- JavaScript engine: `fuzzing/engines/javascript/`
- Python engine: `fuzzing/engines/python/`

---

## Questions?

**"Do I need to configure anything?"**  
No. Just run `./orchestrate.sh path/to/sbom.xml`. It detects ecosystems automatically.

**"What if my SBOM has Java/Go/Rust?"**  
CVE scanning still works. Fuzzing engines for those exist as templates but need testing. You can skip them for now or help validate them.

**"Can I add my own targets?"**  
Yes. Drop a target file in `engines/<ecosystem>/targets/`, add seeds to `corpus/`, rebuild the image.

**"How do I know if a crash is exploitable?"**  
Replay it, minimize it, assess whether the input is attacker-reachable in your app. See `README-ENGINES.md` for triage commands.

**"This found a crash. Now what?"**  
1. Minimize: `docker run ... minimize-crash ...`
2. Replay: `docker run ... run-single ...`
3. Assess: Is this input attacker-reachable?
4. Report: File upstream with minimized PoC if confirmed

---

**Status:** Ready for production use on PHP, JavaScript, Python SBOMs.  
**Updated:** 2026-07-02
