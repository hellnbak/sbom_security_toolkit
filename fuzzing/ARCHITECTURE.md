# Multi-Ecosystem Fuzzing Architecture

## Design Principles

1. **Modular by ecosystem** — Each language/ecosystem gets its own engine subdirectory with isolated dependencies
2. **Common interface** — All engines expose the same run contract so orchestrate.sh treats them uniformly
3. **SBOM-driven** — Engines pin exact versions from CycloneDX SBOM purls
4. **Coverage-guided where possible** — Prefer engines with instrumentation feedback (libFuzzer-style)
5. **Containerized** — Each engine builds as a Docker image to avoid host dependency conflicts

## Directory Structure

```
fuzzing/
├── engines/
│   ├── php/              # Existing php-fuzzer setup (refactored from fuzzing/)
│   │   ├── Dockerfile
│   │   ├── run.sh        # Engine-specific runner
│   │   ├── composer.json
│   │   ├── targets/      # .php harness files
│   │   └── corpus/       # seed inputs
│   │
│   ├── javascript/       # Jazzer.js (npm/yarn/pnpm)
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── package.json
│   │   ├── targets/      # .js/.ts harness files
│   │   └── corpus/
│   │
│   ├── python/           # Atheris
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── requirements.txt
│   │   ├── targets/      # .py harness files
│   │   └── corpus/
│   │
│   ├── java/             # Jazzer (maven/gradle)
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── pom.xml (or build.gradle)
│   │   ├── targets/      # .java harness files
│   │   └── corpus/
│   │
│   ├── go/               # native Go fuzzing
│   │   ├── Dockerfile
│   │   ├── run.sh
│   │   ├── go.mod
│   │   ├── targets/      # _test.go fuzzing functions
│   │   └── corpus/
│   │
│   └── rust/             # cargo-fuzz
│       ├── Dockerfile
│       ├── run.sh
│       ├── Cargo.toml
│       ├── fuzz/         # cargo-fuzz structure
│       └── corpus/
│
├── run-all.sh            # Dispatcher: runs appropriate engines based on SBOM
└── README-ENGINES.md     # Per-engine capabilities and limitations
```

## Engine Contract

Every `engines/<ecosystem>/run.sh` must:

1. **Accept environment variables:**
   - `TIME_BUDGET` — seconds per target (default 300)
   - `FINDINGS` — output directory for corpus + crashes (default `/fuzz/findings`)
   - `TARGET_FILTER` — optional single target name to run

2. **Exit codes:**
   - `0` — no crashes found (completed budget)
   - `1` — crash(es) found (still a success from fuzzing perspective)
   - `2+` — configuration/setup error

3. **Output structure:** (within `$FINDINGS`)
   ```
   findings/
   └── <target-name>/
       ├── corpus/           # persistent, grows across runs
       ├── crash-<hash>.txt  # crash-triggering inputs
       └── coverage/         # optional HTML reports
   ```

4. **Crash documentation:**
   Each engine's README section must document:
   - How to minimize a crash
   - How to replay with a stack trace
   - How to generate coverage reports

## SBOM → Engine Mapping

| PURL Ecosystem | Fuzzing Engine | Image Name | Notes |
|----------------|----------------|------------|-------|
| `pkg:composer/*` | php-fuzzer | `sbom-fuzzer-php` | Instrumentation via php-parser |
| `pkg:npm/*` | Jazzer.js | `sbom-fuzzer-js` | libFuzzer-style for Node.js |
| `pkg:pypi/*` | Atheris | `sbom-fuzzer-python` | libFuzzer + Python C API |
| `pkg:maven/*` | Jazzer | `sbom-fuzzer-java` | libFuzzer for JVM bytecode |
| `pkg:golang/*` | native | `sbom-fuzzer-go` | Built into Go 1.18+ toolchain |
| `pkg:cargo/*` | cargo-fuzz | `sbom-fuzzer-rust` | libFuzzer for Rust |
| `pkg:gem/*` | (future) | — | No mature coverage-guided fuzzer yet |
| `pkg:nuget/*` | (future) | — | SharpFuzz exists but needs eval |

## Orchestration Flow

`orchestrate.sh` Stage 3/4 becomes:

```bash
# Extract ecosystems from SBOM
ECOSYSTEMS=$(python3 detect-ecosystems.py "$RUN_DIR/components.json")

# For each ecosystem with a wired-up engine:
for ECO in $ECOSYSTEMS; do
  ENGINE_DIR="$HERE/fuzzing/engines/$ECO"
  if [ -d "$ENGINE_DIR" ]; then
    echo "[Stage 3.$ECO] Generating targets for $ECO..."
    # Claude Code prompt: "Read engines/$ECO/targets examples, 
    # generate new harnesses for these components: <filtered-list>"
    
    echo "[Stage 4.$ECO] Fuzzing $ECO components..."
    docker build -t "sbom-fuzzer-$ECO" "$ENGINE_DIR"
    docker run --rm -e TIME_BUDGET="$BUDGET" \
      -v "$RUN_DIR/findings-$ECO:/fuzz/findings" \
      "sbom-fuzzer-$ECO"
  else
    echo "[Stage 3/4] No engine for $ECO (scanned for CVEs only)"
  fi
done
```

All engines run **sequentially** to avoid resource contention (fuzzing is CPU-bound).

## Target Selection Criteria (for Claude Code)

When generating new targets, prioritize components that:

1. **Parse untrusted input formats:**
   - Text: Markdown, YAML, JSON, XML, TOML, CSV, email, URIs
   - Binary: images, archives, protobuf, msgpack, ASN.1
   - Code: parsers, template engines, SQL builders

2. **Handle attacker-reachable data:**
   - Web: HTTP message parsing, cookie parsing, multipart form data
   - File upload: MIME type detection, image processing
   - User-generated content: sanitizers, validators

3. **Have complexity/state:**
   - State machines (protocol parsers)
   - Recursive descent (nested structures)
   - Regex-heavy (ReDoS surface)

**Skip:**
- Logging libraries (output-only)
- DI containers (no untrusted input)
- CLI tools (not in request path)
- Simple value objects (trivial code)
- Framework glue (no parsing logic)

## Adding a New Engine

1. Create `engines/<ecosystem>/` directory
2. Write `Dockerfile` that installs the fuzzing tool + builds dependencies
3. Write `run.sh` following the contract above
4. Add 2-3 example targets under `targets/` with seeds under `corpus/`
5. Document in `README-ENGINES.md`:
   - What the engine covers
   - How to write a target
   - How to triage crashes
   - Known limitations
6. Update `detect-ecosystems.py` to map the PURL type
7. Test with `docker build` and a smoke-test run

## Limitations by Design

- **No cross-language fuzzing** — we fuzz libraries in isolation, not app integration points
- **No state fuzzing** — these are stateless input → output fuzzers, not full app fuzzers
- **Version pinning required** — fuzz what's deployed, not latest (security assessment, not QA)
- **Interpreted languages only go so far** — PHP/Python/JS lack the deep instrumentation native fuzzers get

## Why This Beats Alternatives

| Alternative | Why We Don't Use It |
|-------------|---------------------|
| AFL++ on interpreters | Fuzzes the interpreter, not the library — finds CPython bugs, not your YAML parser bugs |
| Property-based testing (Hypothesis, QuickCheck) | Requires per-target property definitions; fuzzers find crashes with zero harness logic |
| DAST tools (Burp, ZAP) | HTTP-level only; miss library bugs not reachable via HTTP |
| Mutation testing | Measures test suite quality, doesn't find new bugs |

Coverage-guided fuzzing is the only technique that:
- Requires minimal harness code (just call the function)
- Automatically explores edge cases
- Finds crashes without knowing what's wrong

---

**Status:** Architecture complete, ready for implementation.
**Priority order:** JavaScript (Jazzer.js) → Python (Atheris) → others as needed.
