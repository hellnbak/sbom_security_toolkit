# Multi-Ecosystem Fuzzing Engines

This directory contains coverage-guided fuzzing engines for multiple programming language ecosystems. Each engine is containerized and follows a common interface.

## Quick Start

```bash
# Run all engines on your SBOM
./orchestrate.sh path/to/sbom.xml

# Or run a single ecosystem manually
cd engines/javascript
docker build -t sbom-fuzzer-javascript .
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-javascript
```

## Supported Ecosystems

| Ecosystem | PURL Type | Engine | Status | Good Targets |
|-----------|-----------|--------|--------|--------------|
| **PHP/Composer** | `pkg:composer/*` | [php-fuzzer](https://github.com/nikic/PHP-Fuzzer) | ✅ Ready | Parsers, template engines, validators |
| **JavaScript/TypeScript** | `pkg:npm/*` | [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) | ✅ Ready | Markdown, YAML, JSON Schema, semver |
| **Python** | `pkg:pypi/*` | [Atheris](https://github.com/google/atheris) | ✅ Ready | YAML, Jinja2, JSON Schema, URL parsing |
| **Java/JVM** | `pkg:maven/*` | [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) | 🚧 Template ready | XML, JSON, protobuf, serialization |
| **Go** | `pkg:golang/*` | native (`go test -fuzz`) | 🚧 Template ready | Parsers, encoders, crypto |
| **Rust** | `pkg:cargo/*` | [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | 🚧 Template ready | Parsers, regex, compression |
| Ruby | `pkg:gem/*` | — | ❌ No engine | (No mature coverage-guided fuzzer) |
| .NET | `pkg:nuget/*` | — | ❌ No engine | (SharpFuzz needs evaluation) |

---

## Engine Details

### PHP (php-fuzzer)

**Directory:** `engines/php/`  
**Coverage:** AST-level instrumentation via `nikic/php-parser`  
**Target pattern:** Export a `$config` with `setTarget()` closure

```php
<?php
require __DIR__ . '/../vendor/autoload.php';
use SomeLibrary\Parser;

$config->setMaxLen(10000);
$config->setAllowedExceptions([SomeLibrary\ParseException::class]);
$config->setTarget(function(string $input) {
    $parser = new Parser();
    $parser->parse($input);
});
```

**Commands:**
```bash
# Build
docker build -t sbom-fuzzer-php engines/php

# Fuzz all targets
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-php

# Fuzz one target
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-php commonmark

# Minimize crash
docker run --rm -v "$PWD/findings:/fuzz/findings" --entrypoint php-fuzzer \
  sbom-fuzzer-php minimize-crash targets/foo.php findings/foo/crash-ABC.txt

# Replay crash
docker run --rm -v "$PWD/findings:/fuzz/findings" --entrypoint php-fuzzer \
  sbom-fuzzer-php run-single targets/foo.php findings/foo/minimized-ABC.txt
```

**Good targets:** Markdown parsers, YAML/XML/JSON parsers, template engines, email validators, URI parsers, numeric string parsers, HTTP message parsers

**Dependencies:** Add to `composer.json` at exact SBOM version

---

### JavaScript/TypeScript (Jazzer.js)

**Directory:** `engines/javascript/`  
**Coverage:** V8 instrumentation (native)  
**Target pattern:** Export a `fuzz(data)` function

```javascript
import { marked } from 'marked';

export function fuzz(data) {
  try {
    const input = data.toString('utf-8');
    if (input.length > 100000) return;
    
    const html = marked.parse(input);
    
    // Force evaluation
    if (html.includes('\x00')) {
      throw new Error('Null byte in output');
    }
  } catch (e) {
    // Let real bugs propagate
    if (e.message.includes('Maximum call stack')) {
      throw e;
    }
  }
}
```

**Commands:**
```bash
# Build
docker build -t sbom-fuzzer-javascript engines/javascript

# Fuzz
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-javascript

# Replay crash
docker run --rm -v "$PWD/findings:/fuzz/findings" \
  --entrypoint npx sbom-fuzzer-javascript \
  jazzer --reproduce=findings/marked/crash-ABC targets/marked.js
```

**Good targets:** Markdown (marked), YAML (js-yaml), JSON Schema (ajv), semver parsing, template engines, parsers

**Dependencies:** Add to `package.json` at exact SBOM version

---

### Python (Atheris)

**Directory:** `engines/python/`  
**Coverage:** libFuzzer + Python C API instrumentation  
**Target pattern:** `TestOneInput(data)` + `atheris.Setup()`

```python
#!/usr/bin/env python3
import atheris
import sys

with atheris.instrument_imports():
    import yaml

def TestOneInput(data):
    try:
        if len(data) > 50000:
            return
        
        input_str = data.decode('utf-8', errors='ignore')
        parsed = yaml.safe_load(input_str)
        
        if parsed is not None:
            str(parsed)
    except yaml.YAMLError:
        pass
    except (RecursionError, MemoryError):
        raise

if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

**Commands:**
```bash
# Build
docker build -t sbom-fuzzer-python engines/python

# Fuzz
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer-python

# Replay crash
docker run --rm -v "$PWD/findings:/fuzz/findings" \
  --entrypoint python3 sbom-fuzzer-python \
  targets/pyyaml_fuzz.py findings/pyyaml_fuzz/crash-ABC
```

**Good targets:** PyYAML, Jinja2, jsonschema, urllib3, lxml, Pillow, cryptography parsers

**Dependencies:** Add to `requirements.txt` at exact SBOM version

---

## Adding a New Engine

To add support for a new ecosystem:

### 1. Create engine directory
```bash
mkdir -p fuzzing/engines/<ecosystem>/{targets,corpus}
```

### 2. Write Dockerfile
```dockerfile
FROM <base-image>
RUN <install-fuzzing-tool>
WORKDIR /fuzz
COPY <manifest> /fuzz/
RUN <install-dependencies>
COPY targets/ corpus/ run.sh /fuzz/
RUN chmod +x /fuzz/run.sh
RUN mkdir -p /fuzz/findings
ENTRYPOINT ["/fuzz/run.sh"]
```

### 3. Write run.sh
Must accept:
- `TIME_BUDGET` env var (seconds per target)
- `FINDINGS` env var (output directory)
- Optional arg for single target name

Must produce:
- `$FINDINGS/<target>/corpus/` — persistent corpus
- `$FINDINGS/<target>/crash-*.txt` — crash inputs
- Exit 0 (no crashes) or 1 (crashes found)

### 4. Add example targets
Create 2-3 targets under `targets/` following the engine's pattern. Include:
- Common parser types (YAML, JSON, Markdown)
- At least 3 seed files per target under `corpus/<target>/`

### 5. Update mapping
Add to `fuzzing/detect-ecosystems.py`:
```python
ECOSYSTEM_TO_ENGINE = {
    'your-ecosystem': 'your-engine',
    ...
}
```

### 6. Document
Add a section to this file explaining:
- Target pattern
- Build/run/triage commands
- Good target library types
- Dependency manifest format

---

## Target Selection Criteria

Good fuzzing targets have these properties:

### ✅ Fuzz This
- **Parsers:** Markdown, YAML, JSON, XML, TOML, CSV, protobuf
- **Input validators:** Email, URI, phone, credit card, regex
- **Template engines:** Jinja2, Handlebars, Twig, Mustache
- **Serializers:** JSON, msgpack, pickle, protobuf
- **Crypto:** PEM parsing, certificate validation, key derivation
- **Image processing:** JPEG, PNG, GIF decoders
- **Archive handling:** ZIP, TAR, GZIP extractors
- **HTTP:** Message parsing, header parsing, cookie parsing
- **Complex state machines:** Protocol parsers, lexers, compilers

### ❌ Skip This
- **Loggers:** Output-only, no untrusted input
- **DI containers:** No parsing logic
- **CLI tools:** Not in request path
- **Framework glue:** No complex logic
- **Simple value objects:** Trivial getters/setters
- **Database clients:** Covered by integration tests
- **Pure networking:** Fuzzing won't find socket bugs

### 🤔 Maybe
- **ORMs:** If they parse query strings
- **Validation libraries:** If they have complex rules
- **Formatters:** If they parse input before formatting

---

## Engine Comparison

| Feature | php-fuzzer | Jazzer.js | Atheris | Jazzer | cargo-fuzz |
|---------|-----------|-----------|---------|--------|------------|
| **Coverage** | AST | Native (V8) | libFuzzer | JVM | libFuzzer |
| **Speed** | Medium | Fast | Slow | Fast | Very Fast |
| **Setup** | Easy | Easy | Medium | Medium | Easy |
| **Corpus growth** | Good | Excellent | Good | Excellent | Excellent |
| **CI-friendly** | Yes | Yes | Yes | Yes | Yes |

**Speed factors:**
- Interpreted languages (Python) are slower than compiled
- Native instrumentation (V8, JVM, LLVM) is faster than runtime
- Corpus quality matters more than raw speed

---

## Best Practices

### Corpus Management
- **Seed wisely:** Include valid, edge-case, and near-invalid inputs
- **Minimize seeds:** Fuzzer will expand them, start small
- **Share corpora:** Same target across SBOMs can share corpus

### Target Writing
- **Bound input length:** Avoid trivial OOM (10KB-100KB typical)
- **Catch expected exceptions:** Parse errors are normal
- **Propagate real bugs:** Stack overflow, OOM, assertion failures
- **No external I/O:** Fuzzers need pure functions

### Time Budgets
- **Smoke test:** 60-300s per target (finds shallow bugs)
- **Real campaign:** 3600-14400s (1-4 hours) per target
- **Continuous:** Run overnight/weekend for deep coverage

### Triage
1. **Replay** the crash to confirm it's real
2. **Minimize** the input to simplest form
3. **Assess reachability:** Can attacker control this input?
4. **Check exploitability:** Stack corruption? Type confusion? DoS?
5. **Report upstream** if confirmed (with minimized PoC)

---

## Limitations

### By Design
- **No app-level fuzzing:** We fuzz libraries in isolation, not your app
- **No state fuzzing:** Stateless input → output only
- **Version-pinned:** Fuzz deployed versions, not latest
- **No cross-language:** Each engine fuzzes one ecosystem

### Technical
- **Interpreted language overhead:** Python/PHP are slower than native
- **Container overhead:** ~200ms startup per target
- **Corpus size:** Large corpora slow down restarts
- **No deterministic replay:** Some crashes are timing-dependent

### Coverage Blind Spots
- **Native extensions:** Instrumentation may not reach C code
- **JIT boundaries:** Coverage may miss JIT-compiled paths
- **Lazy initialization:** Some code only runs after many inputs

---

## Troubleshooting

### "No engine for X ecosystem"
The fuzzing engine for that language isn't implemented yet. Stage 1 (vuln scan) still covers it for known CVEs.

### "Docker build failed"
Check the specific error:
- Missing base image? Verify Docker can pull it
- Compile error? Check the dependencies in requirements/package.json
- Permission error? Run with `sudo` or fix Docker group

### "No crashes but I know there's a bug"
- Seed corpus may not cover that code path
- Time budget may be too short
- Target may need to call a different API
- Fuzzer may need hints (add more edge-case seeds)

### "Too many crashes"
- Might be one root cause, many manifestations
- Minimize all crashes first
- Unique stack traces = unique bugs

### "Fuzzer is slow"
- Input length bound too high? Lower `maxLen`
- Expensive operation in tight loop? Add early returns
- Large corpus? Prune duplicates with `--merge`

---

## References

- **php-fuzzer:** https://github.com/nikic/PHP-Fuzzer
- **Jazzer.js:** https://github.com/CodeIntelligenceTesting/jazzer.js
- **Atheris:** https://github.com/google/atheris
- **Jazzer (JVM):** https://github.com/CodeIntelligenceTesting/jazzer
- **cargo-fuzz:** https://github.com/rust-fuzz/cargo-fuzz
- **Go fuzzing:** https://go.dev/security/fuzz/
- **libFuzzer docs:** https://llvm.org/docs/LibFuzzer.html

---

**Status:** PHP, JavaScript, Python engines ready. Java, Go, Rust templates exist but need testing.  
**Updated:** 2026-07-02
