# SBOM Format Support

The toolkit supports **multiple SBOM formats** out of the box.

## Supported Formats

### ✅ CycloneDX

**Status:** Fully supported

| Format | Versions | Auto-Detection | Notes |
|--------|----------|----------------|-------|
| **CycloneDX XML** | 1.3, 1.4, 1.5, 1.6 | ✓ | Namespace-agnostic |
| **CycloneDX JSON** | 1.3, 1.4, 1.5, 1.6 | ✓ | Native parsing |

**Tools that produce CycloneDX:**
- Syft: `syft packages . -o cyclonedx-json`
- cdxgen: `cdxgen -o sbom.xml .`
- OWASP Dependency-Track (export)
- Maven: cyclonedx-maven-plugin
- Gradle: cyclonedx-gradle-plugin
- NPM: @cyclonedx/cyclonedx-npm

### ✅ SPDX

**Status:** JSON supported, RDF/tag-value with guidance

| Format | Versions | Auto-Detection | Notes |
|--------|----------|----------------|-------|
| **SPDX JSON** | 2.x, 3.x | ✓ | Extracts PURLs from externalRefs/externalIdentifiers |
| **SPDX RDF/XML** | 2.x | ✓ | Convert to JSON first (see below) |
| **SPDX tag-value** | 2.x | ✓ | Convert to JSON first (see below) |

**Tools that produce SPDX:**
- Syft: `syft packages . -o spdx-json`
- Scancode: `scancode -i . --spdx`
- Tern: `tern report -f spdxjson`
- FOSSology: SPDX report export
- spdx-sbom-generator

**Converting SPDX formats:**
```bash
# Install converter
pip install spdx-tools

# RDF/XML → JSON
spdx-tools convert sbom.spdx.rdf sbom.spdx.json

# Tag-value → JSON  
spdx-tools convert sbom.spdx sbom.spdx.json

# Then run normally
./orchestrate.sh sbom.spdx.json
```

---

## Usage Examples

### CycloneDX XML
```bash
# From Syft
syft packages . -o cyclonedx-xml > sbom.xml
./orchestrate.sh sbom.xml

# From cdxgen
cdxgen -o sbom.xml .
./orchestrate.sh sbom.xml
```

### CycloneDX JSON
```bash
# From Syft
syft packages . -o cyclonedx-json > sbom.json
./orchestrate.sh sbom.json

# From NPM
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
./orchestrate.sh sbom.json
```

### SPDX JSON
```bash
# From Syft
syft packages . -o spdx-json > sbom.spdx.json
./orchestrate.sh sbom.spdx.json

# From Scancode
scancode -i . --spdx --json sbom.spdx.json
./orchestrate.sh sbom.spdx.json
```

### SPDX Other Formats
```bash
# Get SPDX RDF/XML or tag-value from tool
syft packages . -o spdx > sbom.spdx

# Convert to JSON
pip install spdx-tools
spdx-tools convert sbom.spdx sbom.spdx.json

# Run pipeline
./orchestrate.sh sbom.spdx.json
```

---

## What Matters: PURLs

The fuzzing engines don't care about SBOM format—they need:

1. **Component name**
2. **Exact version** (to pin dependencies)
3. **PURL** (Package URL) to identify ecosystem

Example PURL formats:
- `pkg:npm/express@4.18.2` → JavaScript engine
- `pkg:pypi/requests@2.31.0` → Python engine
- `pkg:composer/symfony/yaml@7.0.0` → PHP engine
- `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0` → Java engine

As long as your SBOM includes PURLs (most modern tools do), the pipeline works.

---

## Format Auto-Detection

The `extract-components.py` script auto-detects formats:

```python
# Reads first 512 bytes
# XML → checks for CycloneDX namespaces vs SPDX markers
# JSON → checks for "spdxVersion" vs CycloneDX structure
```

No flags or configuration needed—just pass the file:
```bash
./orchestrate.sh path/to/any-sbom
```

---

## SPDX Limitations

### PURLs May Be Missing
Not all SPDX producers include PURLs in `externalRefs`. If missing, the toolkit tries to infer ecosystem from:
- `downloadLocation` (e.g., npmjs.org → npm)
- Package name patterns

This is best-effort. For best results:
- Use tools that emit PURLs (Syft, cdxgen)
- Or use CycloneDX format (PURLs are first-class)

### SPDX 3.x
Structure is different (`elements` vs `packages`). The toolkit handles both SPDX 2.x and 3.x JSON.

---

## Testing Format Support

```bash
# Test CycloneDX XML (your current SBOM)
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml

# Test SPDX JSON (example provided)
./orchestrate.sh test-sboms/example-spdx-2.3.json

# Test extraction directly
python3 extract-components.py path/to/sbom.xml
python3 extract-components.py path/to/sbom.json
python3 extract-components.py path/to/sbom.spdx.json
```

---

## Comparison: CycloneDX vs SPDX

| Feature | CycloneDX | SPDX |
|---------|-----------|------|
| **Security focus** | Yes | License focus (security added later) |
| **PURL support** | First-class (`purl` field) | Via externalRefs (optional) |
| **VEX integration** | Native | Via separate files |
| **Tool support** | Growing fast | Mature, widespread |
| **Complexity** | Simpler | More verbose |

**Recommendation:** Use CycloneDX for security pipelines (better PURL support, VEX integration). SPDX is fully supported if your org already uses it.

---

## Adding More Formats

Want to add another format? Extend `extract-components.py`:

1. Add detection logic in `main()`
2. Write `extract_<format>()` function
3. Return `[{"name": ..., "version": ..., "purl": ...}]`

That's it. The rest of the pipeline is format-agnostic.

---

## Summary

**Supported today:**
- ✅ CycloneDX XML (all versions)
- ✅ CycloneDX JSON (all versions)
- ✅ SPDX JSON (2.x and 3.x)
- ✅ SPDX RDF/XML (convert to JSON first)
- ✅ SPDX tag-value (convert to JSON first)

**How to use:**
```bash
# Just pass any supported format
./orchestrate.sh path/to/sbom
```

**Key requirement:**
- SBOM must include PURLs (or downloadLocation for inference)
- Most modern SBOM tools include PURLs by default

---

**Updated:** 2026-07-02  
**Status:** Multi-format support ready for production use
