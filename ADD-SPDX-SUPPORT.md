# Adding SPDX Format Support

The toolkit currently supports CycloneDX (XML/JSON). To add SPDX:

## Option 1: Convert SPDX → CycloneDX (Recommended)

Use existing converters:

```bash
# Using cyclonedx-cli
cyclonedx convert --input-file sbom.spdx.json --output-file sbom.cdx.json --input-format spdxjson --output-format json

# Then run normally
./orchestrate.sh sbom.cdx.json
```

**Pro:** No code changes needed  
**Con:** Extra step

## Option 2: Add Native SPDX Parsing

Modify `extract-components.py`:

```python
def extract_spdx_json(path):
    """Extract components from SPDX 2.x JSON."""
    with open(path) as f:
        doc = json.load(f)
    
    components = []
    for pkg in doc.get('packages', []):
        # SPDX uses externalRefs for PURLs
        purl = None
        for ref in pkg.get('externalRefs', []):
            if ref.get('referenceType') == 'purl':
                purl = ref.get('referenceLocator')
                break
        
        components.append({
            'name': pkg.get('name'),
            'version': pkg.get('versionInfo'),
            'purl': purl
        })
    
    return components

def extract_spdx_rdf(path):
    """Extract components from SPDX RDF/XML."""
    # Parse RDF/XML using rdflib
    # Extract packages and PURLs
    # Return same structure
    pass

def main():
    path = sys.argv[1]
    
    # Auto-detect format
    if path.endswith('.xml'):
        components = extract_xml(path)  # CycloneDX XML
    elif path.endswith('.json'):
        with open(path) as f:
            data = json.load(f)
        if 'spdxVersion' in data:
            components = extract_spdx_json(path)
        else:
            components = extract_json(path)  # CycloneDX JSON
    elif path.endswith('.rdf'):
        components = extract_spdx_rdf(path)
    
    print(json.dumps(components, indent=2))
```

**Pro:** Native support, one less step  
**Con:** Maintenance burden, SPDX has multiple formats

## Option 3: Use PURL Directly

If you already have PURLs extracted:

```bash
# Create components.json manually
cat > components.json << 'EOF'
[
  {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
  {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
]
EOF

# Run ecosystem detection
python3 fuzzing/detect-ecosystems.py components.json

# Run fuzzing engines manually
cd fuzzing/engines/javascript && docker build -t sbom-fuzzer-javascript . && docker run --rm ...
```

## What Matters Most

The fuzzing engines don't care about SBOM format — they only need:
1. **Component name**
2. **Exact version** (to pin dependencies)
3. **PURL** (to know which ecosystem)

As long as you can extract those three fields, the rest of the pipeline works unchanged.

---

**Recommendation:** Use Option 1 (convert SPDX → CycloneDX) until there's demand for native SPDX. The converter is maintained by the CycloneDX team and handles edge cases.
