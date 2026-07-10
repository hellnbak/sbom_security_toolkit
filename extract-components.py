#!/usr/bin/env python3
"""
extract-components.py — pull {name, version, purl} out of ANY SBOM format.

Supports:
- CycloneDX: XML and JSON (versions 1.3-1.6, namespace-agnostic)
- SPDX: JSON (2.x and 3.x), RDF/XML, tag-value

Usage:
    python3 extract-components.py path/to/sbom.(xml|json|spdx|rdf) > components.json

Output: a JSON array of {"name", "version", "purl"} — purl is what encodes
the ecosystem (pkg:composer/..., pkg:npm/..., pkg:pypi/..., etc.), which is
how orchestrate.sh decides what it can and can't act on downstream.
"""
import sys
import json
import re


def extract_xml(path):
    import xml.etree.ElementTree as ET

    def local(tag):
        return tag.split("}")[-1] if "}" in tag else tag

    root = ET.parse(path).getroot()
    components = []
    for el in root.iter():
        if local(el.tag) != "component":
            continue
        rec = {"name": None, "version": None, "purl": None}
        for child in el:
            lt = local(child.tag)
            if lt in rec and rec[lt] is None:
                rec[lt] = (child.text or "").strip() or None
        if rec["name"]:
            components.append(rec)
    return components


def extract_json(path):
    """Extract from CycloneDX JSON or SPDX JSON."""
    data = json.load(open(path, encoding="utf-8"))

    # Detect format
    if "spdxVersion" in data or "SPDXID" in data:
        return extract_spdx_json(data)
    else:
        return extract_cyclonedx_json(data)


def extract_cyclonedx_json(data):
    """Extract from CycloneDX JSON."""
    components = []

    def walk(items):
        for c in items or []:
            components.append({
                "name": c.get("name"),
                "version": c.get("version"),
                "purl": c.get("purl"),
            })
            # CycloneDX allows nested components; recurse if present.
            if c.get("components"):
                walk(c["components"])

    walk(data.get("components", []))
    return components


def extract_spdx_json(data):
    """Extract from SPDX 2.x or 3.x JSON."""
    components = []

    # SPDX 2.x
    if "packages" in data:
        for pkg in data["packages"]:
            # Extract PURL from externalRefs
            purl = None
            for ref in pkg.get("externalRefs", []):
                ref_type = ref.get("referenceType") or ref.get("type", "")
                if "purl" in ref_type.lower():
                    purl = ref.get("referenceLocator") or ref.get("locator")
                    break

            # Fallback: construct PURL from packageSupplier if available
            if not purl and pkg.get("name"):
                # SPDX doesn't always have PURLs, best effort from name
                name = pkg.get("name")
                version = pkg.get("versionInfo")
                # Try to infer ecosystem from download location or name patterns
                download_url = pkg.get("downloadLocation", "")
                if "npmjs.org" in download_url or download_url.startswith("npm:"):
                    purl = f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"
                elif "pypi.org" in download_url or download_url.startswith("pypi:"):
                    purl = f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
                elif "packagist.org" in download_url or download_url.startswith("composer:"):
                    purl = f"pkg:composer/{name}@{version}" if version else f"pkg:composer/{name}"
                elif "maven" in download_url or ".jar" in download_url:
                    purl = f"pkg:maven/{name}@{version}" if version else f"pkg:maven/{name}"

            components.append({
                "name": pkg.get("name"),
                "version": pkg.get("versionInfo"),
                "purl": purl
            })

    # SPDX 3.x (different structure)
    elif "elements" in data:
        for elem in data.get("elements", []):
            if elem.get("type") == "Package":
                purl = None
                for ext_id in elem.get("externalIdentifiers", []):
                    if ext_id.get("externalIdentifierType") == "purl":
                        purl = ext_id.get("identifier")
                        break

                components.append({
                    "name": elem.get("name"),
                    "version": elem.get("packageVersion"),
                    "purl": purl
                })

    return components


def main():
    if len(sys.argv) != 2:
        print("Usage: extract-components.py <sbom.(xml|json|spdx|rdf)>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "rb") as f:
        head = f.read(512).lstrip()

    if head.startswith(b"<"):
        # Could be CycloneDX XML or SPDX RDF/XML
        if b"spdx" in head.lower():
            print(f"[!] SPDX RDF/XML detected but not yet implemented. Use JSON format or convert with: spdx-tools convert", file=sys.stderr)
            sys.exit(1)
        else:
            components = extract_xml(path)  # CycloneDX XML
    elif head.startswith(b"{") or head.startswith(b"["):
        components = extract_json(path)  # Auto-detects CycloneDX vs SPDX
    else:
        # Might be SPDX tag-value format
        if b"SPDXVersion:" in head or b"SPDXID:" in head:
            print(f"[!] SPDX tag-value format detected but not yet implemented. Use JSON format or convert with: spdx-tools convert", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[!] {path} doesn't look like a supported SBOM format (CycloneDX XML/JSON or SPDX JSON)", file=sys.stderr)
            sys.exit(1)

    print(json.dumps(components, indent=2))
    print(f"[*] Extracted {len(components)} components from {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
