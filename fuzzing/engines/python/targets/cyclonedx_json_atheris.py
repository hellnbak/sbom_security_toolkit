#!/usr/bin/env python3
"""Atheris target for CycloneDX JSON SBOM parsing and graph traversal."""
import atheris
import json
import sys
MAX_BYTES = 250_000
MAX_COMPONENTS = 5_000

def _walk_dependencies(doc):
    deps = doc.get("dependencies", [])
    if not isinstance(deps, list):
        return
    refs = set()
    for dep in deps[:MAX_COMPONENTS]:
        if not isinstance(dep, dict):
            continue
        ref = dep.get("ref")
        if isinstance(ref, str):
            refs.add(ref[:512])
        depends_on = dep.get("dependsOn", [])
        if isinstance(depends_on, list):
            for item in depends_on[:250]:
                if isinstance(item, str):
                    refs.add(item[:512])
    sorted(refs)

def TestOneInput(data: bytes) -> None:
    if len(data) > MAX_BYTES:
        return
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(doc, dict):
        return
    if doc.get("bomFormat") not in (None, "CycloneDX"):
        return
    components = doc.get("components", [])
    if isinstance(components, list):
        for component in components[:MAX_COMPONENTS]:
            if not isinstance(component, dict):
                continue
            for field in ("type", "name", "version", "purl", "bom-ref"):
                value = component.get(field)
                if isinstance(value, str):
                    value.encode("utf-8", errors="strict")
            licenses = component.get("licenses", [])
            if isinstance(licenses, list):
                str(licenses[:50])
    _walk_dependencies(doc)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
