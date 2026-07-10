#!/usr/bin/env python3
"""Atheris target for SPDX JSON parsing and relationship traversal."""
import atheris
import json
import sys
MAX_BYTES = 250_000
MAX_PACKAGES = 5_000

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
    if "spdxVersion" in doc and not str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        return
    ids = set()
    packages = doc.get("packages", [])
    if isinstance(packages, list):
        for package in packages[:MAX_PACKAGES]:
            if not isinstance(package, dict):
                continue
            spdxid = package.get("SPDXID")
            if isinstance(spdxid, str):
                ids.add(spdxid[:512])
            for field in ("name", "versionInfo", "licenseConcluded", "licenseDeclared", "downloadLocation"):
                value = package.get(field)
                if isinstance(value, str):
                    value.encode("utf-8", errors="strict")
    relationships = doc.get("relationships", [])
    if isinstance(relationships, list):
        for rel in relationships[:MAX_PACKAGES]:
            if not isinstance(rel, dict):
                continue
            a = rel.get("spdxElementId"); b = rel.get("relatedSpdxElement"); t = rel.get("relationshipType")
            if isinstance(a, str) and isinstance(b, str) and isinstance(t, str):
                hash((a[:512], t[:128], b[:512]))
    sorted(ids)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
