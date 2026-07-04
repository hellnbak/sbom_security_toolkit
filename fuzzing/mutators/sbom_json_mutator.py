#!/usr/bin/env python3
"""Structure-preserving SBOM mutators for CycloneDX/SPDX-like JSON.

These mutators intentionally keep most outputs parseable so fuzzing reaches
semantic parser/scanner paths instead of stopping at JSON decoding.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, random, sys
from pathlib import Path
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

EDGE_STRINGS = [
    "", " ", "0", "latest", "999999999999999999999.0.0", "1.0.0-alpha+build.☃",
    "../package", "pkg:npm/%40scope/name@1.0.0", "pkg:pypi/requests@2.31.0?arch=x86_64",
    "pkg:generic/name@version#subpath", "CVE-0000-0000", "GPL-2.0-only OR MIT AND Apache-2.0",
    "name\u0000with-null", "homoglyph-рackage", "very" + "-long" * 200,
]
LICENSES = ["MIT", "Apache-2.0", "GPL-2.0-only OR MIT", "NOASSERTION", "LicenseRef-Custom", "MIT AND", "((MIT OR Apache-2.0)"]
PURLS = [
    "pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.31.0", "pkg:maven/org.example/app@1.0.0",
    "pkg:deb/debian/openssl@1.1.1?arch=amd64", "pkg:golang/github.com/example/mod@v1.2.3",
    "pkg:nuget/Newtonsoft.Json@13.0.1", "pkg:unknown/name@", "pkg:npm/%zz@1.0.0",
]

def load_doc(data: bytes):
    return json.loads(data.decode("utf-8", errors="replace"))

def dump_doc(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n").encode()

def components(doc):
    if isinstance(doc, dict):
        if isinstance(doc.get("components"), list):
            return doc["components"]
        if isinstance(doc.get("packages"), list):
            return doc["packages"]
    return []

def mutate_component(comp: dict, rng: random.Random):
    choices = ["name", "version", "purl", "bom-ref", "license", "hash", "supplier"]
    field = rng.choice(choices)
    if field == "name": comp["name"] = rng.choice(EDGE_STRINGS)
    elif field == "version": comp["version"] = rng.choice(EDGE_STRINGS)
    elif field == "purl": comp["purl"] = rng.choice(PURLS)
    elif field == "bom-ref": comp["bom-ref"] = rng.choice([comp.get("bom-ref", "ref"), "duplicate-ref", rng.choice(EDGE_STRINGS)])
    elif field == "license":
        if "licenses" in comp:
            comp["licenses"] = [{"license": {"id": rng.choice(LICENSES)}}]
        else:
            comp["licenseDeclared"] = rng.choice(LICENSES)
    elif field == "hash":
        comp.setdefault("hashes", []).append({"alg": rng.choice(["SHA-256", "MD5", "UNKNOWN"]), "content": rng.choice(EDGE_STRINGS)})
    elif field == "supplier":
        comp["supplier"] = {"name": rng.choice(EDGE_STRINGS)}

def mutate_dependencies(doc: dict, rng: random.Random):
    deps = doc.setdefault("dependencies", [])
    comps = components(doc)
    refs = [c.get("bom-ref") or c.get("SPDXID") or c.get("name") for c in comps if isinstance(c, dict)] or ["root"]
    action = rng.choice(["cycle", "missing", "duplicate", "deep"])
    if action == "cycle" and len(refs) >= 2:
        deps.append({"ref": refs[0], "dependsOn": [refs[1]]})
        deps.append({"ref": refs[1], "dependsOn": [refs[0]]})
    elif action == "missing":
        deps.append({"ref": "missing-ref", "dependsOn": [rng.choice(refs)]})
    elif action == "duplicate":
        deps.append({"ref": rng.choice(refs), "dependsOn": [rng.choice(refs)]})
    else:
        last = "generated-root"
        for i in range(25):
            cur = f"generated-depth-{i}"
            deps.append({"ref": last, "dependsOn": [cur]})
            last = cur

def mutate_doc(doc, seed: int | None = None):
    rng = random.Random(seed)
    out = copy.deepcopy(doc)
    if not isinstance(out, dict):
        return out
    comps = components(out)
    if comps and rng.random() < 0.75:
        comp = rng.choice([c for c in comps if isinstance(c, dict)] or [{}])
        mutate_component(comp, rng)
    else:
        comps.append({"type": "library", "name": rng.choice(EDGE_STRINGS), "version": rng.choice(EDGE_STRINGS), "purl": rng.choice(PURLS), "bom-ref": "generated-" + hashlib.sha1(str(seed).encode()).hexdigest()[:8]})
    if rng.random() < 0.45:
        mutate_dependencies(out, rng)
    if rng.random() < 0.25:
        out.setdefault("vulnerabilities", []).append({"id": "CVE-2099-0001", "source": {"name": "example"}, "ratings": [{"score": 9.8, "method": "CVSSv3"}]})
    return out

def mutate(input_bytes: bytes, max_size: int = 1_000_000, seed: int | None = None) -> bytes:
    try:
        doc = load_doc(input_bytes)
    except Exception:
        return input_bytes[:max_size]
    return dump_doc(mutate_doc(doc, seed))[:max_size]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=25)
    args = ap.parse_args()
    src_path = Path(args.input)
    try:
        src = src_path.read_bytes()
        load_doc(src)
    except Exception:
        from fuzzing.common.sbom_load import load_json_or_normalized
        src = dump_doc(load_json_or_normalized(src_path))
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    for i in range(args.count):
        data = mutate(src, seed=i)
        (out / f"mutated-{i:04d}.json").write_bytes(data)
    print(f"wrote {args.count} mutations to {out}")
if __name__ == "__main__": main()
