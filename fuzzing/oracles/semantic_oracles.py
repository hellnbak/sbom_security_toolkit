#!/usr/bin/env python3
"""Semantic oracles for SBOM fuzzing.

These checks detect silent data loss and suspicious behavior that may not cause
process crashes.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

def load(path: Path):
    try:
        from fuzzing.common.sbom_load import load_json_or_normalized
        return load_json_or_normalized(path)
    except Exception as exc:
        raise ValueError(f"semantic oracles could not parse or normalize input: {exc}") from exc

def comps(doc):
    if isinstance(doc, dict):
        return doc.get("components") or doc.get("packages") or []
    return []

def deps(doc):
    if isinstance(doc, dict):
        return doc.get("dependencies") or doc.get("relationships") or []
    return []

def ids(doc):
    vals=[]
    for c in comps(doc):
        if isinstance(c, dict): vals.append(c.get("bom-ref") or c.get("SPDXID") or c.get("purl") or c.get("name"))
    return [v for v in vals if v]

def check(doc):
    findings=[]
    c=comps(doc); d=deps(doc); identifiers=ids(doc)
    if not c: findings.append({"severity":"warn","oracle":"components_present","message":"No components/packages found"})
    if len(identifiers) != len(set(identifiers)): findings.append({"severity":"fail","oracle":"unique_component_identity","message":"Duplicate component identifiers detected"})
    missing_version=sum(1 for x in c if isinstance(x,dict) and not x.get("version") and not x.get("versionInfo"))
    if c and missing_version/len(c) > 0.5: findings.append({"severity":"warn","oracle":"version_completeness","message":"More than 50% of components lack versions"})
    refs=set(identifiers)
    for dep in d:
        if not isinstance(dep,dict): continue
        ref=dep.get("ref") or dep.get("spdxElementId")
        if ref and refs and ref not in refs and not str(ref).startswith("generated"):
            findings.append({"severity":"warn","oracle":"dependency_ref_exists","message":f"Dependency references unknown component: {ref}"})
    return findings

def compare(before, after):
    findings=[]
    bc, ac = len(comps(before)), len(comps(after))
    if ac < bc:
        findings.append({"severity":"fail","oracle":"no_silent_component_drop","message":f"Component count dropped from {bc} to {ac}"})
    bd, ad = len(deps(before)), len(deps(after))
    if ad < bd:
        findings.append({"severity":"warn","oracle":"no_silent_dependency_drop","message":f"Dependency count dropped from {bd} to {ad}"})
    b_ids, a_ids = set(ids(before)), set(ids(after))
    lost = sorted(b_ids - a_ids)[:20]
    if lost:
        findings.append({"severity":"fail","oracle":"component_identity_preserved","message":f"Lost component identities: {lost}"})
    return findings

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("input"); ap.add_argument("--after"); ap.add_argument("--out"); args=ap.parse_args()
    doc=load(Path(args.input)); findings=check(doc)
    if args.after: findings += compare(doc, load(Path(args.after)))
    out={"input":args.input,"after":args.after,"findings":findings,"passed":not any(f["severity"]=="fail" for f in findings)}
    text=json.dumps(out,indent=2)
    if args.out: Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(text+"\n")
    print(text)
    sys.exit(1 if not out["passed"] else 0)
if __name__=="__main__": main()
