#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, json, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "oracles"))
import semantic_oracles

def reorder(doc):
    out=copy.deepcopy(doc)
    for key in ("components","packages","dependencies","relationships","vulnerabilities"):
        if isinstance(out,dict) and isinstance(out.get(key),list):
            random.Random(42).shuffle(out[key])
    return out

def harmless_metadata(doc):
    out=copy.deepcopy(doc)
    if isinstance(out,dict):
        meta=out.setdefault("metadata",{})
        if isinstance(meta,dict): meta.setdefault("properties",[]).append({"name":"sbom-security-toolkit:metamorphic","value":"true"})
    return out

def minify_pretty(doc): return json.loads(json.dumps(doc,separators=(",",":")))
TRANSFORMS={"reorder":reorder,"harmless_metadata":harmless_metadata,"minify_pretty":minify_pretty}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("sbom"); ap.add_argument("--out-dir",default="fuzzing/reports/metamorphic"); args=ap.parse_args(); p=Path(args.sbom); out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    doc=json.loads(p.read_text(errors="replace")); reports=[]
    for name,fn in TRANSFORMS.items():
        transformed=fn(doc); tp=out/f"{p.stem}.{name}.json"; tp.write_text(json.dumps(transformed,indent=2,ensure_ascii=False)+"\n")
        findings=semantic_oracles.compare(doc,transformed)
        reports.append({"transform":name,"output":str(tp),"findings":findings,"passed":not any(f["severity"]=="fail" for f in findings)})
    report={"input":str(p),"transforms":reports,"passed":all(r["passed"] for r in reports)}
    (out/"metamorphic-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2)); sys.exit(1 if not report["passed"] else 0)
if __name__=="__main__": main()
