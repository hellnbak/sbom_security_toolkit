#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "oracles"))
import semantic_oracles

def normalize(doc):
    # Basic normalizer: sort keys and preserve document shape. This is a harness
    # point for future CycloneDX/SPDX JSON<->XML/tag-value conversions.
    return json.loads(json.dumps(doc, sort_keys=True, ensure_ascii=False))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("sbom"); ap.add_argument("--out-dir",default="fuzzing/reports/roundtrip"); args=ap.parse_args()
    p=Path(args.sbom); out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    doc=json.loads(p.read_text(errors="replace")); norm=normalize(doc)
    roundtrip=out/(p.stem+".roundtrip.json"); roundtrip.write_text(json.dumps(norm,indent=2,ensure_ascii=False)+"\n")
    findings=semantic_oracles.check(doc)+semantic_oracles.compare(doc,norm)
    report={"input":str(p),"roundtrip":str(roundtrip),"findings":findings,"passed":not any(f["severity"]=="fail" for f in findings)}
    (out/"roundtrip-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2)); sys.exit(1 if not report["passed"] else 0)
if __name__=="__main__": main()
