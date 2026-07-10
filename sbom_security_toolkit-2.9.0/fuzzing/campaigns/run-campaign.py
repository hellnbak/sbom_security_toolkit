#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path
try:
    import yaml
except Exception:
    yaml=None

def load(path):
    text=Path(path).read_text()
    if yaml: return yaml.safe_load(text)
    # tiny fallback for simple profiles
    data={}
    for line in text.splitlines():
        if ":" in line and not line.startswith(" "):
            k,v=line.split(":",1); data[k.strip()]=v.strip()
    return data

def run(cmd, allow_fail=True):
    print("+", " ".join(cmd))
    p=subprocess.run(cmd, text=True, capture_output=True)
    return {"cmd":cmd,"returncode":p.returncode,"stdout":p.stdout[-4000:],"stderr":p.stderr[-4000:],"passed":p.returncode==0 or allow_fail}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("profile"); ap.add_argument("--out-dir",default="fuzzing/reports/campaigns"); args=ap.parse_args()
    prof=load(args.profile); out=Path(args.out_dir)/prof.get("name",Path(args.profile).stem); out.mkdir(parents=True,exist_ok=True)
    seed=prof.get("seed_sbom","test-sboms/clean/minimal-cyclonedx.json"); muts=str(prof.get("mutations",25)); started=time.time(); results=[]
    steps=prof.get("steps",[]) or []
    if "structured-mutate" in steps: results.append(run(["python3","fuzzing/mutators/sbom_json_mutator.py",seed,"--out",str(out/"mutations"),"--count",muts]))
    if "purl-mutate" in steps: results.append(run(["python3","fuzzing/mutators/purl_mutator.py","--out",str(out/"purl"),"--count",muts]))
    if "license-mutate" in steps: results.append(run(["python3","fuzzing/mutators/license_expression_mutator.py","--out",str(out/"licenses"),"--count",muts]))
    if "semantic-oracles" in steps: results.append(run(["python3","fuzzing/oracles/semantic_oracles.py",seed], allow_fail=True))
    if "roundtrip" in steps: results.append(run(["python3","fuzzing/roundtrip/roundtrip_sbom.py",seed,"--out-dir",str(out/"roundtrip")], allow_fail=True))
    if "metamorphic" in steps: results.append(run(["python3","fuzzing/metamorphic/metamorphic_sbom.py",seed,"--out-dir",str(out/"metamorphic")], allow_fail=True))
    if "malicious-metadata" in steps: results.append(run(["python3","fuzzing/malicious-metadata/generate_scenarios.py","--out",str(out/"malicious-metadata")]))
    if "health-check" in steps: results.append(run(["python3","fuzzing/api/dependency_track_api_fuzz.py","--base-url",prof.get("base_url","http://localhost:8081"),"--dry-run","--out",str(out/"dependency-track-api.json")]))
    report={"profile":prof,"elapsed_seconds":round(time.time()-started,2),"results":results,"passed":all(r["passed"] for r in results)}
    (out/"campaign-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2)); sys.exit(0 if report["passed"] else 1)
if __name__=="__main__": main()
