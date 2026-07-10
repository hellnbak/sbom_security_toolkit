#!/usr/bin/env python3
"""Safe local Dependency-Track API workflow fuzzing scaffold.

Default mode is dry-run. It never attempts auth bypasses or non-local targets.
Use only against a local test Dependency-Track instance you control.
"""
from __future__ import annotations
import argparse, base64, json, urllib.request, urllib.error
from pathlib import Path

def local_only(url):
    return url.startswith("http://localhost") or url.startswith("http://127.0.0.1")

def request(method,url,headers=None,data=None,timeout=5):
    req=urllib.request.Request(url,method=method,headers=headers or {},data=data)
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            return {"status":r.status,"body":r.read(500).decode(errors="replace")}
    except Exception as e:
        return {"error":type(e).__name__,"message":str(e)[:500]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--base-url",default="http://localhost:8081"); ap.add_argument("--api-key",default=""); ap.add_argument("--sbom",default="test-sboms/clean/minimal-cyclonedx.json"); ap.add_argument("--dry-run",action="store_true"); ap.add_argument("--out",default="fuzzing/reports/dependency-track-api.json"); args=ap.parse_args()
    if not local_only(args.base_url): raise SystemExit("Refusing non-local Dependency-Track fuzz target. Use localhost/127.0.0.1 only.")
    payloads=[]
    sbom=Path(args.sbom).read_bytes() if Path(args.sbom).exists() else b"{}"
    payloads.append({"name":"valid-ish-bom","body":{"projectName":"sbom-fuzz-local","projectVersion":"0.0.0","autoCreate":True,"bom":base64.b64encode(sbom).decode()}})
    payloads.append({"name":"malformed-bom","body":{"projectName":"sbom-fuzz-local","projectVersion":"0.0.0","autoCreate":True,"bom":"not-base64"}})
    results=[]
    headers={"Content-Type":"application/json"}
    if args.api_key: headers["X-Api-Key"]=args.api_key
    if args.dry_run:
        results=[{"payload":p["name"],"dry_run":True,"endpoint":"POST /api/v1/bom"} for p in payloads]
    else:
        for p in payloads:
            results.append({"payload":p["name"],"response":request("POST",args.base_url.rstrip()+"/api/v1/bom",headers,json.dumps(p["body"]).encode())})
    out={"base_url":args.base_url,"dry_run":args.dry_run,"results":results}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(json.dumps(out,indent=2)+"\n"); print(json.dumps(out,indent=2))
if __name__=="__main__": main()
