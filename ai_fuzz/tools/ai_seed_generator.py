#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from ai_fuzz.tools.providers import render_or_call
ROOT=Path(__file__).resolve().parents[2]
TEMPLATE = '''#!/usr/bin/env python3
import json, argparse
from pathlib import Path
def make_seed(i):
    return {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":f"edge-case-{i}","version":"1.0.0","bom-ref":f"pkg:pypi/edge-case-{i}@1.0.0","purl":f"pkg:pypi/edge-case-{i}@1.0.0"}],"dependencies":[{"ref":f"pkg:pypi/edge-case-{i}@1.0.0","dependsOn":[]}]}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--count",type=int,default=5); ap.add_argument("--out",default="fuzzing/corpus/ai/incoming/generated-seeds")
    ns=ap.parse_args(); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    for i in range(ns.count): (out/f"seed-{i:03d}.json").write_text(json.dumps(make_seed(i),indent=2)+"\\n")
if __name__=="__main__": main()
'''
def main(argv=None):
    ap=argparse.ArgumentParser(description='Ask AI to synthesize a seed generator draft'); ap.add_argument('--goal', default='vex-logic-errors'); ap.add_argument('--provider', default='none'); ap.add_argument('--model', default=''); ap.add_argument('--out-dir', default='ai_fuzz/review/incoming/generators'); ns=ap.parse_args(argv)
    out=ROOT/ns.out_dir; out.mkdir(parents=True, exist_ok=True); prompt=f"Generate a safe Python SBOM seed generator for goal: {ns.goal}. It must not use network, subprocesses, or secrets. Output Python only."
    response=render_or_call(ns.provider,prompt,model=ns.model); draft=out/(ns.goal.replace(' ','-').replace('/','-')+'_generator.py')
    draft.write_text(response if response.strip().startswith('#!') or 'def ' in response else TEMPLATE)
    manifest={'goal':ns.goal,'draft':str(draft.relative_to(ROOT)),'review_required':True,'note':'Run ai-seed-generator-test before promoting.'}; (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n'); print(json.dumps(manifest, indent=2))
if __name__=='__main__': main()
