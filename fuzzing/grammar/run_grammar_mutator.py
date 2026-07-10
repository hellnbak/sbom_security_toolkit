#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, random
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SAMPLES={'cyclonedx':['{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}'],'spdx':['SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nPackageName: example\nPackageVersion: 1.0.0\n'],'purl':['pkg:pypi/example@1.0.0','pkg:npm/%40scope/name@0.0.1','pkg:maven/group/artifact@1.2.3'],'license':['MIT','Apache-2.0 OR MIT','GPL-2.0-only WITH Classpath-exception-2.0'],'vex':['{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[{"id":"CVE-2099-0001","analysis":{"state":"not_affected","justification":"code_not_present"}}]}']}
def mutate(s,i):
    ops=[lambda x:x.replace('example',f'example-{i}'), lambda x:x+'\n', lambda x:x.replace('1.0.0','9999.0.0-alpha+'+str(i)), lambda x:x.replace('MIT','NOASSERTION')]; return random.choice(ops)(s)
def main(argv=None):
    ap=argparse.ArgumentParser(description='Runnable grammar-mutator scaffold'); ap.add_argument('--grammar', choices=sorted(SAMPLES), default='cyclonedx'); ap.add_argument('--count', type=int, default=25); ap.add_argument('--out', default='fuzzing/generated-corpus/grammar'); ns=ap.parse_args(argv)
    out=ROOT/ns.out; out.mkdir(parents=True,exist_ok=True)
    for i in range(ns.count):
        seed=random.choice(SAMPLES[ns.grammar]); data=mutate(seed,i); ext='json' if ns.grammar in {'cyclonedx','vex'} else 'txt'; (out/f'{ns.grammar}-{i:04d}.{ext}').write_text(data)
    manifest={'grammar':ns.grammar,'count':ns.count,'out':str(out.relative_to(ROOT)),'note':'Scaffold mode; can be wired to AFL++ Grammar-Mutator.'}; (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n'); print(json.dumps(manifest, indent=2))
if __name__=='__main__': main()
