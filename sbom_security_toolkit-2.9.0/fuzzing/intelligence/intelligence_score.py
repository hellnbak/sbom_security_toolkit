#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, hashlib
from pathlib import Path
from datetime import datetime, timezone
ROOT = Path(__file__).resolve().parents[2]
SIGNALS = {"crash":35,"timeout":25,"semantic":30,"disagreement":28,"vex":18,"purl":12,"cpe":10,"dependency":12,"unicode":8,"duplicate":6,"license":8}
def sha(path: Path) -> str:
    h=hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()
def classify_text(text: str) -> list[str]:
    low=text.lower(); return [k for k in SIGNALS if k in low]
def score_file(path: Path) -> dict:
    try: data=path.read_text(errors='replace')[:200000]
    except Exception: data=''
    sigs=classify_text(path.name+'\n'+data); score=sum(SIGNALS[s] for s in sigs)
    if path.suffix.lower() in {'.json','.xml','.spdx','.txt'}: score += 5
    if len(data) > 5000: score += 3
    if 'bom-ref' in data or 'SPDXID' in data: score += 4
    return {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path), "sha256": sha(path), "score": min(score,100), "signals": sigs, "size": path.stat().st_size}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Rank fuzzing inputs/findings by usefulness')
    ap.add_argument('--inputs', nargs='*', default=['fuzzing/findings','fuzzing/generated-corpus','fuzzing/regression','test-sboms'])
    ap.add_argument('--out-dir', default='reports/fuzzing/intelligence')
    ns=ap.parse_args(argv); candidates=[]
    for raw in ns.inputs:
        p=Path(raw); p=ROOT/p if not p.is_absolute() else p
        if p.is_file(): candidates.append(score_file(p))
        elif p.exists():
            for f in p.rglob('*'):
                if f.is_file() and f.name != '.gitkeep' and f.stat().st_size < 5_000_000: candidates.append(score_file(f))
    candidates.sort(key=lambda x:(x['score'], x['size']), reverse=True)
    out=ROOT/ns.out_dir; out.mkdir(parents=True, exist_ok=True)
    report={"generated_at": datetime.now(timezone.utc).isoformat(), "items": candidates[:250], "summary": {"items_scored": len(candidates), "high_value": sum(1 for c in candidates if c['score']>=50)}}
    (out/'intelligence.json').write_text(json.dumps(report,indent=2)+'\n')
    lines=['# Fuzzing Intelligence Scorecard','',f"Items scored: {len(candidates)}",'','| Score | Signals | Path |','|---:|---|---|']
    for c in candidates[:50]: lines.append(f"| {c['score']} | {', '.join(c['signals']) or '-'} | `{c['path']}` |")
    (out/'intelligence.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps(report['summary'], indent=2))
if __name__=='__main__': main()
