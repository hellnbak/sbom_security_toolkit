#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from fuzzing.intelligence.intelligence_score import score_file
def recommendation(score:int, signals:list[str], dup:bool=False)->str:
    if dup: return 'duplicate'
    if score>=65 or 'crash' in signals or 'semantic' in signals: return 'promote-to-regression'
    if score>=35 or 'disagreement' in signals: return 'keep-for-nightly'
    if score>=15: return 'needs-human-review'
    return 'reject-noise'
def main(argv=None):
    ap=argparse.ArgumentParser(description='Recommend corpus promotion actions')
    ap.add_argument('--corpus', default='fuzzing/corpus/ai/incoming')
    ap.add_argument('--out-dir', default='reports/fuzzing/corpus-recommendations')
    ap.add_argument('--apply', action='store_true')
    ns=ap.parse_args(argv); corpus=ROOT/ns.corpus; out=ROOT/ns.out_dir; out.mkdir(parents=True, exist_ok=True)
    seen={}; rows=[]
    if corpus.exists():
        for f in corpus.rglob('*'):
            if not f.is_file() or f.name=='.gitkeep': continue
            item=score_file(f); dup=item['sha256'] in seen; seen[item['sha256']]=item['path']; item['recommendation']=recommendation(item['score'], item['signals'], dup); rows.append(item)
            if ns.apply and item['recommendation']=='promote-to-regression':
                dest=ROOT/'fuzzing/regression/corpus/recommended'/f.name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(f,dest)
    rows.sort(key=lambda r:r['score'], reverse=True)
    (out/'recommendations.json').write_text(json.dumps({'items':rows},indent=2)+'\n')
    md=['# Corpus Promotion Recommendations','','| Recommendation | Score | Signals | Path |','|---|---:|---|---|']
    for r in rows: md.append(f"| {r['recommendation']} | {r['score']} | {', '.join(r['signals']) or '-'} | `{r['path']}` |")
    (out/'recommendations.md').write_text('\n'.join(md)+'\n')
    print(f"recommendations written to {out}")
if __name__=='__main__': main()
