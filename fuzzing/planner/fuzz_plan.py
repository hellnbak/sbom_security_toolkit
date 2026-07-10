#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path

DB=Path('reports/fuzzing/fuzz-kb.sqlite')

def main():
    ap=argparse.ArgumentParser(description='Recommend next local fuzzing campaigns from KB/status data.')
    ap.add_argument('--db', default=str(DB)); ap.add_argument('--out', default='reports/fuzzing/fuzz-plan.md')
    args=ap.parse_args(); db=Path(args.db)
    recs=[]
    if db.exists():
        con=sqlite3.connect(db); cur=con.cursor()
        by_type=cur.execute('SELECT finding_type,count(*) FROM findings GROUP BY finding_type').fetchall()
        if by_type: recs.append(('semantic-oracle-expansion', 'Existing findings indicate semantic oracles are producing useful signal.'))
        cov=cur.execute('SELECT target, avg(new_paths), max(created_at) FROM coverage_snapshots GROUP BY target').fetchall()
        for target, paths, _ in cov:
            if (paths or 0) <= 1: recs.append((f'{target}-corpus-refresh', 'Low recent new-path yield; add schema-aware and AI-reviewed seeds.'))
    if not recs:
        recs=[
          ('scanner-metamorphic', 'Good default: detects format sensitivity across scanners.'),
          ('truthset', 'Run curated truth-set to benchmark expected vulnerability behavior.'),
          ('dependency-track-stateful', 'Exercise local import/poll/findings workflow in dry-run/local mode.'),
        ]
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    md=['# Recommended Fuzzing Plan','']
    for i,(name,reason) in enumerate(recs,1): md.append(f'{i}. **{name}** — {reason}')
    out.write_text('\n'.join(md)+'\n')
    print(out)
if __name__=='__main__': main()
