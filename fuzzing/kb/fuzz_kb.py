#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = Path(__file__).with_name('schema.sql')
DEFAULT_DB = Path('reports/fuzzing/fuzz-kb.sqlite')

def now(): return datetime.now(timezone.utc).isoformat()
def sha256_file(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
def db(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    con=sqlite3.connect(path)
    con.executescript(SCHEMA.read_text())
    return con

def cmd_init(args):
    con=db(Path(args.db)); con.close(); print(f"initialized {args.db}")

def cmd_add_corpus(args):
    con=db(Path(args.db)); p=Path(args.path); h=sha256_file(p)
    con.execute('INSERT OR REPLACE INTO corpus_entries VALUES (?,?,?,?,?,?)', (h, str(p), args.format, args.source, now(), json.dumps({})))
    con.commit(); print(json.dumps({'sha256':h,'path':str(p)}, indent=2))

def cmd_add_finding(args):
    con=db(Path(args.db)); fid=args.id or 'FIND-'+uuid.uuid4().hex[:10]
    con.execute('INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)', (fid,args.campaign,args.type,args.target,args.severity,args.input_sha256,args.fingerprint,args.summary,args.artifact,now(),json.dumps({})))
    con.commit(); print(fid)

def cmd_summary(args):
    con=db(Path(args.db)); cur=con.cursor()
    summary={}
    for name in ['campaigns','corpus_entries','findings','coverage_snapshots','ai_suggestions']:
        summary[name]=cur.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
    findings=cur.execute('SELECT finding_type,count(*) FROM findings GROUP BY finding_type').fetchall()
    summary['findings_by_type']={k:v for k,v in findings}
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))

def main():
    ap=argparse.ArgumentParser(description='Local fuzzing knowledge base')
    ap.add_argument('--db', default=str(DEFAULT_DB))
    sub=ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init').set_defaults(func=cmd_init)
    p=sub.add_parser('add-corpus'); p.add_argument('path'); p.add_argument('--format', default='unknown'); p.add_argument('--source', default='manual'); p.set_defaults(func=cmd_add_corpus)
    p=sub.add_parser('add-finding'); p.add_argument('--id'); p.add_argument('--campaign', default='manual'); p.add_argument('--type', default='semantic'); p.add_argument('--target', default='unknown'); p.add_argument('--severity', default='info'); p.add_argument('--input-sha256', default=''); p.add_argument('--fingerprint', default=''); p.add_argument('--summary', default=''); p.add_argument('--artifact', default=''); p.set_defaults(func=cmd_add_finding)
    p=sub.add_parser('summary'); p.add_argument('--out', default='reports/fuzzing/fuzz-kb-summary.json'); p.set_defaults(func=cmd_summary)
    args=ap.parse_args(); args.func(args)
if __name__=='__main__': main()
