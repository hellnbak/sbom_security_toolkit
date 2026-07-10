#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, uuid
from datetime import datetime, timezone
from pathlib import Path
import yaml

def now(): return datetime.now(timezone.utc).isoformat()
def read(path):
    p=Path(path); return yaml.safe_load(p.read_text()) if p.exists() else {'apiVersion':'sbom-toolkit.io/v1','kind':'RiskExceptionList','exceptions':[]}
def write(path,data): Path(path).parent.mkdir(parents=True,exist_ok=True); Path(path).write_text(yaml.safe_dump(data,sort_keys=False))
def main(argv=None):
    ap=argparse.ArgumentParser(description='Manage auditable, expiring risk exceptions.'); sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('create'); p.add_argument('--store',default='governance/exceptions.yml'); p.add_argument('--project',required=True); p.add_argument('--vulnerability'); p.add_argument('--component'); p.add_argument('--purl'); p.add_argument('--rule'); p.add_argument('--justification',required=True); p.add_argument('--compensating-control',action='append',default=[]); p.add_argument('--requestor',required=True); p.add_argument('--expires',required=True)
    p=sub.add_parser('approve'); p.add_argument('id'); p.add_argument('--store',default='governance/exceptions.yml'); p.add_argument('--approver',required=True)
    p=sub.add_parser('revoke'); p.add_argument('id'); p.add_argument('--store',default='governance/exceptions.yml'); p.add_argument('--actor',required=True); p.add_argument('--reason',required=True)
    p=sub.add_parser('list'); p.add_argument('--store',default='governance/exceptions.yml'); p.add_argument('--json',action='store_true')
    a=ap.parse_args(argv); d=read(a.store); items=d.setdefault('exceptions',[])
    if a.cmd=='create':
        ident='RISK-'+datetime.now().strftime('%Y%m%d')+'-'+uuid.uuid4().hex[:6].upper(); e={'metadata':{'id':ident,'created_at':now()},'spec':{'project':a.project,'vulnerability':a.vulnerability,'component':a.component,'purl':a.purl,'rule':a.rule,'justification':a.justification,'compensatingControls':a.compensating_control,'requestor':a.requestor,'expires':a.expires,'status':'requested','history':[{'at':now(),'actor':a.requestor,'action':'created'}]}}; items.append(e); write(a.store,d); print(ident); return 0
    target=next((e for e in items if e.get('metadata',{}).get('id')==getattr(a,'id',None)),None)
    if a.cmd in {'approve','revoke'} and not target: raise SystemExit('exception not found')
    if a.cmd=='approve': target['spec'].update({'status':'approved','approvedBy':a.approver,'approvedAt':now()}); target['spec'].setdefault('history',[]).append({'at':now(),'actor':a.approver,'action':'approved'}); write(a.store,d); return 0
    if a.cmd=='revoke': target['spec'].update({'status':'revoked','revokedBy':a.actor,'revokedAt':now(),'revocationReason':a.reason}); target['spec'].setdefault('history',[]).append({'at':now(),'actor':a.actor,'action':'revoked','reason':a.reason}); write(a.store,d); return 0
    active=[]
    for e in items:
        exp=e.get('spec',{}).get('expires'); expired=False
        try: expired=datetime.fromisoformat(str(exp).replace('Z','+00:00'))<=datetime.now(timezone.utc)
        except Exception: pass
        x=json.loads(json.dumps(e)); x['expired']=expired; active.append(x)
    print(json.dumps(active,indent=2) if a.json else '\n'.join(f"{e['metadata']['id']}\t{e['spec']['status']}\t{e['spec']['project']}\texpires={e['spec']['expires']}" for e in active)); return 0
if __name__=='__main__': raise SystemExit(main())
