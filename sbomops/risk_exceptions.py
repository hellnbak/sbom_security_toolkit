#!/usr/bin/env python3
from __future__ import annotations
import argparse, secrets
from pathlib import Path
from typing import Any
from .release_common import load_data, now, parse_time, write_yaml
DEFAULT=Path('governance/exceptions.yml')

def _db(path: Path)->dict[str,Any]:
    d=load_data(path,{}) or {}
    if isinstance(d,list): d={'exceptions':d}
    d.setdefault('version',1); d.setdefault('exceptions',[])
    return d

def _save(path:Path,d:dict[str,Any]): write_yaml(path,d)
def _id()->str: return 'RISK-'+now()[:10].replace('-','')+'-'+secrets.token_hex(3).upper()
def _find(d,eid):
    for x in d['exceptions']:
        if x.get('id')==eid:return x
    raise SystemExit(f'exception not found: {eid}')
def _active(x):
    if x.get('status')!='approved': return False
    exp=parse_time(x.get('expires'))
    from datetime import datetime, timezone
    return not exp or exp>datetime.now(timezone.utc)

def create(a):
    p=Path(a.store); d=_db(p)
    item={'id':_id(),'status':'requested','created_at':now(),'updated_at':now(),'project':a.project or '',
          'vulnerability':a.vulnerability or '','component':a.component or '','purl':a.purl or '',
          'policy_rule':a.policy_rule or '','environment':a.environment or '',
          'requestor':a.requestor,'approver':'','justification':a.justification,
          'compensating_controls':a.compensating_control or [],'expires':a.expires,'history':[{'at':now(),'action':'created','actor':a.requestor}]}
    d['exceptions'].append(item); _save(p,d); return item

def transition(a,status,actor_field):
    p=Path(a.store);d=_db(p);x=_find(d,a.id);actor=getattr(a,actor_field)
    x['status']=status;x['updated_at']=now();x[actor_field]=actor
    x.setdefault('history',[]).append({'at':now(),'action':status,'actor':actor,'reason':getattr(a,'reason','')})
    _save(p,d);return x

def list_items(a):
    d=_db(Path(a.store)); items=d['exceptions']
    if a.status: items=[x for x in items if x.get('status')==a.status]
    for x in items: x['effective']=_active(x)
    return {'count':len(items),'exceptions':items}

def expire(a):
    from datetime import datetime,timezone
    p=Path(a.store);d=_db(p);n=0
    for x in d['exceptions']:
        exp=parse_time(x.get('expires'))
        if x.get('status')=='approved' and exp and exp<=datetime.now(timezone.utc):
            x['status']='expired';x['updated_at']=now();x.setdefault('history',[]).append({'at':now(),'action':'expired','actor':'system'});n+=1
    _save(p,d);return {'expired':n}

def parser():
    ap=argparse.ArgumentParser(description='Manage auditable, time-bound risk exceptions')
    ap.add_argument('--store',default=str(DEFAULT)); sp=ap.add_subparsers(dest='cmd',required=True)
    c=sp.add_parser('create'); c.add_argument('--project');c.add_argument('--vulnerability');c.add_argument('--component');c.add_argument('--purl');c.add_argument('--policy-rule');c.add_argument('--environment');c.add_argument('--justification',required=True);c.add_argument('--compensating-control',action='append');c.add_argument('--requestor',required=True);c.add_argument('--expires',required=True);c.set_defaults(fn=create)
    for name,status,actor in [('approve','approved','approver'),('revoke','revoked','approver'),('reject','rejected','approver')]:
        s=sp.add_parser(name);s.add_argument('id');s.add_argument(f'--{actor}',required=True);s.add_argument('--reason',default='');s.set_defaults(fn=lambda a,st=status,ac=actor:transition(a,st,ac))
    l=sp.add_parser('list');l.add_argument('--status');l.set_defaults(fn=list_items)
    e=sp.add_parser('expire');e.set_defaults(fn=expire)
    return ap

def main(argv=None):
    import json
    a=parser().parse_args(argv);r=a.fn(a);print(json.dumps(r,indent=2,sort_keys=True));return 0
if __name__=='__main__': raise SystemExit(main())
