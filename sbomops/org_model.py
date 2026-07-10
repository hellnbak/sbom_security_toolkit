#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
import yaml

def main(argv=None):
 ap=argparse.ArgumentParser(description='Manage organization/application/service/repository/artifact security context.'); sub=ap.add_subparsers(dest='cmd',required=True)
 p=sub.add_parser('validate'); p.add_argument('file')
 p=sub.add_parser('context'); p.add_argument('file'); p.add_argument('--repository',required=True); p.add_argument('--out',default='reports/context.json')
 a=ap.parse_args(argv); d=yaml.safe_load(Path(a.file).read_text()) or {}; errors=[]
 for k in ('organization','businessUnits'):
  if k not in d: errors.append(f'missing {k}')
 if a.cmd=='validate': print(json.dumps({'valid':not errors,'errors':errors},indent=2)); return 0 if not errors else 4
 found=None
 for bu in d.get('businessUnits',[]):
  for app in bu.get('applications',[]):
   for svc in app.get('services',[]):
    for repo in svc.get('repositories',[]):
     if repo.get('name')==a.repository or repo.get('url')==a.repository:
      found={**d.get('defaults',{}),**bu.get('context',{}),**app.get('context',{}),**svc.get('context',{}),**repo.get('context',{}),'organization':d.get('organization'),'business_unit':bu.get('name'),'application':app.get('name'),'service':svc.get('name'),'repository':repo.get('name')}
 if not found: raise SystemExit('repository not found')
 Path(a.out).parent.mkdir(parents=True,exist_ok=True); Path(a.out).write_text(json.dumps(found,indent=2)+'\n'); print(a.out); return 0
if __name__=='__main__': raise SystemExit(main())
