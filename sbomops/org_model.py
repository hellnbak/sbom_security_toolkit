#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
from .release_common import load_data, now, write_yaml
TEMPLATE={'version':1,'organization':{'id':'example-org','name':'Example Organization'},'business_units':[{'id':'engineering','name':'Engineering'}],'applications':[{'id':'payments','name':'Payments','business_unit':'engineering','owners':{'technical':'team@example.invalid','security':'security@example.invalid'},'business_criticality':'high','data_classification':'confidential','regulatory_scope':[]}],'services':[{'id':'payments-api','application':'payments','repository':'org/payments-api','environment':'production','internet_exposed':True,'support_tier':'tier-1'}]}
def validate(d):
    errors=[]; ids={}
    for section in ('business_units','applications','services','artifacts'):
        for x in d.get(section,[]) or []:
            if not x.get('id'): errors.append(f'{section}: missing id')
            elif x['id'] in ids: errors.append(f'duplicate id: {x["id"]}')
            else: ids[x['id']]=section
    for a in d.get('applications',[]) or []:
        if a.get('business_unit') and a['business_unit'] not in ids: errors.append(f"application {a.get('id')}: unknown business_unit {a['business_unit']}")
    for s in d.get('services',[]) or []:
        if s.get('application') and s['application'] not in ids: errors.append(f"service {s.get('id')}: unknown application {s['application']}")
    return {'valid':not errors,'errors':errors,'counts':{k:len(d.get(k,[]) or []) for k in ('business_units','applications','services','artifacts')}}
def main(argv=None):
    ap=argparse.ArgumentParser(description='Manage organization and ownership context')
    ap.add_argument('--file',default='governance/context.yml');ap.add_argument('--init',action='store_true');ap.add_argument('--validate',action='store_true');ap.add_argument('--print',dest='show',action='store_true')
    a=ap.parse_args(argv);p=Path(a.file)
    if a.init: write_yaml(p,{**TEMPLATE,'generated_at':now()})
    d=load_data(p,{}) or {};r=validate(d)
    if a.show: r['model']=d
    print(json.dumps(r,indent=2));return 0 if r['valid'] else 3
if __name__=='__main__': raise SystemExit(main())
