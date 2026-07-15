from __future__ import annotations
import json,re,zipfile
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[2];UX_DIR=ROOT/'ui/storage/ux';UX_DIR.mkdir(parents=True,exist_ok=True)
SCAN_PROFILES={
'quick':{'label':'Quick confidence check','workflow':'analyze','network':False},
'standard':{'label':'Standard security review','workflow':'analyze','network':False},
'full':{'label':'Full analysis and evidence','workflow':'analyze-everything','network':False},
'release':{'label':'Release assurance','workflow':'analyze','network':False},
'supplier':{'label':'Supplier intake','workflow':'supplier-intake','network':False},
'fuzz':{'label':'Timed fuzzing','workflow':'fuzz-all-timed','network':False},}
TASKS=[('analyze-sbom','Analyze an SBOM'),('analyze-repository','Analyze a repository'),('release-review','Review a release'),('supplier-review','Review supplier software'),('dependency-review','Find unsupported dependencies'),('fuzz-test','Fuzz SBOM tooling'),('compare-evidence','Compare evidence')]
PERSONAS={'developer':'Developer','security':'Security engineer','executive':'Executive','auditor':'Auditor'}
def _now():return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
def _path(name):return UX_DIR/name
def load_state(name,default):
    p=_path(name)
    try:return json.loads(p.read_text())
    except Exception:return default
def save_state(name,data):
    p=_path(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n');return p
def add_activity(action,subject='',details=None):
    data=load_state('activity.json',[]);data.append({'at':_now(),'action':action,'subject':subject,'details':details or {}});data=data[-500:];save_state('activity.json',data);return data[-1]
def saved_views():return load_state('saved-views.json',[])
def save_view(name,filters):
    data=saved_views();slug=re.sub(r'[^a-z0-9-]+','-',name.lower()).strip('-') or 'view';item={'id':slug,'name':name,'filters':filters,'updated_at':_now()};data=[x for x in data if x.get('id')!=slug]+[item];save_state('saved-views.json',data);return item
def preferences():return load_state('preferences.json',{'persona':'security','mode':'guided','high_contrast':False,'reduced_motion':False,'notifications':{'job_complete':True,'release_blocked':True,'exception_expiring':True}})
def save_preferences(values):
    p=preferences();p.update(values);save_state('preferences.json',p);return p
def simulate_policy(severity='high',internet_exposed=False,kev=False,exception=False):
    decision='PASS';reasons=[]
    if exception:decision='PASS_WITH_WARNINGS';reasons.append('approved exception would be required')
    elif kev or severity=='critical':decision='BLOCK';reasons.append('critical or known-exploited finding')
    elif severity=='high':decision='APPROVAL_REQUIRED';reasons.append('high-severity finding requires approval')
    elif severity in {'medium','moderate'}:decision='PASS_WITH_WARNINGS';reasons.append('medium-severity finding')
    if internet_exposed and decision=='PASS':decision='PASS_WITH_WARNINGS';reasons.append('internet exposure increases review priority')
    return {'decision':decision,'reasons':reasons,'inputs':{'severity':severity,'internet_exposed':internet_exposed,'kev':kev,'exception':exception}}
def support_bundle(out=None):
    out=Path(out or UX_DIR/'support-bundle.zip');out.parent.mkdir(parents=True,exist_ok=True)
    secret=re.compile(r'(token|secret|password|api[_-]?key)',re.I)
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for p in UX_DIR.glob('*.json'):
            data=json.loads(p.read_text())
            def clean(x):
                if isinstance(x,dict):return {k:('<redacted>' if secret.search(k) else clean(v)) for k,v in x.items()}
                if isinstance(x,list):return [clean(v) for v in x]
                return x
            z.writestr(p.name,json.dumps(clean(data),indent=2))
    return out


# Compatibility aliases retained for v2.11-v2.13 integrations and tests.
STATE = UX_DIR
def load(name, default):
    return load_state(name, default)
def save(name, data):
    return save_state(name, data)
def create_support_bundle(out=None):
    return support_bundle(out)
def policy_simulation(profile='standard'):
    blocked = {'development': 0, 'standard': 1, 'production': 2, 'high-assurance': 3}.get(profile, 1)
    return {'profile': profile, 'blocked': blocked, 'approval_required': max(0, blocked - 1)}
