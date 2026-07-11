from __future__ import annotations
import json, os, platform, sys, zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / 'ui' / 'storage' / 'ux'
STATE.mkdir(parents=True, exist_ok=True)

DEFAULT_VIEWS = [
 {'name':'Blocking findings','filter':'decision=blocked'}, {'name':'Fix available','filter':'fix_available=true'},
 {'name':'Known exploited','filter':'kev=true'}, {'name':'Reachable vulnerabilities','filter':'reachable=true'},
 {'name':'Internet-facing production','filter':'environment=production&internet_facing=true'},
 {'name':'New this week','filter':'age_days<=7'}, {'name':'SLA breached','filter':'sla=breached'},
 {'name':'Exceptions expiring','filter':'exception_expiring=true'}, {'name':'Unowned findings','filter':'owner='},
 {'name':'Recently resolved','filter':'status=resolved'}]

SCAN_PROFILES = {
 'quick': {'label':'Quick dependency check','checks':['SBOM parse','vulnerability match','license summary']},
 'standard': {'label':'Standard application scan','checks':['vulnerabilities','licenses','dependency health','policy']},
 'production': {'label':'Production release review','checks':['standard checks','KEV/EPSS','reachability','provenance','release gate']},
 'deep': {'label':'Deep supply-chain assessment','checks':['production checks','fuzzing','connector correlation','AI report']},
 'compliance': {'label':'Compliance evidence scan','checks':['production checks','signed evidence','audit history','retention']},
 'container': {'label':'Container release validation','checks':['image SBOM','vulnerabilities','signatures','provenance','policy']},
}

TASKS = [
 ('secure-app','Secure a new application'),('review-release','Review a release'),('triage-critical','Triage critical findings'),
 ('approve-exception','Approve a risk exception'),('prepare-evidence','Prepare audit evidence'),
 ('connect-platform','Connect a security platform'),('remediation-plan','Generate a remediation plan')]

PERSONAS = {
 'developer':['My projects','My blocking findings','Fix recommendations','Remediation pull requests','Build status'],
 'security':['Global risk','Release gates','Findings requiring review','Exceptions','Connector health'],
 'executive':['Risk trend','Blocked production releases','SLA performance','Business-unit exposure','Remediation progress'],
 'auditor':['Evidence packages','Policy history','Exception approvals','Provenance status','Audit logs'],
}

def load(name: str, default: Any):
 p=STATE/name
 if not p.exists(): return default
 try: return json.loads(p.read_text())
 except Exception: return default

def save(name: str, data: Any):
 p=STATE/name; p.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n'); return p

def add_activity(action: str, detail: str='', actor: str='local-user'):
 rows=load('activity.json',[])
 rows.insert(0, {'time':datetime.now(timezone.utc).isoformat(),'action':action,'detail':detail,'actor':actor})
 save('activity.json', rows[:500])

def preferences():
 return load('preferences.json', {'mode':'guided','persona':'security','reduced_motion':False,'notifications':['release_blocked','critical_finding','connector_failed']})

def policy_simulation(policy: str='standard'):
 # Deterministic demo simulation for local/offline UX; real evaluations remain in assurance engine.
 base={'pass':12,'warning':4,'approval':3,'blocked':2}
 if policy=='development': base={'pass':18,'warning':3,'approval':0,'blocked':0}
 if policy=='high-assurance': base={'pass':7,'warning':2,'approval':4,'blocked':8}
 return {'policy':policy, **base, 'generated_at':datetime.now(timezone.utc).isoformat()}

def create_support_bundle(out: Path|None=None):
 out=out or (ROOT/'reports'/'support'/f"support-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip")
 out.parent.mkdir(parents=True,exist_ok=True)
 manifest={'version':_version(),'python':sys.version,'platform':platform.platform(),'generated_at':datetime.now(timezone.utc).isoformat(),'preferences':preferences()}
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  z.writestr('manifest.json',json.dumps(manifest,indent=2))
  for rel in ['VALIDATION.md','pyproject.toml','configs/connectors.yml']:
   p=ROOT/rel
   if p.exists(): z.write(p,rel)
  for p in sorted(STATE.glob('*.json')):
   # UX state contains no raw secrets by design.
   z.write(p,f'ux-state/{p.name}')
 add_activity('support_bundle_created',str(out))
 return out

def _version():
 try:
  from sbomops.__version__ import __version__; return __version__
 except Exception: return 'unknown'
