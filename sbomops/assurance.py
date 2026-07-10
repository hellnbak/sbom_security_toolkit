#!/usr/bin/env python3
"""Unified software supply-chain release assurance engine.

Local-first and deterministic. It evaluates normalized evidence, policies, VEX,
exceptions, provenance, and organizational context and emits stable decisions.
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import yaml

DECISIONS = {"PASS": 0, "PASS_WITH_WARNINGS": 2, "APPROVAL_REQUIRED": 3, "BLOCK": 4, "INCOMPLETE_EVIDENCE": 5, "ERROR": 10}
SEVERITY = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now() -> str: return datetime.now(timezone.utc).isoformat()
def load(path: str | None, default: Any) -> Any:
    if not path: return default
    p=Path(path)
    if not p.exists(): return default
    if p.suffix.lower() in {'.yml','.yaml'}: return yaml.safe_load(p.read_text()) or default
    return json.loads(p.read_text())
def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

def normalize_findings(data: Any) -> list[dict[str,Any]]:
    if isinstance(data, dict):
        for key in ('findings','vulnerabilities','results','matches'):
            if isinstance(data.get(key), list): data=data[key]; break
        else: data=[]
    out=[]
    for raw in data or []:
        if not isinstance(raw,dict): continue
        vuln=raw.get('vulnerability') if isinstance(raw.get('vulnerability'),dict) else {}
        art=raw.get('artifact') if isinstance(raw.get('artifact'),dict) else {}
        sev=str(raw.get('severity') or vuln.get('severity') or 'unknown').lower()
        cvss=raw.get('cvss') or vuln.get('cvss') or vuln.get('cvssScore') or 0
        try: cvss=float(cvss)
        except Exception: cvss=0.0
        epss=raw.get('epss') or vuln.get('epss') or 0
        try: epss=float(epss)
        except Exception: epss=0.0
        out.append({
            'id': raw.get('id') or raw.get('vulnerability_id') or vuln.get('id') or 'UNKNOWN',
            'component': raw.get('component') or raw.get('package') or art.get('name') or '',
            'version': raw.get('version') or art.get('version') or '',
            'purl': raw.get('purl') or art.get('purl') or '',
            'severity': sev, 'cvss': cvss, 'epss': epss,
            'kev': bool(raw.get('kev') or raw.get('cisa_kev') or vuln.get('kev')),
            'fix_available': bool(raw.get('fix_available') or raw.get('fixAvailable') or vuln.get('fix_available')),
            'age_days': int(raw.get('age_days') or raw.get('vulnerability_age_days') or 0),
            'direct': bool(raw.get('direct',False)), 'reachable': raw.get('reachable'),
            'environment': raw.get('environment') or '', 'raw': raw,
        })
    return out

def vex_index(data: Any) -> dict[tuple[str,str],dict]:
    items=[]
    if isinstance(data,dict): items=data.get('statements') or data.get('vulnerabilities') or data.get('status') or []
    elif isinstance(data,list): items=data
    out={}
    for x in items or []:
        if not isinstance(x,dict): continue
        vid=x.get('vulnerability') or x.get('id') or x.get('vulnerability_id')
        if isinstance(vid,dict): vid=vid.get('id')
        prod=x.get('product') or x.get('component') or x.get('purl') or '*'
        if isinstance(prod,list):
            for p in prod: out[(str(vid),str(p))]=x
        else: out[(str(vid),str(prod))]=x
    return out

def exception_index(data: Any) -> list[dict]:
    if isinstance(data,dict): return data.get('exceptions') or data.get('items') or []
    return data or []

def active_exception(f:dict, exceptions:list[dict], rule_id:str, at:datetime) -> dict|None:
    for e in exceptions:
        spec=e.get('spec',e)
        exp=spec.get('expires') or spec.get('expires_at')
        if exp:
            try:
                if datetime.fromisoformat(str(exp).replace('Z','+00:00')) <= at: continue
            except Exception: continue
        if spec.get('status','approved').lower() not in {'approved','active'}: continue
        scopes=[spec.get('vulnerability'),spec.get('component'),spec.get('purl'),spec.get('rule')]
        if spec.get('rule') and spec.get('rule') != rule_id: continue
        if spec.get('vulnerability') and spec.get('vulnerability') != f.get('id'): continue
        if spec.get('component') and spec.get('component') != f.get('component'): continue
        if spec.get('purl') and spec.get('purl') != f.get('purl'): continue
        if any(scopes) or spec.get('project'): return e
    return None

def matches(rule:dict, f:dict, context:dict) -> bool:
    if rule.get('severity') and SEVERITY.get(f['severity'],0) < SEVERITY.get(str(rule['severity']).lower(),0): return False
    if 'fixAvailable' in rule and bool(rule['fixAvailable']) != f['fix_available']: return False
    if 'kev' in rule and bool(rule['kev']) != f['kev']: return False
    if rule.get('epss',{}).get('greaterThan') is not None and f['epss'] <= float(rule['epss']['greaterThan']): return False
    if rule.get('cvss',{}).get('greaterThan') is not None and f['cvss'] <= float(rule['cvss']['greaterThan']): return False
    if rule.get('ageDays',{}).get('greaterThan') is not None and f['age_days'] <= int(rule['ageDays']['greaterThan']): return False
    if 'direct' in rule and bool(rule['direct']) != f['direct']: return False
    if 'reachable' in rule and rule['reachable'] != f['reachable']: return False
    env=rule.get('environment')
    if env and env not in {f.get('environment'),context.get('environment')}: return False
    return True

def evaluate(policy:dict, findings:list[dict], vex:dict, exceptions:list[dict], provenance:dict, context:dict) -> dict:
    spec=policy.get('spec',policy); violations=[]; approvals=[]; warnings=[]; at=datetime.now(timezone.utc)
    required=spec.get('requireEvidence',{})
    missing=[]
    if required.get('provenance') and not provenance: missing.append('provenance')
    if required.get('signedArtifact') and not provenance.get('artifact_signature_verified'): missing.append('verified artifact signature')
    if required.get('signedSbom') and not provenance.get('sbom_signature_verified'): missing.append('verified SBOM signature')
    if required.get('builderIdentity') and not provenance.get('builder_identity'): missing.append('builder identity')
    for f in findings:
        vx=vex.get((f['id'],f.get('purl') or '*')) or vex.get((f['id'],'*'))
        if vx and str(vx.get('status') or vx.get('analysis',{}).get('state') or '').lower() in {'not_affected','not affected','false_positive','resolved','fixed'}:
            continue
        for bucket,target in (('deny',violations),('requireApproval',approvals),('warn',warnings)):
            for i,rule in enumerate(spec.get(bucket,[]) or []):
                if not isinstance(rule,dict) or not matches(rule,f,context): continue
                rid=rule.get('id') or f'{bucket}-{i+1}'
                exc=active_exception(f,exceptions,rid,at)
                item={'rule':rid,'finding':{k:v for k,v in f.items() if k!='raw'},'message':rule.get('message') or f"{f['id']} matched {rid}"}
                if exc: item['exception']=exc.get('metadata',{}).get('id') or exc.get('id'); warnings.append(item)
                else: target.append(item)
                break
    decision='PASS'
    if missing: decision='INCOMPLETE_EVIDENCE'
    elif violations: decision='BLOCK'
    elif approvals: decision='APPROVAL_REQUIRED'
    elif warnings: decision='PASS_WITH_WARNINGS'
    return {'schema_version':'1.0','decision':decision,'exit_code':DECISIONS[decision],'policy':policy.get('metadata',{}).get('name') or policy.get('name') or 'unnamed-policy','evaluated_at':now(),'context':context,'summary':{'findings':len(findings),'violations':len(violations),'approvals':len(approvals),'warnings':len(warnings),'missing_evidence':missing},'violations':violations,'approvals_required':approvals,'warnings':warnings,'provenance':provenance}

def render(r:dict)->str:
    lines=['# Release Assurance Decision','',f"**Decision:** {r['decision']}",f"**Policy:** {r['policy']}",f"**Evaluated:** {r['evaluated_at']}",'']
    if r['summary']['missing_evidence']: lines += ['## Missing evidence','']+[f"- {x}" for x in r['summary']['missing_evidence']]+['']
    for title,key in [('Blocking violations','violations'),('Approvals required','approvals_required'),('Warnings','warnings')]:
        lines += [f'## {title}','']
        lines += [f"- **{x['rule']}** — {x['message']}" + (f" (exception: {x['exception']})" if x.get('exception') else '') for x in r[key]] or ['- None']
        lines.append('')
    return '\n'.join(lines)

def main(argv=None):
    ap=argparse.ArgumentParser(description='Evaluate release assurance policy over vulnerability and supply-chain evidence.')
    ap.add_argument('--policy',required=True); ap.add_argument('--findings'); ap.add_argument('--vex'); ap.add_argument('--exceptions'); ap.add_argument('--provenance'); ap.add_argument('--context'); ap.add_argument('--out-dir',default='reports/release-assurance'); ap.add_argument('--fail-on',choices=['block','approval','warning','never'],default='block')
    a=ap.parse_args(argv)
    try:
        r=evaluate(load(a.policy,{}),normalize_findings(load(a.findings,[])),vex_index(load(a.vex,{})),exception_index(load(a.exceptions,[])),load(a.provenance,{}),load(a.context,{}))
        out=Path(a.out_dir); out.mkdir(parents=True,exist_ok=True); (out/'policy-decision.json').write_text(json.dumps(r,indent=2)+'\n'); (out/'policy-decision.md').write_text(render(r)+'\n'); print(f"Release decision: {r['decision']}")
        thresholds={'block':{'BLOCK','INCOMPLETE_EVIDENCE','ERROR'},'approval':{'BLOCK','INCOMPLETE_EVIDENCE','ERROR','APPROVAL_REQUIRED'},'warning':set(DECISIONS)-{'PASS'},'never':set()}
        return r['exit_code'] if r['decision'] in thresholds[a.fail_on] else 0
    except Exception as e:
        print(f'assurance error: {e}',file=sys.stderr); return 10
if __name__=='__main__': raise SystemExit(main())
