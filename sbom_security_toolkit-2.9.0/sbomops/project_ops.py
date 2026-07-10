#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from .common import parse_components
ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ROOT / 'projects'
def now(): return datetime.now(timezone.utc).isoformat()
def slugify(name): return ''.join(ch.lower() if ch.isalnum() else '-' for ch in name).strip('-') or 'project'
def project_dir(project): return PROJECTS / slugify(project)
def ensure_project(project, source='', policy='policies/default-release-policy.yml', ai_provider='none', fuzz_profile='sbom,scanner,ai'):
    d=project_dir(project)
    for sub in ['sboms','scans','fuzzing','reports','evidence','history','owners']:(d/sub).mkdir(parents=True,exist_ok=True)
    meta=d/'metadata.json'
    data={'project_id':d.name,'name':project,'source':source,'policy':policy,'ai_provider':ai_provider,'fuzz_profile':fuzz_profile,'updated_at':now()}
    if meta.exists():
        old=json.loads(meta.read_text()); old.update({k:v for k,v in data.items() if v}); data=old
    else: data['created_at']=now()
    meta.write_text(json.dumps(data,indent=2)+'\n'); return d
def list_projects():
    PROJECTS.mkdir(parents=True,exist_ok=True); out=[]
    for d in sorted(PROJECTS.iterdir()):
        m=d/'metadata.json'
        if m.exists():
            try: out.append(json.loads(m.read_text()))
            except Exception: pass
    return out
def component_rows(sbom_path):
    try:
        _fmt, comps, _meta = parse_components(sbom_path)
        return [{'name': c.name or c.bom_ref or 'unknown', 'version': c.version or '', 'purl': c.purl or '', 'type': 'library'} for c in comps]
    except Exception:
        try:
            doc=json.loads(Path(sbom_path).read_text(errors='replace'))
        except Exception:
            return []
        rows=[]
        for c in doc.get('components') or []:
            if isinstance(c,dict): rows.append({'name':c.get('name') or c.get('bom-ref') or c.get('bom_ref') or 'unknown','version':c.get('version') or '','purl':c.get('purl') or '', 'type':c.get('type') or 'library'})
        return rows
def summarize_run(sbom):
    rows=component_rows(Path(sbom)); missing=sum(1 for r in rows if not r.get('version')); ecosystems={}
    for r in rows:
        p=r.get('purl',''); eco='unknown'
        if p.startswith('pkg:'): eco=p.split('/',1)[0].replace('pkg:','')
        ecosystems[eco]=ecosystems.get(eco,0)+1
    quality=max(0,min(100,100-missing*3-max(0,5-len(rows))*5))
    return {'component_count':len(rows),'missing_versions':missing,'ecosystems':ecosystems,'sbom_quality_estimate':quality}
def _summaries(d):
    out=[]
    for f in sorted((d/'history').glob('*/summary.json')):
        try: out.append(json.loads(f.read_text()))
        except Exception: pass
    return out
def _write_history_csv(d):
    rows=_summaries(d); p=d/'reports'/'history.csv'
    if not rows: return
    with p.open('w',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=['run_id','created_at','component_count','missing_versions','sbom_quality_estimate','note']); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,'') for k in w.fieldnames})
def record(project, sbom, run_dir=None, note=''):
    d=ensure_project(project); rid=datetime.now().strftime('%Y%m%d-%H%M%S'); run=d/'history'/rid; run.mkdir(parents=True,exist_ok=True)
    dest=d/'sboms'/f'{rid}-{Path(sbom).name}'; shutil.copy2(sbom,dest)
    if run_dir and Path(run_dir).exists(): shutil.copytree(run_dir,d/'evidence'/rid,dirs_exist_ok=True)
    summary=summarize_run(dest); summary.update({'run_id':rid,'project_id':d.name,'created_at':now(),'sbom':str(dest.relative_to(ROOT)),'note':note})
    (run/'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); _write_history_csv(d); return summary
def delta(project,out_dir):
    d=project_dir(project); rows=_summaries(d); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    if len(rows)<2: result={'project':project,'status':'insufficient-history','message':'At least two recorded runs are required.'}
    else:
        old,new=rows[-2],rows[-1]; result={'project':project,'from':old.get('run_id'),'to':new.get('run_id'),'component_delta':new.get('component_count',0)-old.get('component_count',0),'missing_version_delta':new.get('missing_versions',0)-old.get('missing_versions',0),'quality_delta':new.get('sbom_quality_estimate',0)-old.get('sbom_quality_estimate',0),'old':old,'new':new}
    (out_dir/'project-delta.json').write_text(json.dumps(result,indent=2)+'\n'); (out_dir/'project-delta.md').write_text('# Project Delta\n\n'+json.dumps(result,indent=2)+'\n'); return result
def trend(project,out_dir):
    d=project_dir(project); rows=_summaries(d); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True); result={'project':project,'run_count':len(rows),'runs':rows}
    (out_dir/'project-trend.json').write_text(json.dumps(result,indent=2)+'\n')
    html=['<!doctype html><html><body><h1>Project Trend</h1><table border="1"><tr><th>Run</th><th>Components</th><th>Missing Versions</th><th>Quality</th></tr>']
    html += [f"<tr><td>{r.get('run_id')}</td><td>{r.get('component_count')}</td><td>{r.get('missing_versions')}</td><td>{r.get('sbom_quality_estimate')}</td></tr>" for r in rows]
    html.append('</table></body></html>'); (out_dir/'project-trend.html').write_text('\n'.join(html)+'\n'); return result
def release_decision(sbom,out_dir):
    out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True); s=summarize_run(sbom); reasons=[]; decision='pass'
    if s['missing_versions']>0: decision='warn'; reasons.append(f"{s['missing_versions']} components are missing exact versions.")
    if s['sbom_quality_estimate']<70: decision='block'; reasons.append('SBOM quality estimate is below 70.')
    if not reasons: reasons.append('No blocking local release-decision heuristics triggered.')
    result={'decision':decision,'reasons':reasons,'summary':s}; (out_dir/'release-decision.json').write_text(json.dumps(result,indent=2)+'\n'); (out_dir/'release-decision.md').write_text('# Release Decision\n\nDecision: **%s**\n\n%s\n'%(decision,'\n'.join('- '+r for r in reasons))); return result
def ci_generate(out):
    out=Path(out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text('''name: SBOM Security Toolkit\non:\n  pull_request:\n  push:\n    branches: [ main ]\njobs:\n  sbom-security:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: "3.11"\n      - run: pip install -r requirements.txt\n      - run: python -m sbomops.repo_intake analyze . --out-dir reports/repo-intake --dependency-health --fuzz\n      - uses: actions/upload-artifact@v4\n        with:\n          name: sbom-security-evidence\n          path: reports/\n''')
def policy_tune(out,stale_days=365):
    out=Path(out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(f'''name: generated-release-policy\nfail_on:\n  cisa_kev: true\n  critical_without_vex: true\n  unsupported_dependencies: true\n  stale_dependencies_days_gt: {stale_days}\nwarn_on:\n  scanner_disagreement: true\n  missing_dependency_graph: true\n''')
def owners_template(out):
    out=Path(out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text("""owners:\n  npm:\n    react: frontend-team\n    express: platform-team\n  pypi:\n    django: backend-team\n    requests: platform-team\n  unknown:\n    '*': security-team\n""")
def ai_summary(input_dir,out_dir):
    input_dir=Path(input_dir); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True); files=[p for p in input_dir.rglob('*.json')][:20] if input_dir.exists() else []
    data={'input_dir':str(input_dir),'files_reviewed':[str(p) for p in files],'note':'AI-ready executive summary scaffold; AI summarizes evidence but does not accept risk.'}
    (out_dir/'ai-executive-summary.json').write_text(json.dumps(data,indent=2)+'\n'); (out_dir/'ai-executive-summary.md').write_text('# AI Executive Summary Scaffold\n\n'+'\n'.join('- '+str(p) for p in files)+'\n')
def evidence_index(bundle_dir,out_dir):
    bundle_dir=Path(bundle_dir); out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True); files=[str(p.relative_to(bundle_dir)) for p in sorted(bundle_dir.rglob('*')) if p.is_file()] if bundle_dir.exists() else []
    (out_dir/'evidence-index.json').write_text(json.dumps({'bundle_dir':str(bundle_dir),'files':files},indent=2)+'\n'); (out_dir/'evidence-index.html').write_text('<!doctype html><html><body><h1>Evidence Bundle Viewer</h1><ul>'+''.join(f'<li>{f}</li>' for f in files)+'</ul></body></html>')
def main(argv=None):
    ap=argparse.ArgumentParser(prog='sst project'); sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('init'); p.add_argument('project'); p.add_argument('--source',default=''); p.add_argument('--policy',default='policies/default-release-policy.yml'); p.add_argument('--ai-provider',default='none'); p.add_argument('--fuzz-profile',default='sbom,scanner,ai')
    sub.add_parser('list')
    p=sub.add_parser('record'); p.add_argument('project'); p.add_argument('--sbom',required=True); p.add_argument('--run-dir'); p.add_argument('--note',default='')
    p=sub.add_parser('delta'); p.add_argument('project'); p.add_argument('--out-dir',default='reports/project-delta')
    p=sub.add_parser('trend'); p.add_argument('project'); p.add_argument('--out-dir',default='reports/project-trend')
    p=sub.add_parser('release-decision'); p.add_argument('--sbom',required=True); p.add_argument('--out-dir',default='reports/release-decision')
    p=sub.add_parser('ci-generate'); p.add_argument('--out',default='.github/workflows/sbom-security-toolkit.yml')
    p=sub.add_parser('policy-tune'); p.add_argument('--out',default='policies/generated/generated-release-policy.yml'); p.add_argument('--stale-days',type=int,default=365)
    p=sub.add_parser('owners-template'); p.add_argument('--out',default='owners.yml')
    p=sub.add_parser('ai-summary'); p.add_argument('--input-dir',default='reports/latest'); p.add_argument('--out-dir',default='reports/ai-executive-summary')
    p=sub.add_parser('evidence-index'); p.add_argument('bundle_dir'); p.add_argument('--out-dir',default='reports/evidence-viewer')
    a=ap.parse_args(argv)
    if a.cmd=='init': print(ensure_project(a.project,source=a.source,policy=a.policy,ai_provider=a.ai_provider,fuzz_profile=a.fuzz_profile)); return 0
    if a.cmd=='list': print(json.dumps(list_projects(),indent=2)); return 0
    if a.cmd=='record': print(json.dumps(record(a.project,Path(a.sbom),Path(a.run_dir) if a.run_dir else None,a.note),indent=2)); return 0
    if a.cmd=='delta': print(json.dumps(delta(a.project,a.out_dir),indent=2)); return 0
    if a.cmd=='trend': print(json.dumps(trend(a.project,a.out_dir),indent=2)); return 0
    if a.cmd=='release-decision': print(json.dumps(release_decision(a.sbom,a.out_dir),indent=2)); return 0
    if a.cmd=='ci-generate': ci_generate(a.out); print(a.out); return 0
    if a.cmd=='policy-tune': policy_tune(a.out,a.stale_days); print(a.out); return 0
    if a.cmd=='owners-template': owners_template(a.out); print(a.out); return 0
    if a.cmd=='ai-summary': ai_summary(a.input_dir,a.out_dir); print(a.out_dir); return 0
    if a.cmd=='evidence-index': evidence_index(a.bundle_dir,a.out_dir); print(a.out_dir); return 0
    return 2
if __name__=='__main__': raise SystemExit(main())
