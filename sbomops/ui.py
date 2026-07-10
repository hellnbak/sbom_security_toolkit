#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, html
from pathlib import Path

def load(path):
    p=Path(path)
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: return None
    return None

def card(title, body):
    return f'<section class="card"><h2>{html.escape(title)}</h2>{body}</section>'

def main():
    ap=argparse.ArgumentParser(description='Generate a static local dashboard from report artifacts.')
    ap.add_argument('--reports-dir', default='reports'); ap.add_argument('--out', default='reports/ui/index.html')
    args=ap.parse_args(); base=Path(args.reports_dir); out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    quality=load(base/'sbom-quality/sbom-quality.json') or load(base/'bundle/summary.json') or {}
    policy=load(base/'policy/policy-result.json') or {}
    supplier=load(base/'supplier-intake/supplier-intake.json') or {}
    scanner=load(base/'scanner-compare/scanner-compare.json') or {}
    q_body=f"<p class=big>{quality.get('score', quality.get('quality_score','n/a'))}/100</p><p>Grade: {html.escape(str(quality.get('grade', quality.get('quality_grade','n/a'))))}</p>"
    p_body=f"<p class=big>{html.escape(str(policy.get('status','n/a')))}</p><ul>"+''.join(f"<li>{html.escape(f.get('level',''))}: {html.escape(f.get('message',''))}</li>" for f in policy.get('findings',[])[:8])+"</ul>"
    s_body=f"<p class=big>{html.escape(str(supplier.get('status','n/a')))}</p><ul>"+''.join(f"<li>{html.escape(x)}</li>" for x in supplier.get('vendor_followup_questions',[])[:8])+"</ul>"
    sc_body='<ul>'+''.join(f"<li>{html.escape(name)}: {len(val.get('cves',[]))} CVEs</li>" for name,val in scanner.get('scanner_results',{}).items())+'</ul>'
    html_doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>SBOM Security Toolkit Dashboard</title><style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;margin:0;color:#17202a}}header{{background:#101820;color:white;padding:2rem}}main{{max-width:1100px;margin:2rem auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}}.card{{background:white;border:1px solid #ddd;border-radius:12px;padding:1.25rem;box-shadow:0 1px 4px #0001}}.big{{font-size:2.2rem;font-weight:700;margin:.25rem 0}}footer{{max-width:1100px;margin:1rem auto 3rem;color:#667}}code{{background:#eef;padding:.15rem .3rem;border-radius:4px}}
</style></head><body><header><h1>SBOM Security Toolkit Dashboard</h1><p>Static local dashboard generated from CLI report artifacts.</p></header><main>
{card('SBOM Quality', q_body)}{card('Policy Gate', p_body)}{card('Supplier Intake', s_body)}{card('Scanner Comparison', sc_body)}
</main><footer><p>Generated dashboard. Keep sensitive SBOMs and reports local unless approved for sharing.</p></footer></body></html>'''
    out.write_text(html_doc,encoding='utf-8'); print(out)
if __name__=='__main__': main()
