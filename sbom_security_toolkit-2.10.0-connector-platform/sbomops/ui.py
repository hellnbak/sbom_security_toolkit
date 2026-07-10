#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, html
from pathlib import Path
from typing import Any


def load(path: Path, default: Any = None):
    if path.exists():
        try: return json.loads(path.read_text(encoding='utf-8'))
        except Exception: return default
    return default


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ''))


def card(title: str, body: str, css: str = '') -> str:
    return f'<section class="card {css}"><h2>{esc(title)}</h2>{body}</section>'


def connector_cards(base: Path) -> str:
    items = []
    for p in sorted((base / 'connectors').glob('*.json')) if (base / 'connectors').exists() else []:
        doc = load(p, {}) or {}
        connector = doc.get('connector', {})
        result = doc.get('result', doc)
        items.append({
            'name': connector.get('name', p.stem),
            'kind': connector.get('kind', ''),
            'ok': result.get('ok', False),
            'mode': result.get('mode', ''),
            'operation': result.get('operation', ''),
            'records': result.get('records', 0),
            'error': result.get('error', ''),
        })
    smoke = load(base / 'connector-smoke' / 'summary.json', {}) or {}
    if smoke and not items:
        for result in smoke.get('results', []):
            items.append({'name': result.get('connector',''), 'kind':'', 'ok':result.get('ok',False), 'mode':result.get('mode',''), 'operation':result.get('operation',''), 'records':result.get('records',0), 'error':result.get('error','')})
    if not items:
        return '<p>No connector status artifacts found. Run <code>sst connectors smoke</code> or a connector command.</p>'
    rows = []
    for item in items:
        status = 'Healthy' if item['ok'] else 'Error'
        cls = 'ok' if item['ok'] else 'bad'
        rows.append(f"<tr><td><strong>{esc(item['name'])}</strong><br><small>{esc(item['kind'])}</small></td><td><span class='pill {cls}'>{status}</span></td><td>{esc(item['operation'])}</td><td>{esc(item['mode'])}</td><td>{esc(item['records'])}</td><td>{esc(item['error'])}</td></tr>")
    return '<div class="table-wrap"><table><thead><tr><th>Connector</th><th>Status</th><th>Operation</th><th>Mode</th><th>Records</th><th>Message</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'


def main():
    ap=argparse.ArgumentParser(description='Generate a static local dashboard from report artifacts.')
    ap.add_argument('--reports-dir', default='reports'); ap.add_argument('--out', default='reports/ui/index.html')
    args=ap.parse_args(); base=Path(args.reports_dir); out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    quality=load(base/'sbom-quality/sbom-quality.json', {}) or load(base/'bundle/summary.json', {}) or {}
    policy=load(base/'policy/policy-result.json', {}) or load(base/'release-assurance/policy-decision.json', {}) or {}
    supplier=load(base/'supplier-intake/supplier-intake.json', {}) or {}
    scanner=load(base/'scanner-compare/scanner-compare.json', {}) or {}
    assurance=load(base/'release-assurance/policy-decision.json', {}) or load(base/'assurance/policy-decision.json', {}) or {}
    q_body=f"<p class=big>{esc(quality.get('score', quality.get('quality_score','n/a')))}/100</p><p>Grade: {esc(quality.get('grade', quality.get('quality_grade','n/a')))}</p>"
    decision=assurance.get('decision', policy.get('status','n/a'))
    reasons=assurance.get('reasons', []) or [x.get('message','') for x in policy.get('findings',[])[:8]]
    p_body=f"<p class=big>{esc(str(decision).upper())}</p><ul>"+''.join(f"<li>{esc(x if isinstance(x,str) else x.get('message',x))}</li>" for x in reasons[:8])+"</ul>"
    s_body=f"<p class=big>{esc(supplier.get('status','n/a'))}</p><ul>"+''.join(f"<li>{esc(x)}</li>" for x in supplier.get('vendor_followup_questions',[])[:8])+"</ul>"
    sc_body='<ul>'+''.join(f"<li>{esc(name)}: {len(val.get('cves',[]))} CVEs</li>" for name,val in scanner.get('scanner_results',{}).items())+'</ul>'
    connector_body=connector_cards(base)
    html_doc=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SBOM Security Toolkit Dashboard</title><style>
:root{{--bg:#f4f7fb;--ink:#17202a;--muted:#667085;--panel:#fff;--line:#dfe5ec;--nav:#0b1728;--accent:#246bfd;--ok:#16794b;--bad:#b42318}}*{{box-sizing:border-box}}body{{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);margin:0;color:var(--ink)}}header{{background:linear-gradient(135deg,var(--nav),#17365e);color:white;padding:2.2rem}}header p{{color:#d5e2f2}}main{{max-width:1200px;margin:2rem auto;display:grid;grid-template-columns:repeat(12,1fr);gap:1rem;padding:0 1rem}}.card{{grid-column:span 3;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1.25rem;box-shadow:0 4px 16px #10243e0c}}.wide{{grid-column:1/-1}}.card h2{{margin-top:0;font-size:1rem;color:#344054}}.big{{font-size:2.2rem;font-weight:750;margin:.25rem 0;text-transform:uppercase}}footer{{max-width:1200px;margin:1rem auto 3rem;color:var(--muted);padding:0 1rem}}code{{background:#eef2f6;padding:.15rem .3rem;border-radius:4px}}table{{width:100%;border-collapse:collapse;font-size:.92rem}}th,td{{text-align:left;padding:.75rem;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}}.table-wrap{{overflow:auto}}.pill{{display:inline-block;padding:.2rem .55rem;border-radius:999px;font-weight:650;font-size:.78rem}}.pill.ok{{background:#e9f7ef;color:var(--ok)}}.pill.bad{{background:#feeceb;color:var(--bad)}}small{{color:var(--muted)}}@media(max-width:900px){{.card{{grid-column:span 6}}}}@media(max-width:600px){{.card{{grid-column:1/-1}}}}
</style></head><body><header><h1>SBOM Security Toolkit</h1><p>Release assurance, supply-chain intelligence, connector health, and operational evidence.</p></header><main>
{card('SBOM Quality', q_body)}{card('Release Decision', p_body)}{card('Supplier Intake', s_body)}{card('Scanner Comparison', sc_body)}{card('Connector Platform', connector_body, 'wide')}
</main><footer><p>Generated locally from report artifacts. Secrets are referenced by environment variable and are not embedded in this dashboard.</p></footer></body></html>'''
    out.write_text(html_doc,encoding='utf-8'); print(out)
if __name__=='__main__': main()
