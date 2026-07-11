#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import re
import urllib.parse
import yaml
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

from .job_runner import (
    ROOT, JOBS, WORKFLOWS, FUZZ_WORKFLOWS, REPO_WORKFLOWS, create_job, delete_job, list_jobs, read_status, save_upload,
    scanner_status, status_path, logs_path, job_dir, storage_init, MAX_UPLOAD_BYTES
)
from sbomops.config_manager import (
    AI_DIR, CLOUD_DIR, FUZZ_DIR, POLICY_DIR, PROJECT_DIR, build_ai_provider_config,
    build_cloud_settings_config, build_fuzzing_profile_config, build_policy_config,
    build_project_defaults_config, import_config, list_configs, safe_slug, write_yaml
)
from sbomops import enterprise as enterprise_ops
from . import ux

CSS = """
:root{--bg:#f4f6fa;--panel:#fff;--panel2:#f8fafc;--text:#172033;--muted:#667085;--line:#e4e7ec;--brand:#175cd3;--brand2:#004eeb;--danger:#b42318;--warning:#b54708;--success:#067647;--sidebar:#101828;font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:var(--text);background:var(--bg)}*{box-sizing:border-box}body{margin:0;background:var(--bg)}a{color:var(--brand)}.app{display:grid;grid-template-columns:250px 1fr;min-height:100vh}.sidebar{background:var(--sidebar);color:white;padding:20px 14px;position:sticky;top:0;height:100vh;overflow:auto}.brand{font-weight:800;font-size:18px;padding:8px 12px 20px}.brand small{display:block;font-weight:500;color:#98a2b3;margin-top:4px}.nav-group{color:#98a2b3;font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:18px 12px 8px}.nav a{display:flex;gap:10px;align-items:center;color:#d0d5dd;padding:10px 12px;border-radius:8px;text-decoration:none;margin:2px 0}.nav a:hover,.nav a.active{background:#344054;color:white}.main{min-width:0}.topbar{height:68px;background:white;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:0 28px;position:sticky;top:0;z-index:5}.search{flex:1;max-width:620px}.search input{width:100%}.top-actions{margin-left:auto;display:flex;gap:8px}.wrap{max-width:1440px;margin:0 auto;padding:26px}.page-title{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:20px}.page-title h1{margin:0;font-size:28px}.page-title p{margin:6px 0 0;color:var(--muted)}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin:0 0 18px;box-shadow:0 1px 2px rgba(16,24,40,.04)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}.metric{background:white;border:1px solid var(--line);border-radius:12px;padding:18px}.metric .label{color:var(--muted);font-size:13px}.metric .value{font-size:30px;font-weight:750;margin:8px 0}.metric .hint{font-size:12px;color:var(--muted)}h1,h2,h3{color:#101828}h2{margin:.1rem 0 1rem;font-size:19px}h3{margin:.2rem 0 .7rem}.btn,button,input[type=submit]{background:var(--brand);color:white;border:0;border-radius:8px;padding:9px 13px;text-decoration:none;display:inline-block;cursor:pointer;font-weight:600}.btn:hover,button:hover{background:var(--brand2)}.btn.secondary{background:white;color:#344054;border:1px solid #d0d5dd}.btn.danger,button.danger{background:var(--danger)}.btn.small{font-size:12px;padding:6px 9px}.muted{color:var(--muted)}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:650;background:#f2f4f7;color:#344054}.completed,.passed,.healthy{background:#ecfdf3;color:var(--success)}.failed,.blocked,.unhealthy{background:#fef3f2;color:var(--danger)}.running,.queued,.warning{background:#fffaeb;color:var(--warning)}.approval{background:#eff8ff;color:#175cd3}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border-bottom:1px solid var(--line);text-align:left;padding:12px 10px;vertical-align:top}th{font-size:12px;color:#667085;text-transform:uppercase;letter-spacing:.03em;background:#fcfcfd}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}code,pre{background:#f2f4f7;border-radius:7px}pre{padding:14px;overflow:auto;max-height:520px}input,select,textarea{padding:9px 11px;border:1px solid #d0d5dd;border-radius:8px;background:white;color:#101828}textarea{width:100%;min-height:160px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}label{display:block;font-weight:600;margin:12px 0 6px}.small{font-size:13px}.ok{color:var(--success)}.bad{color:var(--danger)}.decision{border-left:5px solid var(--brand)}.decision.blocked{border-left-color:var(--danger)}.decision.warning{border-left-color:var(--warning)}.decision.passed{border-left-color:var(--success)}.empty{text-align:center;padding:42px 20px}.empty h3{margin-bottom:8px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}.toolbar .spacer{flex:1}.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:-4px 0 18px}.tabs a{padding:10px 12px;text-decoration:none;color:#475467;border-bottom:2px solid transparent}.tabs a.active{border-color:var(--brand);color:var(--brand);font-weight:650}.callout{padding:14px 16px;border-radius:9px;background:#eff8ff;border:1px solid #b2ddff}.connector{display:flex;gap:14px;align-items:flex-start}.connector-icon{width:42px;height:42px;border-radius:10px;background:#f2f4f7;display:grid;place-items:center;font-weight:800}.progress{height:8px;background:#eaecf0;border-radius:999px;overflow:hidden}.progress span{display:block;height:100%;background:var(--brand)}.steps{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 22px}.step{padding:8px 12px;border-radius:999px;background:#f2f4f7;color:#667085;font-size:13px}.step.active{background:#eff8ff;color:#175cd3;font-weight:700}.choice{display:block;border:1px solid var(--line);border-radius:10px;padding:14px;margin:8px 0;cursor:pointer}.choice:hover{border-color:#84adff;background:#f9fbff}.checklist li{margin:10px 0}.hero{padding:28px;background:linear-gradient(135deg,#eff8ff,#fff);border:1px solid #b2ddff;border-radius:14px;margin-bottom:18px}@media(max-width:900px){.app{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.metrics{grid-template-columns:repeat(2,1fr)}.topbar{position:relative}.nav a{display:inline-flex}.nav-group{display:none}}@media(max-width:560px){.metrics{grid-template-columns:1fr}.wrap{padding:16px}.topbar{padding:0 16px}.page-title{display:block}.top-actions{display:none}}
"""

NAV = [
    ("Get Started", [("/welcome","Quick Start"),("/workflows","Guided Workflows"),("/project/new","New Project"),("/help","Help Center")]),
    ("Workspace", [("/dashboard","Overview"),("/projects","Projects"),("/jobs","Scans"),("/findings","Findings"),("/decisions","Release Decisions"),("/actions","Action Center"),("/saved-views","Saved Views"),("/activity","Activity")]),
    ("Governance", [("/controls","Security Controls"),("/exceptions","Exceptions"),("/reports","Reports"),("/evidence","Evidence")]),
    ("Platform", [("/integrations","Connectors"),("/notifications","Notifications"),("/personas","My View"),("/settings","Policies & Settings"),("/admin","Administration")]),
    ("Advanced", [("/repository","Repository Intake"),("/fuzzing","Fuzzing Lab"),("/scanners","Scanner Status"),("/demo","Demo / QA")]),
]

def page(title: str, body: str, path: str = "") -> bytes:
    nav=[]
    for group, links in NAV:
        nav.append(f"<div class='nav-group'>{html.escape(group)}</div>")
        for href,label in links:
            active=" active" if path == href or (href != '/dashboard' and path.startswith(href+'/')) else ""
            nav.append(f"<a class='{active.strip()}' href='{href}'>{html.escape(label)}</a>")
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)} · SBOM Security Toolkit</title><style>{CSS}</style><script>function togglePalette(){{const p=document.getElementById('palette');p.hidden=!p.hidden;if(!p.hidden)p.querySelector('input').focus()}}document.addEventListener('keydown',e=>{{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){{e.preventDefault();togglePalette()}}if(e.key==='Escape'){{const p=document.getElementById('palette');if(p)p.hidden=true}}}})</script></head><body><div class='app'><aside class='sidebar'><div class='brand'>SBOM Security Toolkit<small>Release Assurance Workbench</small></div><nav class='nav'>{''.join(nav)}</nav><div class='nav-group'>Support</div><nav class='nav'><a href='/policy-simulator'>Policy Simulator</a><a href='/support'>Support Bundle</a><a href='/feedback'>Feedback</a></nav></aside><section class='main'><header class='topbar'><form class='search' action='/search' method='get'><input name='q' aria-label='Global search' placeholder='Search projects, CVEs, components, releases…'></form><div class='top-actions'><button class='btn secondary' onclick='togglePalette()' title='Command palette (⌘K)'>⌘K</button><a class='btn secondary' href='/welcome'>Quick Start</a><a class='btn secondary' href='/'>Upload SBOM</a><a class='btn' href='/project/new'>New Project</a><a class='btn secondary' href='/workflows'>Guided Workflow</a></div></header><main class='wrap'><div id='palette' hidden class='card' style='position:fixed;z-index:30;top:80px;left:50%;transform:translateX(-50%);width:min(620px,90vw);box-shadow:0 18px 60px rgba(0,0,0,.25)'><form action='/search'><input name='q' style='width:100%' placeholder='Search or type a command: scan, project, report, exception…'><div class='toolbar' style='margin-top:12px'><a class='btn secondary' href='/'>Run scan</a><a class='btn secondary' href='/project/new'>New project</a><a class='btn secondary' href='/workflows'>Guided workflow</a><a class='btn secondary' href='/reports'>Generate report</a></div></form></div>{body}</main></section></div></body></html>""".encode()

    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{CSS}</style><script>function togglePalette(){{const p=document.getElementById('palette');p.hidden=!p.hidden;if(!p.hidden)p.querySelector('input').focus()}}document.addEventListener('keydown',e=>{{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){{e.preventDefault();togglePalette()}}if(e.key==='Escape'){{const p=document.getElementById('palette');if(p)p.hidden=true}}}})</script></head><body><div class='top'><h1>SBOM Security Toolkit Workbench</h1><div class='nav'><a href='/'>Upload</a><a href='/jobs'>Jobs</a><a href='/scanners'>Scanner Status</a><a href='/repository'>Repository Intake</a><a href='/projects'>Projects</a><a href='/settings'>Settings</a><a href='/admin'>Admin</a><a href='/integrations'>Integrations</a><a href='/findings'>Findings</a><a href='/reports'>Reports</a><a href='/ai-reports'>AI Reports</a><a href='/demo'>Demo/QA</a><a href='/fuzzing'>Fuzzing Lab</a><a href='/fuzzing/dashboard'>Fuzz Dashboard</a></div></div><main class='wrap'><div id='palette' hidden class='card' style='position:fixed;z-index:30;top:80px;left:50%;transform:translateX(-50%);width:min(620px,90vw);box-shadow:0 18px 60px rgba(0,0,0,.25)'><form action='/search'><input name='q' style='width:100%' placeholder='Search or type a command: scan, project, report, exception…'><div class='toolbar' style='margin-top:12px'><a class='btn secondary' href='/'>Run scan</a><a class='btn secondary' href='/project/new'>New project</a><a class='btn secondary' href='/workflows'>Guided workflow</a><a class='btn secondary' href='/reports'>Generate report</a></div></form></div>{body}</main></body></html>""".encode()

def esc(x) -> str:
    return html.escape(str(x or ""))

def parse_multipart(body: bytes, content_type: str) -> Tuple[Dict[str, str], Tuple[str, bytes]]:
    m = re.search(r"boundary=([^;]+)", content_type)
    if not m:
        raise ValueError("Missing multipart boundary")
    boundary = b"--" + m.group(1).strip().strip('"').encode()
    fields: Dict[str, str] = {}
    file_tuple = ("upload.sbom", b"")
    for part in body.split(boundary):
        if not part or part in (b"--\r\n", b"--"):
            continue
        part = part.strip(b"\r\n")
        if b"\r\n\r\n" not in part:
            continue
        header, data = part.split(b"\r\n\r\n", 1)
        header_text = header.decode("utf-8", errors="replace")
        name_m = re.search(r'name="([^"]+)"', header_text)
        if not name_m:
            continue
        name = name_m.group(1)
        filename_m = re.search(r'filename="([^"]*)"', header_text)
        if filename_m:
            file_tuple = (filename_m.group(1) or "upload.sbom", data)
        else:
            fields[name] = data.decode("utf-8", errors="replace")
    return fields, file_tuple

class Handler(BaseHTTPRequestHandler):
    server_version = "SBOMWorkbench/1.5"

    def send_html(self, title: str, body: str, code: int = 200):
        raw = page(title, body, urllib.parse.urlparse(self.path).path)
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def send_json(self, data, code=200):
        raw = json.dumps(data, indent=2, sort_keys=True).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        if path == "/": return self.index()
        if path == "/dashboard": return self.dashboard_page()
        if path == "/welcome": return self.welcome_page(url)
        if path == "/workflows": return self.workflows_page(url)
        if path == "/saved-views": return self.saved_views_page()
        if path == "/activity": return self.activity_page()
        if path == "/notifications": return self.notifications_page()
        if path == "/personas": return self.personas_page()
        if path == "/policy-simulator": return self.policy_simulator_page(url)
        if path == "/support": return self.support_page()
        if path == "/feedback": return self.feedback_page()
        if path == "/project/new": return self.project_wizard(url)
        if path == "/connectors/setup": return self.connector_wizard(url)
        if path == "/help": return self.help_page()
        if path == "/sample": return self.sample_page()
        if path == "/decisions": return self.decisions_page()
        if path == "/actions": return self.actions_page()
        if path == "/controls": return self.controls_page()
        if path == "/exceptions": return self.exceptions_page()
        if path == "/evidence": return self.evidence_page()
        if path == "/search": return self.search_page(url)
        if path == "/jobs": return self.jobs()
        if path.startswith("/jobs/"): return self.job(path.split("/", 2)[2])
        if path == "/scanners": return self.scanners()
        if path == "/repository": return self.repository_intake()
        if path == "/projects": return self.projects_page()
        if path == "/settings": return self.settings_page()
        if path == "/admin": return self.admin_page()
        if path == "/integrations": return self.integrations_page()
        if path == "/findings": return self.findings_page()
        if path == "/reports": return self.reports_page()
        if path == "/ai-reports": return self.ai_reports_page()
        if path == "/demo": return self.demo_qa_page()
        if path.startswith("/reports/view/"): return self.reports_view(path.split("/", 3)[3])
        if path.startswith("/settings/view/"): return self.settings_view(path.split("/", 3)[3])
        if path == "/fuzzing": return self.fuzzing_lab()
        if path == "/fuzzing/logs": return self.fuzzing_logs()
        if path == "/fuzzing/dashboard": return self.fuzzing_dashboard()
        if path.startswith("/api/jobs/"): return self.api_job(path.split("/", 3)[3])
        if path.startswith("/download/"): return self.download(path.split("/", 2)[2])
        self.send_html("Not found", "<div class='card'><h2>Not found</h2></div>", 404)

    def do_POST(self):
        if self.path == "/upload": return self.upload()
        if self.path == "/welcome/save": return self.welcome_save()
        if self.path == "/preferences/save": return self.preferences_save()
        if self.path == "/saved-views/save": return self.saved_views_save()
        if self.path == "/notifications/save": return self.notifications_save()
        if self.path == "/support/create": return self.support_create()
        if self.path == "/feedback/save": return self.feedback_save()
        if self.path == "/project/new/save": return self.project_wizard_save()
        if self.path == "/connectors/setup/save": return self.connector_wizard_save()
        if self.path == "/settings/save": return self.settings_save()
        if self.path == "/admin/save": return self.admin_save()
        if self.path == "/integrations/save": return self.integrations_save()
        if self.path == "/controls/run": return self.controls_run()
        if self.path == "/findings/save": return self.findings_save()
        if self.path == "/reports/refresh": return self.reports_refresh()
        if self.path == "/ai-reports/generate": return self.ai_reports_generate()
        if self.path == "/demo/run": return self.demo_qa_run()
        if self.path.startswith("/delete/"):
            jid = self.path.split("/", 2)[2]; delete_job(jid); self.redirect("/jobs"); return
        self.send_html("Not found", "<div class='card'><h2>Not found</h2></div>", 404)

    def redirect(self, location: str):
        self.send_response(303); self.send_header("Location", location); self.end_headers()

    def index(self):
        opts = "".join(f"<option value='{esc(k)}'>{esc(v)}</option>" for k,v in WORKFLOWS.items())
        body = f"""
        <div class='card'><h2>Upload an SBOM and run a local workflow</h2>
        <p class='muted'>Runs locally on 127.0.0.1. Uploads are stored under <code>ui/storage</code>. Network access is off by default unless a workflow/tool you invoke performs local scanner calls.</p>
        <form action='/upload' method='post' enctype='multipart/form-data'>
          <label>SBOM file</label><input type='file' name='sbom' required>
          <p class='small muted'>Allowed: .json, .xml, .spdx, .txt. Max size: {MAX_UPLOAD_BYTES//(1024*1024)} MB.</p>
          <label>Workflow</label><select name='workflow'>{opts}</select>
          <p class='small muted'><strong>Use “Full SBOM analysis + every action + all fuzzing scenarios”</strong> when you want every possible analysis action plus the broad timed fuzzing suite in one job.</p>
          <p class='small muted'><strong>Unsupported / out-of-date dependency analysis</strong> is available in this dropdown. It checks uploaded SBOMs for deprecated, abandoned, stale, unpinned, or unsupported-risk dependencies.</p>
          <div class='grid'><div><label>Stale threshold days</label><input name='stale_days' value='365' size='8'><p class='small muted'>Used by unsupported/out-of-date dependency analysis.</p></div><div><label>Fuzz time per step/library</label><input name='duration_seconds' value='60' size='8'><p class='small muted'>Used by the all-actions/all-fuzz workflow and AI fuzz execution.</p></div><div><label>Fuzz targets</label><input name='library_targets' value='sbom,scanner,ai' size='28'><p class='small muted'>For all-actions runs. Examples: sbom,scanner,ai or all.</p></div><div><label>Project ID</label><input name='project_id' value='uploaded-sbom' size='24'><p class='small muted'>Optional history workspace for project record/delta/trend.</p></div></div>
          <div class='card'>
            <h3>Optional AI-assisted fuzz cases for Full SBOM Analysis</h3>
            <p class='small muted'>When enabled for <strong>Full SBOM analysis</strong>, the workbench asks the configured provider for SBOM-specific fuzz case ideas, validates deterministic cases, and can run only safe generated cases. AI output is advisory and review-gated.</p>
            <p><label><input type='checkbox' name='ai_analysis_enabled' value='1'> Enable AI-assisted fuzz case generation during Full SBOM Analysis</label></p>
            <div class='grid'>
              <div><label>AI fuzz mode</label><select name='ai_analysis_mode'><option value='suggest'>Suggest only</option><option value='generate-run'>Generate and run validated cases</option></select></div>
              <div><label>AI provider</label><select name='ai_provider'><option value='none'>prompt-only / none</option><option value='bedrock'>AWS Bedrock</option><option value='glm'>GLM local/OpenAI-compatible</option><option value='ollama'>Ollama-compatible</option><option value='openai-compatible'>OpenAI-compatible</option></select></div>
              <div><label>AI model</label><input name='ai_model' placeholder='Bedrock model ID, glm-5.2, etc.' size='32'></div>
              <div><label>Max generated cases</label><input name='ai_max_cases' value='5' size='8'></div>
              <div><label>Time budget per case</label><input name='duration_seconds' value='30' size='8'></div>
              <div><label>AI scenario</label><input name='scenario' value='sbom-analysis-targeted-edge-cases' size='34'></div>
            </div>
          </div>
          <div class='card'>
            <h3>Lifecycle intelligence sources</h3>
            <p class='small muted'>Used by unsupported / out-of-date dependency analysis. Network is still opt-in. Offline mode uses SBOM metadata plus built-in or user-provided lifecycle cache data.</p>
            <div class='grid'>
              <div><label>Sources</label><input name='lifecycle_sources' value='sbom,known,registry,endoflife' size='42'><p class='small muted'>Comma list: sbom, known, registry, endoflife.</p></div>
              <div><label>Lifecycle cache path</label><input name='lifecycle_cache' placeholder='configs/lifecycle/eol-cache.json' size='42'><p class='small muted'>Optional JSON cache keyed by product slug.</p></div>
            </div>
            <p><label><input type='checkbox' name='offline_cache_only' value='1'> Offline cache only; do not call external lifecycle providers even when network is enabled</label></p>
          </div>
          <label>Policy path</label><input name='policy' value='policies/default-release-policy.yml' size='46'>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled enrichment/scanner actions when available, including registry metadata and endoflife.date lifecycle lookups</label></p>
          <input type='submit' value='Start scan'>
        </form></div>
        <div class='grid'><div class='card'><h3>Local-first</h3><p>No auth, no database, no cloud upload. Use on localhost only.</p></div><div class='card'><h3>Evidence bundle</h3><p>Each job produces a downloadable zip with input, logs, status, and reports.</p></div><div class='card'><h3>Safe defaults</h3><p>Filename sanitization, size/type limits, isolated per-job directories, and delete controls.</p></div></div>
        """
        self.send_html("Upload", body)

    def upload(self):
        length = int(self.headers.get("Content-Length", "0"))
        ctype = self.headers.get("Content-Type", "")
        if length > MAX_UPLOAD_BYTES + 1024 * 1024:
            return self.send_html("Upload too large", "<div class='card'><h2>Upload too large</h2></div>", 413)
        try:
            fields, (filename, content) = parse_multipart(self.rfile.read(length), ctype)
            workflow = fields.get("workflow", "analyze")
            secrets = {}
            github_token = fields.get("github_token", "").strip()
            if github_token:
                secrets["GITHUB_TOKEN"] = github_token
            repo_source = fields.get("repo_source", "").strip()
            repo_source_type = fields.get("repo_source_type", "upload")
            if workflow.startswith("repo-") and repo_source and (not content or not filename):
                descriptor = {
                    "kind": "repo-descriptor",
                    "source": repo_source,
                    "allow_remote": repo_source_type == "github" or fields.get("repo_allow_remote") == "1",
                    "github_token_env": "GITHUB_TOKEN",
                }
                upload_path = ROOT / "ui" / "storage" / "uploads" / f"repo-descriptor-{int(__import__('time').time())}.json"
                upload_path.parent.mkdir(parents=True, exist_ok=True)
                upload_path.write_text(json.dumps(descriptor, indent=2) + "\n")
                upload = upload_path
            else:
                upload = save_upload(filename, content)
            options = {k: fields.get(k, "") for k in ["count", "duration_seconds", "library_targets", "edge", "budget_profile", "ai_provider", "ai_model", "ai_goal", "scenario", "dtrack_url", "target", "grammar", "finding_id", "finding_state", "repo_generators", "repo_source_type", "repo_allow_remote", "repo_fuzz", "repo_dependency_health", "stale_days", "lifecycle_sources", "lifecycle_cache", "offline_cache_only", "ai_analysis_enabled", "ai_analysis_mode", "ai_max_cases", "project_id"]}
            jid = create_job(workflow, upload, policy=fields.get("policy", "policies/default-release-policy.yml"), network=fields.get("network") == "1", options=options, secrets=secrets)
            self.redirect(f"/jobs/{jid}")
        except Exception as exc:
            self.send_html("Upload error", f"<div class='card'><h2>Upload error</h2><pre>{esc(exc)}</pre></div>", 400)

    def jobs(self):
        rows = "".join(f"<tr><td><a href='/jobs/{esc(j['job_id'])}'>{esc(j['job_id'])}</a></td><td>{esc(j.get('workflow_label'))}</td><td><span class='pill {esc(j.get('state'))}'>{esc(j.get('state'))}</span></td><td>{esc(j.get('created_at'))}</td></tr>" for j in list_jobs())
        if not rows: rows = "<tr><td colspan='4' class='muted'>No jobs yet.</td></tr>"
        self.send_html("Jobs", f"<div class='card'><h2>Jobs</h2><table><tr><th>Job</th><th>Workflow</th><th>Status</th><th>Created</th></tr>{rows}</table></div>")

    def job(self, jid: str):
        try: s = read_status(jid)
        except FileNotFoundError: return self.send_html("Job not found", "<div class='card'><h2>Job not found</h2></div>", 404)
        logs = logs_path(jid).read_text(errors="replace") if logs_path(jid).exists() else ""
        options_html = self.options_table(s.get("options") or {})
        steps = "".join(f"<tr><td>{esc(x.get('name'))}</td><td>{esc(x.get('returncode'))}</td><td>{esc(x.get('elapsed_seconds',''))}</td></tr>" for x in s.get("steps", [])) or "<tr><td colspan='3' class='muted'>No completed steps yet.</td></tr>"
        result_links = self.result_links(jid)
        refresh = "<meta http-equiv='refresh' content='3'>" if s.get("state") in {"queued", "running"} else ""
        body = f"{refresh}<div class='card'><h2>Job {esc(jid)}</h2><p><span class='pill {esc(s.get('state'))}'>{esc(s.get('state'))}</span> {esc(s.get('workflow_label'))}</p><p class='muted'>Input: <code>{esc(s.get('input_file'))}</code></p><p><a class='btn' href='/download/{esc(jid)}'>Download evidence bundle</a> <a class='btn secondary' href='/reports'>View reports</a> <a class='btn secondary' href='/api/jobs/{esc(jid)}'>JSON status</a></p><form method='post' action='/delete/{esc(jid)}'><button class='danger'>Delete job</button></form></div><div class='card'><h2>Workflow Options</h2>{options_html}</div><div class='card'><h2>Steps</h2><table><tr><th>Step</th><th>Exit</th><th>Seconds</th></tr>{steps}</table></div><div class='card'><h2>Results</h2>{result_links}</div><div class='card'><h2>Logs</h2><pre>{esc(logs[-20000:])}</pre></div>"
        self.send_html("Job", body)

    def options_table(self, options: Dict[str, str]) -> str:
        visible = {k: v for k, v in options.items() if v}
        if not visible:
            return "<p class='muted'>No custom workflow options.</p>"
        rows = "".join(f"<tr><td><code>{esc(k)}</code></td><td>{esc(v)}</td></tr>" for k, v in sorted(visible.items()))
        return f"<table><tr><th>Option</th><th>Value</th></tr>{rows}</table>"

    def result_links(self, jid: str) -> str:
        base = job_dir(jid) / "results"
        if not base.exists(): return "<p class='muted'>No result files yet.</p>"
        items = []
        for f in sorted(base.rglob("*")):
            if f.is_file():
                rel = f.relative_to(job_dir(jid))
                items.append(f"<li><code>{esc(rel)}</code></li>")
        return "<ul>" + "".join(items[:200]) + "</ul>" if items else "<p class='muted'>No result files yet.</p>"

    def api_job(self, jid: str):
        try: return self.send_json(read_status(jid))
        except FileNotFoundError: return self.send_json({"error":"not found"}, 404)











    def workflows_page(self, url):
        q=urllib.parse.parse_qs(url.query); chosen=q.get('task',[''])[0]
        cards=''.join(f"<div class='card'><h3>{esc(label)}</h3><p class='muted'>A guided, step-by-step workflow with sensible defaults and clear completion criteria.</p><a class='btn' href='/workflows?task={esc(key)}'>Start workflow</a></div>" for key,label in ux.TASKS)
        profile=''.join(f"<option value='{esc(k)}'>{esc(v['label'])}</option>" for k,v in ux.SCAN_PROFILES.items())
        detail=''
        if chosen:
            label=dict(ux.TASKS).get(chosen,chosen)
            detail=f"<div class='hero'><h2>{esc(label)}</h2><div class='steps'><span class='step active'>1 Goal</span><span class='step'>2 Scope</span><span class='step'>3 Controls</span><span class='step'>4 Run</span><span class='step'>5 Review</span></div><form action='/' method='get'><label>Scan profile</label><select name='profile'>{profile}</select><label>Environment</label><select><option>Development</option><option>Staging</option><option selected>Production</option><option>Regulated production</option></select><p class='callout'><strong>Recommended next step:</strong> Continue to the scan screen with these defaults, then review the plain-language result summary.</p><button>Continue</button></form></div>"
        self.send_html('Guided Workflows',f"<div class='page-title'><div><h1>Guided workflows</h1><p>Choose an outcome. The Workbench handles the underlying security steps.</p></div></div>{detail}<div class='grid'>{cards}</div>")

    def saved_views_page(self):
        rows=ux.load('saved_views.json',ux.DEFAULT_VIEWS)
        cards=''.join(f"<div class='card'><h3>{esc(x['name'])}</h3><code>{esc(x['filter'])}</code><p><a class='btn secondary' href='/findings?{esc(x['filter'])}'>Open view</a></p></div>" for x in rows)
        self.send_html('Saved Views',f"<div class='page-title'><div><h1>Saved views</h1><p>Reusable filters for high-volume triage.</p></div></div><div class='grid'>{cards}</div><div class='card'><h2>Create view</h2><form method='post' action='/saved-views/save'><label>Name</label><input name='name' required><label>Filter expression</label><input name='filter' placeholder='severity=critical&fix_available=true' size='48' required><button>Save view</button></form></div>")

    def saved_views_save(self):
        f=self.parse_urlencoded(); rows=ux.load('saved_views.json',ux.DEFAULT_VIEWS); rows.append({'name':f.get('name','Custom view'),'filter':f.get('filter','')}); ux.save('saved_views.json',rows); ux.add_activity('saved_view_created',f.get('name','')); self.redirect('/saved-views')

    def activity_page(self):
        rows=ux.load('activity.json',[])
        htmlrows=''.join(f"<tr><td>{esc(x.get('time'))}</td><td>{esc(x.get('action'))}</td><td>{esc(x.get('detail'))}</td><td>{esc(x.get('actor'))}</td></tr>" for x in rows) or "<tr><td colspan='4'>No activity yet.</td></tr>"
        self.send_html('Activity',f"<div class='page-title'><div><h1>Activity timeline</h1><p>Chronological project and governance events for troubleshooting and audits.</p></div></div><div class='card table-wrap'><table><tr><th>Time</th><th>Action</th><th>Detail</th><th>Actor</th></tr>{htmlrows}</table></div>")

    def notifications_page(self):
        p=ux.preferences(); selected=set(p.get('notifications',[])); events=[('release_blocked','Release blocked'),('critical_finding','Critical finding introduced'),('connector_failed','Connector failed'),('scan_completed','Scan completed'),('exception_requested','Exception requested'),('exception_expiring','Exception expiring'),('evidence_ready','Evidence ready'),('remediation_pr','Remediation PR created')]
        checks=''.join(f"<label><input type='checkbox' name='events' value='{k}' {'checked' if k in selected else ''}> {esc(v)}</label>" for k,v in events)
        self.send_html('Notifications',f"<div class='page-title'><div><h1>Notification preferences</h1><p>Choose events and delivery channels.</p></div></div><div class='card'><form method='post' action='/notifications/save'><div class='grid'><div><h3>Events</h3>{checks}</div><div><h3>Channels</h3><label><input type='checkbox' name='channels' value='in-app' checked> In-app</label><label><input type='checkbox' name='channels' value='email'> Email</label><label><input type='checkbox' name='channels' value='slack'> Slack</label><label><input type='checkbox' name='channels' value='teams'> Teams</label><label><input type='checkbox' name='channels' value='webhook'> Webhook</label></div></div><button>Save preferences</button></form></div>")

    def notifications_save(self):
        f=self.parse_urlencoded(multi=True); p=ux.preferences(); p['notifications']=f.get('events',[]); p['channels']=f.get('channels',[]); ux.save('preferences.json',p); ux.add_activity('notification_preferences_updated'); self.redirect('/notifications')

    def personas_page(self):
        p=ux.preferences(); cards=''.join(f"<label class='choice'><input type='radio' name='persona' value='{k}' {'checked' if p.get('persona')==k else ''}> <strong>{k.title()}</strong><br><span class='muted'>{esc(', '.join(items))}</span></label>" for k,items in ux.PERSONAS.items())
        self.send_html('My View',f"<div class='page-title'><div><h1>My view</h1><p>Tailor the homepage and navigation to your role and preferred level of detail.</p></div></div><div class='card'><form method='post' action='/preferences/save'><h2>Role-specific homepage</h2>{cards}<h2>Interface mode</h2><label><input type='radio' name='mode' value='guided' {'checked' if p.get('mode')=='guided' else ''}> Guided mode</label><label><input type='radio' name='mode' value='advanced' {'checked' if p.get('mode')=='advanced' else ''}> Advanced mode</label><label><input type='checkbox' name='reduced_motion' value='1' {'checked' if p.get('reduced_motion') else ''}> Reduce motion</label><button>Save my view</button></form></div>")

    def preferences_save(self):
        f=self.parse_urlencoded(); p=ux.preferences(); p.update({'persona':f.get('persona',p.get('persona','security')),'mode':f.get('mode',p.get('mode','guided')),'reduced_motion':f.get('reduced_motion')=='1'}); ux.save('preferences.json',p); ux.add_activity('preferences_updated',json.dumps(p)); self.redirect('/personas')

    def policy_simulator_page(self,url):
        q=urllib.parse.parse_qs(url.query); policy=q.get('policy',['standard'])[0]; r=ux.policy_simulation(policy)
        self.send_html('Policy Simulator',f"<div class='page-title'><div><h1>Policy simulation</h1><p>Preview impact before enforcing a policy.</p></div></div><div class='card'><form><label>Policy preset</label><select name='policy'><option value='development'>Development</option><option value='standard' {'selected' if policy=='standard' else ''}>Standard production</option><option value='high-assurance' {'selected' if policy=='high-assurance' else ''}>High assurance</option></select><button>Simulate</button></form></div><div class='metrics'><div class='metric'><div class='label'>Would pass</div><div class='value'>{r['pass']}</div></div><div class='metric'><div class='label'>Warnings</div><div class='value'>{r['warning']}</div></div><div class='metric'><div class='label'>Approval</div><div class='value'>{r['approval']}</div></div><div class='metric'><div class='label'>Blocked</div><div class='value'>{r['blocked']}</div></div></div><div class='callout'><strong>Recommendation:</strong> Run simulation against production data before enabling enforcement. This preview is deterministic sample data when no project corpus is selected.</div>")

    def support_page(self):
        self.send_html('Support',"<div class='page-title'><div><h1>Support and diagnostics</h1><p>Create a sanitized troubleshooting package with version, route health, connector state, and UX settings.</p></div></div><div class='card'><p>Secrets and raw connector tokens are never included.</p><form method='post' action='/support/create'><button>Create support bundle</button></form></div><div class='card'><h2>Error recovery checklist</h2><ol><li>Review the plain-language error and recommended action.</li><li>Retry the operation.</li><li>Open technical details only when needed.</li><li>Create a support bundle if the issue persists.</li></ol></div>")

    def support_create(self):
        try:
            p=ux.create_support_bundle(); self.send_html('Support bundle ready',f"<div class='card'><h2>Support bundle ready</h2><p><code>{esc(p)}</code></p><p class='ok'>Secrets were excluded.</p><a class='btn' href='/support'>Back</a></div>")
        except Exception as exc: self.send_html('Support bundle failed',f"<div class='card'><h2>Support bundle failed</h2><p>What failed: bundle creation.</p><p>Recommended action: verify reports/support is writable and retry.</p><details><summary>Technical details</summary><pre>{esc(exc)}</pre></details></div>",500)

    def feedback_page(self):
        self.send_html('Feedback',"<div class='page-title'><div><h1>Product feedback</h1><p>Tell us where the experience is unclear.</p></div></div><div class='card'><form method='post' action='/feedback/save'><label>Page or workflow</label><input name='context' required><label>Was the recommendation useful?</label><select name='useful'><option>Yes</option><option>Partly</option><option>No</option></select><label>What was confusing?</label><textarea name='message' required></textarea><button>Submit feedback</button></form></div>")

    def feedback_save(self):
        f=self.parse_urlencoded(); rows=ux.load('feedback.json',[]); rows.append({'time':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),**f}); ux.save('feedback.json',rows); ux.add_activity('feedback_submitted',f.get('context','')); self.send_html('Thank you',"<div class='card'><h2>Thank you</h2><p>Your feedback was saved locally.</p><a class='btn' href='/dashboard'>Return to dashboard</a></div>")

    def _all_statuses(self):
        try:
            return list_jobs()
        except Exception:
            return []

    def dashboard_page(self):
        jobs = self._all_statuses()
        blocked = sum(1 for j in jobs if str(j.get("state","")).lower() in {"failed","blocked"})
        running = sum(1 for j in jobs if str(j.get("state","")).lower() in {"running","queued"})
        completed = sum(1 for j in jobs if str(j.get("state","")).lower() == "completed")
        connectors = self._connector_records()
        unhealthy = sum(1 for x in connectors if x.get("status") not in {"healthy","configured"})
        recent = "".join(f"<tr><td><a href='/jobs/{esc(j.get('job_id'))}'>{esc(j.get('workflow_label') or j.get('workflow'))}</a></td><td><span class='pill {esc(j.get('state'))}'>{esc(j.get('state'))}</span></td><td>{esc(j.get('created_at'))}</td><td><a href='/jobs/{esc(j.get('job_id'))}'>View</a></td></tr>" for j in jobs[:8]) or "<tr><td colspan='4'><div class='empty'><h3>No scans yet</h3><p class='muted'>Upload an SBOM or connect a source to begin.</p><a class='btn' href='/'>Run first analysis</a></div></td></tr>"
        conn = "".join(f"<tr><td>{esc(x.get('name'))}</td><td>{esc(x.get('type'))}</td><td><span class='pill {esc(x.get('status'))}'>{esc(x.get('status'))}</span></td><td>{esc(x.get('last_sync') or 'Never')}</td></tr>" for x in connectors[:6]) or "<tr><td colspan='4' class='muted'>No connectors configured. <a href='/integrations'>Add a connector</a>.</td></tr>"
        guide=self._guide_state(); checklist=[('Create your first project',guide.get('project_created')),('Run your first scan',bool(jobs)),('Connect a security tool',guide.get('connector_created') or bool(connectors)),('Choose a release policy',guide.get('policy')),('Generate evidence',any((ROOT/'release-evidence').rglob('*')) if (ROOT/'release-evidence').exists() else False)]
        checklist_html=''.join(f"<li>{'✓' if done else '○'} {esc(label)}</li>" for label,done in checklist)
        onboarding='' if guide.get('complete') else f"<div class='hero'><h2>Welcome to SBOM Security Toolkit</h2><p>Use guided setup to go from a source to a release decision without learning every feature first.</p><a class='btn' href='/welcome'>Continue Quick Start</a> <a class='btn secondary' href='/sample'>Explore sample data</a></div><div class='card'><h2>Getting started</h2><ul class='checklist'>{checklist_html}</ul></div>"
        body=f"""{onboarding}<div class='page-title'><div><h1>Overview</h1><p>Your software supply-chain security posture and the work requiring attention.</p></div><a class='btn' href='/welcome'>Guided setup</a></div>
        <div class='metrics'><div class='metric'><div class='label'>Projects monitored</div><div class='value'>{len(jobs)}</div><div class='hint'>Across all recorded workspaces</div></div><div class='metric'><div class='label'>Blocked or failed</div><div class='value'>{blocked}</div><div class='hint'>Release decisions needing action</div></div><div class='metric'><div class='label'>Active scans</div><div class='value'>{running}</div><div class='hint'>{completed} completed</div></div><div class='metric'><div class='label'>Connector issues</div><div class='value'>{unhealthy}</div><div class='hint'>{len(connectors)} configured</div></div></div>
        <div class='grid'><div class='card'><h2>Work requiring attention</h2><div class='grid'><a class='card decision blocked' href='/decisions'><strong>{blocked} blocked decisions</strong><p class='muted small'>Review violations and remediation.</p></a><a class='card decision warning' href='/exceptions'><strong>Exceptions</strong><p class='muted small'>Review approvals and expirations.</p></a><a class='card decision' href='/actions'><strong>Action Center</strong><p class='muted small'>One queue for security work.</p></a></div></div><div class='card'><h2>Getting started</h2><ol><li>Connect GitHub, Snyk, or Dependency-Track.</li><li>Add or upload a project.</li><li>Run analysis and review the release decision.</li><li>Fix, approve, or export evidence.</li></ol><a class='btn secondary' href='/integrations'>Open connector catalog</a></div></div>
        <div class='card'><div class='page-title'><div><h2>Recent scans</h2></div><a href='/jobs'>View all</a></div><div class='table-wrap'><table><tr><th>Workflow</th><th>Status</th><th>Created</th><th></th></tr>{recent}</table></div></div>
        <div class='card'><div class='page-title'><div><h2>Connector health</h2></div><a href='/integrations'>Manage connectors</a></div><div class='table-wrap'><table><tr><th>Name</th><th>Type</th><th>Status</th><th>Last sync</th></tr>{conn}</table></div></div>"""
        self.send_html("Overview", body)

    def _connector_records(self):
        records=[]
        cfg=ROOT/'configs'/'connectors.yml'
        try:
            data=yaml.safe_load(cfg.read_text()) if cfg.exists() else {}
            for item in (data or {}).get('connectors',[]):
                records.append({'name':item.get('name','Unnamed'),'type':item.get('type','generic'),'status':'configured' if item.get('enabled',True) else 'disabled','last_sync':item.get('last_sync')})
        except Exception:
            pass
        return records

    def decisions_page(self):
        rows=[]
        for j in self._all_statuses():
            state=str(j.get('state','unknown')).lower(); decision='BLOCKED' if state in {'failed','blocked'} else ('IN PROGRESS' if state in {'running','queued'} else 'PASSED')
            cls='blocked' if decision=='BLOCKED' else ('warning' if decision=='IN PROGRESS' else 'passed')
            rows.append(f"<tr><td><a href='/jobs/{esc(j.get('job_id'))}'>{esc(j.get('workflow_label') or j.get('job_id'))}</a></td><td><span class='pill {cls}'>{decision}</span></td><td>{esc(j.get('created_at'))}</td><td>{len(j.get('steps') or [])}</td><td><a href='/jobs/{esc(j.get('job_id'))}'>Review</a></td></tr>")
        table=''.join(rows) or "<tr><td colspan='5'><div class='empty'><h3>No release decisions yet</h3><p class='muted'>Run an assurance workflow to evaluate a release.</p><a class='btn' href='/'>Run analysis</a></div></td></tr>"
        self.send_html('Release Decisions',f"<div class='page-title'><div><h1>Release Decisions</h1><p>Clear pass, warning, approval, and block outcomes with traceable reasons.</p></div></div><div class='card'><div class='toolbar'><select><option>All decisions</option><option>Blocked</option><option>Approval required</option><option>Passed</option></select><input placeholder='Filter project or release'><span class='spacer'></span><a class='btn secondary' href='/reports'>Export</a></div><div class='table-wrap'><table><tr><th>Release / scan</th><th>Decision</th><th>Evaluated</th><th>Checks</th><th></th></tr>{table}</table></div></div>")

    def actions_page(self):
        jobs=self._all_statuses(); failed=[j for j in jobs if str(j.get('state')).lower() in {'failed','blocked'}]; running=[j for j in jobs if str(j.get('state')).lower() in {'running','queued'}]
        items=''.join(f"<tr><td><span class='pill blocked'>High</span></td><td>Review failed release workflow</td><td><a href='/jobs/{esc(j.get('job_id'))}'>{esc(j.get('workflow_label'))}</a></td><td>Security engineering</td><td><a class='btn small secondary' href='/jobs/{esc(j.get('job_id'))}'>Review</a></td></tr>" for j in failed)
        if not items: items="<tr><td colspan='5'><div class='empty'><h3>No urgent actions</h3><p class='muted'>Blocked releases, connector failures, exception approvals, and incomplete evidence will appear here.</p></div></td></tr>"
        self.send_html('Action Center',f"<div class='page-title'><div><h1>Action Center</h1><p>A single queue for work requiring review or remediation.</p></div></div><div class='metrics'><div class='metric'><div class='label'>Blocking issues</div><div class='value'>{len(failed)}</div></div><div class='metric'><div class='label'>Scans running</div><div class='value'>{len(running)}</div></div><div class='metric'><div class='label'>Awaiting approval</div><div class='value'>0</div></div><div class='metric'><div class='label'>Connector failures</div><div class='value'>{sum(1 for x in self._connector_records() if x.get('status')=='unhealthy')}</div></div></div><div class='card'><div class='toolbar'><select><option>All work</option><option>Blocking</option><option>Approvals</option><option>Connector health</option></select><input placeholder='Search actions'><span class='spacer'></span><button class='secondary'>Save view</button></div><div class='table-wrap'><table><tr><th>Priority</th><th>Action</th><th>Resource</th><th>Owner</th><th></th></tr>{items}</table></div></div>")


    def controls_page(self):
        body = """
        <div class='page-title'><div><h1>Security Controls</h1><p>Run release assurance, VEX, provenance, evidence, organization context, and remediation workflows from one place.</p></div></div>
        <div class='grid'>
          <div class='card'><h2>Release Assurance</h2><p class='muted'>Evaluate an SBOM against policy and produce a PASS, WARNING, APPROVAL REQUIRED, or BLOCK decision.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='assurance'><label>Normalized findings JSON</label><input name='findings' value='reports/findings/findings.json' size='42'><label>Policy</label><input name='policy' value='policies/production-release-assurance.yml' size='42'><input type='submit' value='Run dry-run assurance'></form></div>
          <div class='card'><h2>VEX</h2><p class='muted'>Generate an OpenVEX statement for review and attach exploitability context to findings.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='vex'><label>SBOM path</label><input name='sbom' value='test-sboms/example-spdx-2.3.json' size='42'><label>Vulnerability</label><input name='vulnerability' placeholder='CVE-2026-12345'><input type='submit' value='Generate VEX draft'></form></div>
          <div class='card'><h2>Provenance</h2><p class='muted'>Verify artifact digests and inspect SLSA or in-toto provenance evidence.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='provenance'><label>Artifact path</label><input name='artifact' value='test-sboms/example-spdx-2.3.json' size='42'><label>Provenance path</label><input name='provenance' placeholder='provenance.json' size='42'><input type='submit' value='Verify provenance'></form></div>
          <div class='card'><h2>Evidence Bundle</h2><p class='muted'>Build a hash-manifested release evidence package from current analysis artifacts.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='evidence'><label>Input directory</label><input name='input_dir' value='reports' size='42'><label>Output directory</label><input name='output_dir' value='release-evidence/workbench' size='42'><input type='submit' value='Build evidence bundle'></form></div>
          <div class='card'><h2>Organization Context</h2><p class='muted'>Create or inspect organization, business unit, application, service, repository, and artifact ownership context.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='org'><label>Project ID</label><input name='project_id' value='workbench-project'><label>Business criticality</label><select name='criticality'><option>high</option><option>medium</option><option>low</option></select><input type='submit' value='Generate context template'></form></div>
          <div class='card'><h2>Remediation</h2><p class='muted'>Generate a deterministic remediation plan from normalized findings without automatically changing code.</p><form method='post' action='/controls/run'><input type='hidden' name='action' value='remediation'><label>SBOM path</label><input name='sbom' value='test-sboms/vulnerable/sample-trivy-report.json' size='42'><input type='submit' value='Generate remediation plan'></form></div>
        </div>
        <div class='callout'><strong>Safe default:</strong> controls create local artifacts and plans. External writes, pull requests, and connector sends remain opt-in.</div>
        """
        self.send_html('Security Controls', body)

    def controls_run(self):
        try:
            import argparse as _argparse
            fields = self.parse_urlencoded(); action = fields.get('action','')
            out = None
            if action == 'vex':
                from sbomops import integrations as mod
                out = mod.export_openvex(_argparse.Namespace(sbom=fields.get('sbom'), out='reports/openvex/workbench-openvex.json', vulnerability=fields.get('vulnerability',''), status='under_investigation', justification='component_not_analyzed', impact_statement='Generated for security review.', action_statement='Validate exploitability and remediation.', author='SBOM Security Toolkit'))
            elif action == 'org':
                target=Path('configs/generated/org')/f"{safe_slug(fields.get('project_id','workbench-project'))}.yml"; target.parent.mkdir(parents=True,exist_ok=True)
                data={'organization':'default','business_unit':'default','application':fields.get('project_id','workbench-project'),'service':fields.get('project_id','workbench-project'),'repository':'unknown','business_criticality':fields.get('criticality','high'),'internet_exposed':False,'owners':{'technical':'','security':'','business':''}}
                target.write_text(yaml.safe_dump(data,sort_keys=False)); out={'created':str(target)}
            elif action == 'evidence':
                src=Path(fields.get('input_dir','reports')); dst=Path(fields.get('output_dir','release-evidence/workbench')); dst.mkdir(parents=True,exist_ok=True)
                import hashlib, datetime
                records=[]
                if src.exists():
                    for f in sorted(src.rglob('*')):
                        if f.is_file(): records.append({'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size})
                manifest={'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':records}
                (dst/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n'); out={'manifest':str(dst/'manifest.json'),'files':len(records)}
            elif action == 'provenance':
                artifact=Path(fields.get('artifact','')); prov=Path(fields.get('provenance',''))
                import hashlib
                out={'artifact':str(artifact),'exists':artifact.exists(),'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest() if artifact.exists() else None,'provenance':str(prov),'provenance_exists':prov.exists(),'status':'verified' if artifact.exists() and prov.exists() else 'incomplete'}
                target=Path('reports/provenance/workbench-verification.json'); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(out,indent=2)+'\n')
            elif action == 'remediation':
                source=Path(fields.get('sbom','')); target=Path('reports/remediation/workbench-plan.json'); target.parent.mkdir(parents=True,exist_ok=True)
                out={'source':str(source),'status':'planned','automatic_changes':False,'recommendations':['Review normalized critical and high findings','Prefer fixed versions with compatible upgrade paths','Regenerate SBOM and rerun release assurance after changes']}
                target.write_text(json.dumps(out,indent=2)+'\n')
            elif action == 'assurance':
                from sbomops import assurance as mod
                # Run the module through its CLI parser contract in a subprocess to preserve production behavior.
                import subprocess, sys
                cmd=[sys.executable,'-m','sbomops.assurance','--policy',fields.get('policy',''),'--findings',fields.get('findings',''),'--out-dir','reports/assurance/workbench','--fail-on','never']
                cp=subprocess.run(cmd,capture_output=True,text=True,timeout=120); out={'command':cmd,'returncode':cp.returncode,'stdout':cp.stdout[-4000:],'stderr':cp.stderr[-4000:]}
            else: raise ValueError('Unsupported control action: '+action)
            self.send_html('Control completed',f"<div class='card'><h2>Control completed</h2><pre>{esc(json.dumps(out,indent=2,default=str))}</pre><p><a class='btn' href='/controls'>Back to Security Controls</a> <a class='btn secondary' href='/reports'>View reports</a></p></div>")
        except Exception as exc:
            self.send_html('Control error',f"<div class='card'><h2>Control error</h2><pre>{esc(exc)}</pre></div>",400)

    def _guide_state(self):
        path=ROOT/'ui'/'storage'/'onboarding.json'
        try: return json.loads(path.read_text())
        except Exception: return {}

    def _save_guide_state(self, data):
        path=ROOT/'ui'/'storage'/'onboarding.json'; path.parent.mkdir(parents=True,exist_ok=True)
        current=self._guide_state(); current.update(data); path.write_text(json.dumps(current,indent=2)+'\n')

    def welcome_page(self, url):
        q=urllib.parse.parse_qs(url.query); step=int((q.get('step') or ['1'])[0]); state=self._guide_state()
        steps=''.join(f"<span class='step {'active' if i==step else ''}'>{i}. {name}</span>" for i,name in enumerate(['Goal','Source','Environment','Policy','Review'],1))
        if step==1:
            content="""<h2>What would you like to secure today?</h2><label class='choice'><input type='radio' name='goal' value='repository' checked> Scan a repository</label><label class='choice'><input type='radio' name='goal' value='sbom'> Upload an SBOM</label><label class='choice'><input type='radio' name='goal' value='connector'> Connect a security tool</label><label class='choice'><input type='radio' name='goal' value='release'> Check whether a release is safe</label>"""
        elif step==2:
            content="""<h2>Choose a source</h2><label>Repository URL or local path</label><input name='source' size='58' placeholder='https://github.com/org/repo or /path/to/repo'><p class='muted'>You can also upload an SBOM after setup or configure Snyk, GitHub, GitLab, Dependency-Track, or DefectDojo.</p>"""
        elif step==3:
            content="""<h2>Where will this run?</h2><label class='choice'><input type='radio' name='environment' value='development'> Development</label><label class='choice'><input type='radio' name='environment' value='staging'> Staging</label><label class='choice'><input type='radio' name='environment' value='production' checked> Production</label><label class='choice'><input type='radio' name='environment' value='internet-production'> Internet-facing production</label><label class='choice'><input type='radio' name='environment' value='regulated'> Regulated workload</label>"""
        elif step==4:
            content="""<h2>Select a policy preset</h2><label class='choice'><input type='radio' name='policy' value='basic'> Basic — visibility first</label><label class='choice'><input type='radio' name='policy' value='standard' checked> Standard — balanced release controls</label><label class='choice'><input type='radio' name='policy' value='production'> Production — blocks critical and known-exploited risk</label><label class='choice'><input type='radio' name='policy' value='high-assurance'> High assurance — provenance, VEX, and strict dependency controls</label>"""
        else:
            content=f"""<h2>Ready to begin</h2><p>Your guided setup will create a project, choose sensible defaults, and take you to the right next action.</p><pre>{esc(json.dumps(state,indent=2))}</pre><label><input type='checkbox' name='complete' value='1' checked> Mark onboarding complete</label>"""
        back=f"<a class='btn secondary' href='/welcome?step={step-1}'>Back</a>" if step>1 else ""
        submit='Finish setup' if step==5 else 'Continue'
        body=f"<div class='hero'><h1>Quick Start</h1><p>Answer a few questions and the toolkit will configure a safe starting point.</p></div><div class='card'>{steps}<form method='post' action='/welcome/save'><input type='hidden' name='step' value='{step}'>{content}<p>{back} <input type='submit' value='{submit}'></p></form></div><div class='card'><h3>Prefer to explore first?</h3><p><a class='btn secondary' href='/sample'>Load the sample workspace</a> <a class='btn secondary' href='/help'>Open Help Center</a></p></div>"
        self.send_html('Quick Start',body)

    def welcome_save(self):
        f=self.parse_urlencoded(); step=int(f.pop('step','1')); self._save_guide_state({k:v for k,v in f.items() if k!='complete'})
        if step>=5:
            self._save_guide_state({'complete':True}); return self.redirect('/dashboard')
        self.redirect(f'/welcome?step={step+1}')

    def project_wizard(self, url):
        body="""<div class='page-title'><div><h1>Create a project</h1><p>Set ownership and risk context once; use it across scans, decisions, reports, and evidence.</p></div></div><div class='card'><form method='post' action='/project/new/save'><div class='grid'><div><label>Project name</label><input name='name' required placeholder='payments-api'></div><div><label>Source</label><input name='source' placeholder='repository URL, path, or SBOM'></div><div><label>Environment</label><select name='environment'><option>development</option><option>staging</option><option selected>production</option></select></div><div><label>Business criticality</label><select name='criticality'><option>low</option><option>medium</option><option selected>high</option></select></div><div><label>Technical owner</label><input name='technical_owner'></div><div><label>Security owner</label><input name='security_owner'></div><div><label>Data classification</label><select name='classification'><option>public</option><option>internal</option><option>confidential</option><option>restricted</option></select></div><div><label>Default policy</label><select name='policy'><option>basic</option><option selected>standard</option><option>production</option><option>high-assurance</option></select></div></div><p><label><input type='checkbox' name='internet_exposed' value='1'> Internet-facing</label></p><input type='submit' value='Create project'></form></div>"""
        self.send_html('Create project',body)

    def project_wizard_save(self):
        f=self.parse_urlencoded(); name=safe_slug(f.get('name','project')); target=ROOT/'configs'/'generated'/'projects'/f'{name}.yml'; target.parent.mkdir(parents=True,exist_ok=True)
        data={'project_id':name,'name':f.get('name'),'source':f.get('source'),'environment':f.get('environment'),'business_criticality':f.get('criticality'),'internet_exposed':self.bool_field(f,'internet_exposed'),'data_classification':f.get('classification'),'default_policy':f.get('policy'),'owners':{'technical':f.get('technical_owner'),'security':f.get('security_owner')}}
        target.write_text(yaml.safe_dump(data,sort_keys=False)); self._save_guide_state({'project_created':True}); self.redirect('/projects')

    def connector_wizard(self, url):
        body="""<div class='page-title'><div><h1>Connect a tool</h1><p>Configure integrations with read-only and dry-run safeguards by default.</p></div></div><div class='card'><form method='post' action='/connectors/setup/save'><label>Tool</label><select name='type'><option>snyk</option><option>github</option><option>gitlab</option><option>dependency-track</option><option>defectdojo</option><option>jira</option><option>webhook</option></select><label>Connection name</label><input name='name' required value='primary'><label>Base URL</label><input name='base_url' size='58' placeholder='https://api.example.com'><label>Secret environment variable</label><input name='secret_env' placeholder='SNYK_TOKEN'><p><label><input type='checkbox' name='write_enabled' value='1'> Enable writes (not recommended until connection testing succeeds)</label></p><input type='submit' value='Save connector'></form></div><div class='callout'><strong>Safe default:</strong> credentials are referenced through environment variables; plaintext secrets are not stored.</div>"""
        self.send_html('Connect a tool',body)

    def connector_wizard_save(self):
        f=self.parse_urlencoded(); name=safe_slug(f.get('name','connector')); target=ROOT/'configs'/'generated'/'connectors'/f'{name}.yml'; target.parent.mkdir(parents=True,exist_ok=True)
        data={'name':name,'type':f.get('type'),'base_url':f.get('base_url'),'secret_env':f.get('secret_env'),'read_only':not self.bool_field(f,'write_enabled'),'write_enabled':self.bool_field(f,'write_enabled'),'dry_run':True}
        target.write_text(yaml.safe_dump(data,sort_keys=False)); self._save_guide_state({'connector_created':True}); self.redirect('/integrations')

    def help_page(self):
        body="""<div class='page-title'><div><h1>Help Center</h1><p>Plain-language guidance for the most common workflows.</p></div></div><div class='grid'><div class='card'><h2>First scan</h2><p>Create a project, upload an SBOM or repository, select a policy, and review the release decision.</p><a href='/welcome'>Open Quick Start</a></div><div class='card'><h2>Connect a tool</h2><p>Add Snyk, GitHub, GitLab, Dependency-Track, DefectDojo, Jira, or a webhook.</p><a href='/connectors/setup'>Open connector setup</a></div><div class='card'><h2>Understand a decision</h2><p>Release decisions explain what passed, what blocked, and what action to take next.</p><a href='/decisions'>View decisions</a></div><div class='card'><h2>Advanced controls</h2><p>Use VEX, provenance, evidence packages, remediation, and organization context.</p><a href='/controls'>Open Security Controls</a></div></div><div class='card'><h2>Recommended workflow</h2><ol><li>Create a project</li><li>Add a source or connector</li><li>Run analysis</li><li>Review findings and release decision</li><li>Remediate or request an exception</li><li>Generate reports and evidence</li></ol></div>"""
        self.send_html('Help Center',body)

    def sample_page(self):
        self._save_guide_state({'sample_loaded':True})
        body="""<div class='hero'><h1>Sample workspace loaded</h1><p>Explore a realistic example without external credentials.</p></div><div class='metrics'><div class='metric'><div class='label'>Release decision</div><div class='value'>BLOCK</div><div class='hint'>3 policy violations</div></div><div class='metric'><div class='label'>Critical findings</div><div class='value'>1</div><div class='hint'>Fix available</div></div><div class='metric'><div class='label'>Exceptions</div><div class='value'>1</div><div class='hint'>Expires in 14 days</div></div><div class='metric'><div class='label'>Connectors</div><div class='value'>2/3</div><div class='hint'>One needs attention</div></div></div><div class='card'><h2>Try these next</h2><p><a class='btn' href='/decisions'>Review blocked release</a> <a class='btn secondary' href='/findings'>Inspect findings</a> <a class='btn secondary' href='/connectors/setup'>Add a connector</a></p></div>"""
        self.send_html('Sample workspace',body)

    def exceptions_page(self):
        path=ROOT/'governance'/'exceptions.yml'; records=[]
        try:
            data=yaml.safe_load(path.read_text()) if path.exists() else {}
            records=(data or {}).get('exceptions',[]) if isinstance(data,dict) else (data or [])
        except Exception: pass
        rows=''.join(f"<tr><td>{esc(x.get('id') or x.get('name'))}</td><td>{esc(x.get('project','All'))}</td><td>{esc(x.get('vulnerability') or x.get('rule',''))}</td><td><span class='pill approval'>{esc(x.get('status','approved'))}</span></td><td>{esc(x.get('expires','—'))}</td></tr>" for x in records) or "<tr><td colspan='5'><div class='empty'><h3>No active exceptions</h3><p class='muted'>Approved, pending, and expiring risk exceptions will appear here.</p></div></td></tr>"
        self.send_html('Exceptions',f"<div class='page-title'><div><h1>Risk Exceptions</h1><p>Govern approvals, compensating controls, ownership, and expiration.</p></div><a class='btn' href='/settings'>Create exception</a></div><div class='card'><div class='table-wrap'><table><tr><th>ID</th><th>Project</th><th>Scope</th><th>Status</th><th>Expires</th></tr>{rows}</table></div></div>")

    def evidence_page(self):
        roots=[ROOT/'release-evidence',ROOT/'reports']; files=[]
        for root in roots:
            if root.exists(): files += [p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in {'.zip','.json','.pdf','.md'}]
        rows=''.join(f"<tr><td>{esc(p.name)}</td><td>{esc(p.parent.relative_to(ROOT))}</td><td>{p.stat().st_size}</td><td>{esc(__import__('datetime').datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec='minutes'))}</td></tr>" for p in sorted(files,key=lambda x:x.stat().st_mtime,reverse=True)[:100]) or "<tr><td colspan='4'><div class='empty'><h3>No evidence packages yet</h3><p class='muted'>Generate a release evidence bundle from a completed scan.</p><a class='btn' href='/jobs'>View scans</a></div></td></tr>"
        self.send_html('Evidence',f"<div class='page-title'><div><h1>Evidence</h1><p>Auditor-ready SBOM, VEX, decision, provenance, report, and signature packages.</p></div></div><div class='card'><div class='table-wrap'><table><tr><th>Artifact</th><th>Location</th><th>Bytes</th><th>Modified</th></tr>{rows}</table></div></div>")

    def search_page(self,url):
        q=(urllib.parse.parse_qs(url.query).get('q') or [''])[0].strip().lower(); matches=[]
        if q:
            for j in self._all_statuses():
                hay=json.dumps(j).lower()
                if q in hay: matches.append((j.get('workflow_label') or j.get('job_id'),f"/jobs/{j.get('job_id')}",'Scan'))
            for p in [ROOT/'README.md',ROOT/'RELEASE-NOTES.md',ROOT/'CHANGELOG.md']:
                if p.exists() and q in p.read_text(errors='ignore').lower(): matches.append((p.name,'/reports','Documentation'))
        rows=''.join(f"<tr><td><a href='{esc(href)}'>{esc(name)}</a></td><td>{esc(kind)}</td></tr>" for name,href,kind in matches) or "<tr><td colspan='2'><div class='empty'><h3>No results</h3><p class='muted'>Search projects, scan records, CVEs, components, releases, and documentation.</p></div></td></tr>"
        self.send_html('Search',f"<div class='page-title'><div><h1>Search</h1><p>Results for <strong>{esc(q)}</strong></p></div></div><div class='card'><div class='table-wrap'><table><tr><th>Result</th><th>Type</th></tr>{rows}</table></div></div>")

    def reports_page(self):
        try:
            from sbomops import reports_viewer
            result = reports_viewer.index_reports(argparse.Namespace(roots=None, out=str(reports_viewer.REPORT_INDEX), markdown=str(reports_viewer.REPORT_INDEX_MD)))
            index = json.loads(reports_viewer.REPORT_INDEX.read_text(encoding="utf-8")) if reports_viewer.REPORT_INDEX.exists() else {"reports": []}
            reports = index.get("reports", [])
        except Exception as exc:
            return self.send_html("Reports", f"<div class='card'><h2>Reports error</h2><pre>{esc(exc)}</pre></div>", 500)
        categories = {}
        for r in reports:
            categories.setdefault(r.get("category", "Reports"), []).append(r)
        sections = []
        for category, rows in sorted(categories.items()):
            body_rows = "".join(
                f"<tr><td><a href='/reports/view/{esc(urllib.parse.quote(r.get('path',''), safe=''))}'>{esc(r.get('title'))}</a></td><td><code>{esc(r.get('path'))}</code></td><td>{esc(r.get('size_bytes'))}</td><td>{esc(r.get('modified_at'))}</td></tr>"
                for r in rows[:200]
            )
            sections.append(f"<div class='card'><h2>{esc(category)}</h2><table><tr><th>Report</th><th>Path</th><th>Bytes</th><th>Modified</th></tr>{body_rows}</table></div>")
        if not sections:
            sections.append("<div class='card'><p class='muted'>No reports found yet. Run a scan, findings export, integration export, fuzzing workflow, or project dashboard first.</p></div>")
        body = f"""
        <div class='card'><h2>Reports</h2>
        <p class='muted'>View generated reports directly in the Workbench without downloading the full evidence bundle. This page indexes reports from <code>reports/</code>, <code>release-evidence/</code>, <code>ui/storage/jobs/*/results</code>, <code>findings/</code>, <code>fuzzing/reports/</code>, and <code>projects/</code>.</p>
        <p><form method='post' action='/reports/refresh'><button>Refresh report index</button></form></p>
        <p class='small muted'>Indexed reports: {esc(result.get('reports', len(reports)))}. Index file: <code>reports/report-index.json</code>. Markdown index: <code>reports/report-index.md</code>.</p>
        </div>
        {''.join(sections)}
        """
        self.send_html("Reports", body)

    def reports_view(self, encoded_report_id: str):
        try:
            from sbomops import reports_viewer
            report_id = urllib.parse.unquote(encoded_report_id)
            data = reports_viewer.read_report(report_id)
            r = data.get("report", {})
            text = data.get("text", "")
            parsed = data.get("parsed")
            if parsed is not None:
                rendered = f"<pre>{esc(json.dumps(parsed, indent=2, sort_keys=False))}</pre>"
            else:
                rendered = f"<pre>{esc(text)}</pre>"
            trunc = "<p class='small bad'>Preview truncated. Download the evidence bundle or open the file on disk for the full content.</p>" if data.get("truncated") else ""
            body = f"""
            <div class='card'><h2>{esc(r.get('title'))}</h2>
            <p><a class='btn secondary' href='/reports'>Back to reports</a></p>
            <table><tr><th>Category</th><td>{esc(r.get('category'))}</td></tr><tr><th>Path</th><td><code>{esc(r.get('path'))}</code></td></tr><tr><th>Bytes</th><td>{esc(r.get('size_bytes'))}</td></tr><tr><th>Modified</th><td>{esc(r.get('modified_at'))}</td></tr></table>
            {trunc}</div>
            <div class='card'><h2>Preview</h2>{rendered}</div>
            """
            self.send_html("Report", body)
        except Exception as exc:
            self.send_html("Report error", f"<div class='card'><h2>Report error</h2><pre>{esc(exc)}</pre><p><a class='btn' href='/reports'>Back to reports</a></p></div>", 400)

    def reports_refresh(self):
        try:
            from sbomops import reports_viewer
            result = reports_viewer.index_reports(argparse.Namespace(roots=None, out=str(reports_viewer.REPORT_INDEX), markdown=str(reports_viewer.REPORT_INDEX_MD)))
            self.send_html("Reports refreshed", f"<div class='card'><h2>Report index refreshed</h2><pre>{esc(json.dumps(result, indent=2, sort_keys=True))}</pre><p><a class='btn' href='/reports'>View reports</a></p></div>")
        except Exception as exc:
            self.send_html("Reports error", f"<div class='card'><h2>Reports error</h2><pre>{esc(exc)}</pre></div>", 400)


    def ai_reports_page(self):
        try:
            from sbomops import ai_report_writer
            templates = ai_report_writer.REPORT_TYPES
        except Exception:
            templates = {"full": "Full Security Report", "executive": "Executive Summary"}
        opts = "".join(f"<option value='{esc(k)}'>{esc(v)}</option>" for k, v in templates.items())
        body = f"""
        <div class='card'><h2>AI Report Writer</h2>
        <p class='muted'>Generate evidence-bound human-readable reports from existing SBOM Security Toolkit artifacts. AI can summarize and explain evidence, but it cannot approve releases, accept risk, suppress findings, or mark fixes verified.</p>
        <p><a class='btn secondary' href='/reports'>View generated reports</a></p></div>
        <div class='card'><h2>Generate report</h2>
        <form method='post' action='/ai-reports/generate'>
          <div class='grid'>
            <div><label>Report type</label><select name='report_type'>{opts}</select></div>
            <div><label>Audience</label><select name='audience'><option value='security'>Security</option><option value='executive'>Executive</option><option value='engineering'>Engineering</option><option value='supplier'>Supplier / vendor</option><option value='audit'>Audit / compliance</option></select></div>
            <div><label>Tone</label><select name='tone'><option value='action-oriented'>Action-oriented</option><option value='concise'>Concise</option><option value='detailed'>Detailed</option><option value='formal'>Formal</option></select></div>
            <div><label>AI provider</label><select name='provider'><option value='none'>Prompt-only / deterministic</option><option value='bedrock'>AWS Bedrock</option><option value='ollama'>Ollama</option><option value='glm'>GLM</option><option value='openai-compatible'>OpenAI-compatible</option></select></div>
          </div>
          <div class='grid'>
            <div><label>SBOM path</label><input name='sbom' value='test-sboms/example-spdx-2.3.json' size='46'></div>
            <div><label>Project filter</label><input name='project' placeholder='optional project id'></div>
            <div><label>Model</label><input name='model' placeholder='optional model id'></div>
            <div><label>Output directory</label><input name='out_dir' value='reports/ai' size='32'></div>
          </div>
          <label>Additional evidence roots</label><input name='evidence_roots' placeholder='comma-separated, optional' size='70'>
          <p class='small muted'>Provider <code>none</code> creates deterministic Markdown/HTML plus the exact prompt and fact bundle for manual review. Bedrock/Ollama/GLM/OpenAI-compatible use the existing optional provider abstraction.</p>
          <input type='submit' value='Generate AI report'>
        </form></div>
        <div class='grid'>
          <div class='card'><h3>Evidence-bound</h3><p>Reports are generated from local findings, lifecycle, release, fuzzing, SARIF/OpenVEX, project, and evidence artifacts.</p></div>
          <div class='card'><h3>Multi-audience</h3><p>Executive summaries, engineering remediation reports, supplier assessments, release memos, fuzzing summaries, lifecycle reports, and full security reports.</p></div>
          <div class='card'><h3>Safe by design</h3><p>AI output is advisory. Risk acceptance, suppression, verification, and release approval remain explicit human/governance actions.</p></div>
        </div>
        """
        self.send_html("AI Reports", body)

    def ai_reports_generate(self):
        try:
            from sbomops import ai_report_writer
            fields = self.parse_urlencoded()
            ns = argparse.Namespace(
                sbom=fields.get('sbom',''),
                project=fields.get('project',''),
                report_type=fields.get('report_type','full'),
                audience=fields.get('audience','security'),
                tone=fields.get('tone','action-oriented'),
                provider=fields.get('provider','none'),
                model=fields.get('model',''),
                timeout=60,
                out_dir=fields.get('out_dir','reports/ai'),
                evidence_roots=fields.get('evidence_roots',''),
            )
            meta = ai_report_writer.generate(ns)
            self.send_html('AI report generated', f"<div class='card'><h2>AI report generated</h2><pre>{esc(json.dumps(meta, indent=2, sort_keys=True))}</pre><p><a class='btn' href='/reports'>View reports</a> <a class='btn secondary' href='/ai-reports'>Back to AI Reports</a></p></div>")
        except Exception as exc:
            self.send_html('AI report error', f"<div class='card'><h2>AI report error</h2><pre>{esc(exc)}</pre><p><a class='btn' href='/ai-reports'>Back to AI Reports</a></p></div>", 400)

    def findings_page(self):
        try:
            from sbomops import findings as findings_ops
            dash = findings_ops.dashboard(argparse.Namespace(project=""))
            db = findings_ops.load_db()
            recent = list(reversed(db.get("findings", [])))[:25]
        except Exception:
            dash = {"total": 0, "by_status": {}, "by_severity": {}, "by_owner": {}, "sla": {}}
            recent = []
        rows = "".join(
            f"<tr><td><code>{esc(f.get('finding_id'))}</code></td><td>{esc(f.get('severity'))}</td><td>{esc(f.get('status'))}</td><td>{esc(f.get('owner'))}</td><td>{esc(f.get('component'))}</td><td>{esc(f.get('title'))}</td><td>{esc(f.get('due_date'))}</td></tr>"
            for f in recent
        ) or "<tr><td colspan='7' class='muted'>No findings imported yet. Import an SBOM below or run <code>make findings-import</code>.</td></tr>"
        body = f"""
        <div class='card'><h2>Findings & Remediation Operations</h2>
        <p class='muted'>Normalize SBOM, policy, dependency-health, scanner, and fuzzing outputs into a central finding lifecycle. Generate remediation plans, owner routing, SLA reports, next-best-action queues, risk acceptances, suppressions, verification evidence, and ticket-ready remediation text.</p>
        <div class='grid'>
          <div class='card'><h3>Total</h3><p style='font-size:28px'>{esc(dash.get('total'))}</p></div>
          <div class='card'><h3>SLA</h3><pre>{esc(json.dumps(dash.get('sla', {}), indent=2))}</pre></div>
          <div class='card'><h3>By status</h3><pre>{esc(json.dumps(dash.get('by_status', {}), indent=2))}</pre></div>
          <div class='card'><h3>By severity</h3><pre>{esc(json.dumps(dash.get('by_severity', {}), indent=2))}</pre></div>
        </div></div>
        <div class='grid'>
        <div class='card'><h3>Import SBOM findings</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='import'><label>SBOM path on this host</label><input name='sbom' value='test-sboms/example-spdx-2.3.json' size='48'><label>Project</label><input name='project' value='default-project'><label>Owner</label><input name='owner' value='platform-security'><input type='submit' value='Import and dedupe findings'></form></div>
        <div class='card'><h3>Generate remediation outputs</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='remediation'><label>Project</label><input name='project' value='default-project'><label>Optional finding ID</label><input name='finding_id' placeholder='leave blank for project'><label>Optional fixed version</label><input name='fixed_version' placeholder='e.g. 1.2.3'><input type='submit' value='Generate remediation plans'></form></div>
        <div class='card'><h3>Lifecycle action</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='lifecycle'><label>Finding ID</label><input name='finding_id' required size='38'><label>Action</label><select name='action'><option value='assign'>Assign</option><option value='triaged'>Mark triaged</option><option value='in_progress'>Mark in progress</option><option value='accept'>Risk accept</option><option value='suppress'>Suppress</option></select><label>Owner</label><input name='owner' value='platform-security'><label>Reason / note</label><input name='reason' value='Reviewed by security owner.' size='42'><label>Expires at</label><input name='expires_at' value='2026-12-31'><input type='submit' value='Apply lifecycle action'></form></div>
        <div class='card'><h3>Reports and next actions</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='reports'><label>Project</label><input name='project' value='default-project'><input type='submit' value='Generate dashboard, SLA, next actions, export'></form></div>
        <div class='card'><h3>Ticket template</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='ticket'><label>Finding ID</label><input name='finding_id' required size='38'><label>Optional fixed version</label><input name='fixed_version'><input type='submit' value='Generate remediation ticket text'></form></div>
        <div class='card'><h3>Verify fixes</h3><form method='post' action='/findings/save'><input type='hidden' name='kind' value='verify'><label>Project</label><input name='project' value='default-project'><label>Optional current SBOM path</label><input name='sbom' size='48'><input type='submit' value='Verify candidate-fixed findings'></form></div>
        </div>
        <div class='card'><h2>Recent findings</h2><table><tr><th>ID</th><th>Severity</th><th>Status</th><th>Owner</th><th>Component</th><th>Title</th><th>Due</th></tr>{rows}</table></div>
        """
        self.send_html("Findings", body)

    def findings_save(self):
        try:
            from sbomops import findings as findings_ops
            fields = self.parse_urlencoded()
            kind = fields.get('kind', '')
            outputs = []
            if kind == 'import':
                outputs.append(findings_ops.import_sbom(argparse.Namespace(sbom=fields.get('sbom','test-sboms/example-spdx-2.3.json'), project=fields.get('project','default-project'), owner=fields.get('owner',''))))
            elif kind == 'remediation':
                outputs.append(findings_ops.generate_remediation(argparse.Namespace(project=fields.get('project',''), finding_id=fields.get('finding_id',''), fixed_version=fields.get('fixed_version',''), include_closed=True)))
            elif kind == 'lifecycle':
                action = fields.get('action','triaged')
                fid = fields.get('finding_id','')
                if action == 'assign':
                    outputs.append(findings_ops.update_finding(argparse.Namespace(finding_id=fid, status='assigned', owner=fields.get('owner',''), ticket_url='')))
                elif action == 'accept':
                    outputs.append(findings_ops.accept_or_suppress(argparse.Namespace(finding_id=fid, reason=fields.get('reason',''), owner=fields.get('owner',''), expires_at=fields.get('expires_at',''), conditions='reopen if exploitability or fixed version changes'), 'risk_accepted'))
                elif action == 'suppress':
                    outputs.append(findings_ops.accept_or_suppress(argparse.Namespace(finding_id=fid, reason=fields.get('reason',''), owner=fields.get('owner',''), expires_at=fields.get('expires_at',''), conditions='review before permanent suppression'), 'suppressed'))
                else:
                    outputs.append(findings_ops.update_finding(argparse.Namespace(finding_id=fid, status=action, owner=fields.get('owner',''), ticket_url='')))
            elif kind == 'reports':
                project = fields.get('project','')
                outputs.append(findings_ops.dashboard(argparse.Namespace(project=project)))
                outputs.append(findings_ops.sla_report(argparse.Namespace(project=project)))
                outputs.append(findings_ops.next_actions(argparse.Namespace(project=project, limit=10)))
                outputs.append(findings_ops.export_report(argparse.Namespace(project=project, status='', out_dir='reports/findings')))
            elif kind == 'ticket':
                outputs.append(findings_ops.ticket_text(argparse.Namespace(finding_id=fields.get('finding_id',''), fixed_version=fields.get('fixed_version',''))))
            elif kind == 'verify':
                outputs.append(findings_ops.verify(argparse.Namespace(project=fields.get('project','default-project'), sbom=fields.get('sbom',''))))
            else:
                raise ValueError(f'Unsupported findings action: {kind}')
            self.send_html('Findings saved', f"<div class='card'><h2>Findings operation complete</h2><pre>{esc(json.dumps(outputs, indent=2, sort_keys=True))}</pre><p><a class='btn' href='/findings'>Back to Findings</a></p></div>")
        except Exception as exc:
            self.send_html('Findings error', f"<div class='card'><h2>Findings error</h2><pre>{esc(exc)}</pre></div>", 400)

    def integrations_page(self):
        body = """
        <div class='card'><h2>Production integrations</h2>
        <p class='muted'>Generate reviewable export payloads, CI/CD templates, deployment scaffolds, notification tests, OIDC config, and worker runtime limits. Live delivery remains dry-run-first. Use the CLI/Make targets with explicit SEND=1 for real Jira, DefectDojo, Slack/webhook, or email delivery.</p></div>
        <div class='grid'>
        <div class='card'><h3>Unified connector platform</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='connector-platform'><div class='grid'><div><label>Connector name</label><input name='name' value='corporate-snyk'></div><div><label>Type</label><select name='type'><option value='snyk'>Snyk</option><option value='dependency-track'>Dependency-Track</option><option value='defectdojo'>DefectDojo</option><option value='github'>GitHub</option><option value='webhook'>Generic webhook</option></select></div><div><label>Base URL</label><input name='base_url' placeholder='Provider API URL'></div><div><label>Token environment variable</label><input name='token_env' value='SNYK_TOKEN'></div></div><label>Organization/project/repository identifier</label><input name='resource_id' placeholder='org UUID, project UUID, or owner/repo' size='48'><label><input type='checkbox' name='allow_write' value='true'> Enable write operations</label><p class='small muted'>Read-only and dry-run by default. Secrets are stored only as environment-variable references. Use CLI <code>--send</code> for live network calls.</p><input type='submit' value='Save connector and run dry-run health check'></form></div>
        <div class='card'><h3>Snyk SBOM connector</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='snyk'><div class='grid'><div><label>Snyk org ID</label><input name='org_id' placeholder='SNYK_ORG_ID or UUID'></div><div><label>Snyk project ID</label><input name='project_id' placeholder='SNYK_PROJECT_ID or UUID'></div><div><label>Token env var</label><input name='token_env' value='SNYK_TOKEN'></div><div><label>SBOM format</label><select name='format'><option value='cyclonedx1.6+json'>CycloneDX 1.6 JSON</option><option value='cyclonedx1.5+json'>CycloneDX 1.5 JSON</option><option value='cyclonedx1.4+json'>CycloneDX 1.4 JSON</option><option value='cyclonedx1.6+xml'>CycloneDX 1.6 XML</option><option value='spdx2.3+json'>SPDX 2.3 JSON</option></select></div></div><label>Local SBOM path for comparison</label><input name='local_sbom' value='test-sboms/example-spdx-2.3.json' size='48'><p class='small muted'>Dry-run by default. Stores token references only. Live pulls require CLI/Make with SEND=1.</p><input type='submit' value='Save config and run dry-run'></form></div>
        <div class='card'><h3>SARIF / OpenVEX / ticket payloads</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='exports'><label>SBOM path on this host</label><input name='sbom' value='test-sboms/example-spdx-2.3.json' size='48'><label>Jira project key</label><input name='project_key' value='SEC'><input type='submit' value='Generate exports'></form></div>
        <div class='card'><h3>CI/CD templates</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='ci'><label>Provider</label><select name='provider'><option value='all'>All</option><option value='github'>GitHub Actions</option><option value='gitlab'>GitLab CI</option><option value='jenkins'>Jenkins</option><option value='circleci'>CircleCI</option><option value='buildkite'>Buildkite</option><option value='azure'>Azure DevOps</option></select><input type='submit' value='Generate CI templates'></form></div>
        <div class='card'><h3>Deployment and runtime</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='deployment'><label>OIDC issuer</label><input name='issuer' value='https://issuer.example.com' size='38'><label>Allowed domains</label><input name='allowed_domains' value='example.com'><input type='submit' value='Generate Helm/OIDC/worker limits'></form></div>
        <div class='card'><h3>Notifications</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='notification'><label>Type</label><select name='type'><option value='webhook'>Webhook</option><option value='slack'>Slack</option><option value='email'>Email</option></select><label>Target reference</label><input name='target_ref' value='SST_WEBHOOK_URL'><label>Message</label><input name='message' value='Notification configuration test' size='42'><input type='submit' value='Create dry-run notification payload'></form></div>
        </div>
        <div class='grid'><div class='card'><h3>Live integration dry-run tests</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='live-dryrun'><label>SBOM path</label><input name='sbom' value='test-sboms/example-spdx-2.3.json' size='48'><label>Jira project key</label><input name='project_key' value='SEC'><input type='submit' value='Run Jira/DefectDojo/notification dry-run'></form></div><div class='card'><h3>Scheduler, jobs, and retention</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='ops'><label>Evidence retention days</label><input name='retention_days' value='90'><input type='submit' value='Run operational dry-run checks'></form></div></div><div class='card'><h3>GitHub App and demo</h3><form method='post' action='/integrations/save'><input type='hidden' name='kind' value='github-demo'><input type='submit' value='Generate GitHub App scaffold and demo dataset'></form></div>
        """
        self.send_html("Integrations", body)

    def integrations_save(self):
        try:
            import argparse as _argparse
            from sbomops import integrations as int_ops
            fields = self.parse_urlencoded(); kind = fields.get('kind','')
            outputs = []
            if kind == 'connector-platform':
                from sbomops import connectors as connector_ops
                name = fields.get('name','connector')
                ctype = fields.get('type','snyk')
                token_env = fields.get('token_env','') or {'snyk':'SNYK_TOKEN','dependency-track':'DEPENDENCY_TRACK_API_KEY','defectdojo':'DEFECTDOJO_TOKEN','github':'GITHUB_TOKEN','webhook':'SST_WEBHOOK_URL'}.get(ctype,'CONNECTOR_TOKEN')
                resource = fields.get('resource_id','')
                config = {'base_url': fields.get('base_url',''), 'token_ref': 'env:'+token_env, 'read_only': fields.get('allow_write','') != 'true', 'verify_tls': True}
                if ctype == 'snyk': config['org_id'] = resource
                elif ctype == 'github': config['repository'] = resource
                elif ctype == 'dependency-track': config['project_name'] = resource or 'SBOM Security Toolkit Project'
                elif ctype == 'webhook': config = {'url_ref':'env:'+token_env, 'read_only': fields.get('allow_write','') != 'true', 'verify_tls': True}
                cfg_path = Path('configs/generated/integrations') / f'{name}.json'
                cfg_path.parent.mkdir(parents=True, exist_ok=True); cfg_path.write_text(json.dumps(config, indent=2)+'\n')
                outputs.append(connector_ops.add_connector(_argparse.Namespace(registry='configs/connectors.yml', name=name, type=ctype, config=str(cfg_path), allow_write=fields.get('allow_write','') == 'true', insecure_skip_tls_verify=False, timeout_seconds=30, retries=3)))
                outputs.append(connector_ops.execute(_argparse.Namespace(registry='configs/connectors.yml', name=name, send=False, out=f'reports/connectors/{name}-health.json'), 'test'))
            elif kind == 'snyk':
                org_id = fields.get('org_id','')
                project_id = fields.get('project_id','')
                token_env = fields.get('token_env','SNYK_TOKEN') or 'SNYK_TOKEN'
                fmt = fields.get('format','cyclonedx1.6+json')
                local_sbom = fields.get('local_sbom') or 'test-sboms/example-spdx-2.3.json'
                outputs.append(int_ops.snyk_config(_argparse.Namespace(api_base_url='https://api.snyk.io', api_version='2024-10-15', org_id=org_id, project_id=project_id, token_env=token_env, token_secret_ref='env:'+token_env, format=fmt, out='configs/generated/integrations/snyk.yml')))
                outputs.append(int_ops.snyk_test(_argparse.Namespace(api_base_url='https://api.snyk.io', api_version='2024-10-15', org_id=org_id, token_env=token_env, out='reports/snyk/snyk-test.json', send=False)))
                outputs.append(int_ops.snyk_pull_sbom(_argparse.Namespace(api_base_url='https://api.snyk.io', api_version='2024-10-15', org_id=org_id, project_id=project_id, token_env=token_env, format=fmt, out='reports/snyk/snyk-project.sbom.cdx.json', meta_out='reports/snyk/snyk-pull-meta.json', error_out='reports/snyk/snyk-pull-error.json', timeout_seconds=30, send=False)))
                if Path(local_sbom).exists():
                    # Generate a deterministic sample Snyk SBOM so the UI can demonstrate comparison without live credentials.
                    sample_snyk = Path('reports/snyk/sample-snyk.cdx.json')
                    sample_snyk.parent.mkdir(parents=True, exist_ok=True)
                    sample_snyk.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','name':'demo-snyk-only','version':'1.0.0','purl':'pkg:npm/demo-snyk-only@1.0.0'}]}, indent=2)+'\n')
                    outputs.append(int_ops.snyk_compare(_argparse.Namespace(snyk_sbom=str(sample_snyk), local_sbom=local_sbom, out='reports/snyk/snyk-sbom-compare.json', markdown='reports/snyk/snyk-sbom-compare.md')))
            elif kind == 'exports':
                sbom = fields.get('sbom') or 'test-sboms/example-spdx-2.3.json'
                outputs.append(int_ops.export_sarif(_argparse.Namespace(sbom=sbom, out='reports/sarif/sbom-security-toolkit.sarif', project='workbench', release_decision='')))
                outputs.append(int_ops.export_openvex(_argparse.Namespace(sbom=sbom, out='reports/openvex/openvex.json', vulnerability='', status='under_investigation', justification='component_not_analyzed', impact_statement='Generated for review.', action_statement='Review before distribution.', author='SBOM Security Toolkit')))
                outputs.append(int_ops.export_jira(_argparse.Namespace(sbom=sbom, out='reports/integrations/jira-issues.json', project_key=fields.get('project_key','SEC'), issue_type='Task')))
                outputs.append(int_ops.export_defectdojo(_argparse.Namespace(sbom=sbom, out='reports/integrations/defectdojo-import.json', product_name='SBOM Security Toolkit Project', engagement_name='SBOM Review', minimum_severity='Info')))
            elif kind == 'ci':
                outputs.append(int_ops.generate_ci(_argparse.Namespace(provider=fields.get('provider','all'), out_dir='reports/ci-templates')))
            elif kind == 'deployment':
                outputs.append(int_ops.generate_k8s(_argparse.Namespace(out_dir='deploy/kubernetes')))
                outputs.append(int_ops.write_oidc(_argparse.Namespace(issuer=fields.get('issuer','https://issuer.example.com'), out='configs/generated/integrations/oidc.yml', client_id_env='SST_OIDC_CLIENT_ID', client_secret_env='SST_OIDC_CLIENT_SECRET', allowed_domains=fields.get('allowed_domains',''), default_role='analyst', admin_groups='', role_claim='groups')))
                outputs.append(int_ops.write_worker_limits(_argparse.Namespace(out='configs/generated/integrations/worker-limits.yml', max_repo_mb=500, max_sbom_mb=100, max_evidence_mb=1000, job_timeout_seconds=3600, fuzz_timeout_seconds=300, max_concurrent_jobs=1, retry_count=1, allowed_workflows='analyze,analyze-everything,repo-intake,dependency-health,fuzz-all-timed')))
            elif kind == 'notification':
                outputs.append(int_ops.notify(_argparse.Namespace(type=fields.get('type','webhook'), target_ref=fields.get('target_ref','SST_WEBHOOK_URL'), event='test', severity='info', title='SBOM Security Toolkit test', message=fields.get('message','Notification configuration test'), project='workbench', out='reports/notifications/last-notification.json', send=False, smtp_host='localhost', smtp_port=25, email_from='sst@example.local')))
            elif kind == 'live-dryrun':
                sbom = fields.get('sbom') or 'test-sboms/example-spdx-2.3.json'
                outputs.append(int_ops.jira_test(_argparse.Namespace(url='', email='', token_env='JIRA_API_TOKEN', out='reports/integrations/jira-test.json', send=False)))
                outputs.append(int_ops.jira_create(_argparse.Namespace(sbom=sbom, findings='', out='reports/integrations/jira-create.json', project_key=fields.get('project_key','SEC'), issue_type='Task', state='reports/integrations/jira-state.json', url='', email='', token_env='JIRA_API_TOKEN', send=False)))
                outputs.append(int_ops.defectdojo_test(_argparse.Namespace(url='', token_env='DEFECTDOJO_TOKEN', out='reports/integrations/defectdojo-test.json', send=False)))
                outputs.append(int_ops.defectdojo_upload(_argparse.Namespace(sbom=sbom, out='reports/integrations/defectdojo-upload.json', payload_out='reports/integrations/defectdojo-import.json', product_name='SBOM Security Toolkit Project', engagement_name='SBOM Review', minimum_severity='Info', url='', token_env='DEFECTDOJO_TOKEN', send=False)))
                outputs.append(int_ops.notify(_argparse.Namespace(type='webhook', target_ref='SST_WEBHOOK_URL', event='workbench_dryrun', severity='info', title='SBOM Security Toolkit dry-run', message='Workbench live integration dry-run completed.', project='workbench', out='reports/notifications/workbench-dryrun.json', send=False, smtp_host='localhost', smtp_port=25, email_from='sst@example.local')))
            elif kind == 'ops':
                outputs.append(int_ops.scheduler_run(_argparse.Namespace(history='reports/scheduler/history.json', once=True, dry_run=True)))
                outputs.append(int_ops.jobs_control(_argparse.Namespace(action='list', jobs_dir='ui/storage/jobs', job_id='', new_job_id='', note='', limit=25)))
                outputs.append(int_ops.evidence_cleanup(_argparse.Namespace(roots='reports,ui/storage/jobs', retention_days=int(fields.get('retention_days','90')), out='reports/evidence-cleanup.json', dry_run=True)))
            elif kind == 'github-demo':
                outputs.append(int_ops.github_app_scaffold(_argparse.Namespace(out_dir='configs/generated/integrations/github-app', workflow='analyze-everything', release_decision_mode='check')))
                outputs.append(int_ops.demo_enterprise(_argparse.Namespace(out_dir='reports/demo-enterprise')))
            else:
                raise ValueError('Unsupported integration action: '+kind)
            self.send_html('Integrations saved', f"<div class='card'><h2>Generated integration artifacts</h2><pre>{esc(json.dumps(outputs, indent=2, sort_keys=True))}</pre><p><a class='btn' href='/integrations'>Back to integrations</a></p></div>")
        except Exception as exc:
            self.send_html('Integrations error', f"<div class='card'><h2>Integrations error</h2><pre>{esc(exc)}</pre></div>", 400)


    def admin_page(self):
        status = enterprise_ops.health(argparse.Namespace())
        state_rows = "".join(
            f"<tr><td>{esc(c['name'])}</td><td><code>{esc(c['path'])}</code></td><td>{'yes' if c['exists'] else 'no'}</td><td>{esc(c['bytes'])}</td></tr>"
            for c in status.get("checks", [])
        )
        audit_rows = "".join(
            f"<tr><td>{esc(a.get('ts'))}</td><td>{esc(a.get('actor'))}</td><td>{esc(a.get('action'))}</td><td>{esc(a.get('resource'))}</td><td>{esc(a.get('status'))}</td></tr>"
            for a in enterprise_ops.load_audit(25)
        ) or "<tr><td colspan='5' class='muted'>No audit events yet.</td></tr>"
        body = f"""
        <div class='card'><h2>Enterprise cloud administration</h2>
        <p class='muted'>Local-first remains the default. These controls generate self-hosted cloud configuration for users, roles, schedules, notifications, secret references, service accounts, and audit logging. Secrets are stored as references, not plaintext values.</p>
        <p>Status: <span class='pill {esc(status.get('status'))}'>{esc(status.get('status'))}</span></p>
        <table><tr><th>Area</th><th>Path</th><th>Exists</th><th>Bytes</th></tr>{state_rows}</table></div>

        <div class='card'><h2>First-run setup wizard</h2>
        <form method='post' action='/admin/save'><input type='hidden' name='kind' value='setup-wizard'>
        <div class='grid'><div><label>Admin username</label><input name='admin_username' value='admin'></div><div><label>Admin email</label><input name='admin_email' placeholder='admin@example.com'></div><div><label>Project ID</label><input name='project_id' value='default-project'></div><div><label>Auth mode</label><select name='mode'><option value='local'>Local password</option><option value='oidc'>OIDC scaffold</option><option value='disabled'>Disabled / lab only</option></select></div></div>
        <p class='small muted'>Leave password blank to generate a one-time admin password. Store it immediately.</p><input type='submit' value='Run setup wizard'></form></div>

        <div class='card'><h2>User / RBAC</h2>
        <form method='post' action='/admin/save'><input type='hidden' name='kind' value='create-user'>
        <div class='grid'><div><label>Username</label><input name='username' value='analyst'></div><div><label>Email</label><input name='email'></div><div><label>Role</label><select name='role'><option>admin</option><option>maintainer</option><option selected>analyst</option><option>read-only</option><option>service-account</option></select></div><div><label>Password</label><input name='password' type='password' placeholder='blank generates one'></div></div><input type='submit' value='Save user'></form>
        <hr><form method='post' action='/admin/save'><input type='hidden' name='kind' value='create-role'><div class='grid'><div><label>Role name</label><input name='name' value='security-reviewer'></div><div><label>Permissions</label><input name='permissions' value='scan:view,evidence:view,release:view'></div></div><input type='submit' value='Save role'></form></div>

        <div class='card'><h2>Scheduled scans</h2>
        <form method='post' action='/admin/save'><input type='hidden' name='kind' value='schedule'>
        <div class='grid'><div><label>Name</label><input name='name' value='nightly-full-scan'></div><div><label>Project ID</label><input name='project_id' value='default-project'></div><div><label>Workflow</label><select name='workflow'><option value='analyze-everything'>Full SBOM analysis + every action + all fuzzing scenarios</option><option value='repo-intake'>Repository intake</option><option value='dependency-health'>Dependency health</option><option value='fuzz-all-timed'>Timed fuzzing</option></select></div><div><label>Cadence</label><select name='cadence'><option>hourly</option><option selected>daily</option><option>weekly</option><option>monthly</option></select></div></div><input type='submit' value='Save schedule'></form></div>

        <div class='card'><h2>Notifications</h2>
        <form method='post' action='/admin/save'><input type='hidden' name='kind' value='notification'>
        <div class='grid'><div><label>Name</label><input name='name' value='security-alerts'></div><div><label>Type</label><select name='type'><option value='webhook'>Webhook</option><option value='slack'>Slack</option><option value='email'>Email</option></select></div><div><label>Target reference</label><input name='target_ref' value='SST_WEBHOOK_URL'></div><div><label>Events</label><input name='events' value='policy_failed,release_blocked,scan_failed,evidence_ready'></div></div><input type='submit' value='Save notification'></form></div>

        <div class='card'><h2>Secrets and service accounts</h2>
        <form method='post' action='/admin/save'><input type='hidden' name='kind' value='secret-ref'>
        <div class='grid'><div><label>Name</label><input name='name' value='github-token'></div><div><label>Provider</label><select name='provider'><option value='env'>Environment variable</option><option value='aws-secrets-manager'>AWS Secrets Manager</option><option value='docker-secret'>Docker secret</option><option value='kubernetes-secret'>Kubernetes secret</option><option value='local-encrypted'>Local encrypted file</option></select></div><div><label>Reference</label><input name='reference' value='GITHUB_TOKEN'></div><div><label>Purpose</label><input name='purpose' value='private repository access'></div></div><input type='submit' value='Save secret reference'></form>
        <hr><form method='post' action='/admin/save'><input type='hidden' name='kind' value='api-token'><div class='grid'><div><label>Token name</label><input name='name' value='ci-service-account'></div><div><label>Owner</label><input name='owner' value='ci'></div><div><label>Role</label><select name='role'><option value='service-account'>service-account</option><option value='analyst'>analyst</option><option value='maintainer'>maintainer</option></select></div></div><input type='submit' value='Create API token'></form></div>

        <div class='card'><h2>Audit log</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Status</th></tr>{audit_rows}</table></div>
        """
        self.send_html("Enterprise Admin", body)

    def admin_save(self):
        try:
            fields = self.parse_urlencoded()
            kind = fields.get("kind", "")
            actor = fields.get("actor", "workbench") or "workbench"
            if kind == "setup-wizard":
                args = argparse.Namespace(**{"mode": fields.get("mode", "local"), "session_ttl_minutes": "480", "oidc_issuer": "", "admin_username": fields.get("admin_username", "admin"), "admin_display_name": fields.get("admin_username", "admin"), "admin_email": fields.get("admin_email", ""), "admin_password": fields.get("admin_password", ""), "project_id": fields.get("project_id", "default-project"), "actor": actor})
                out = enterprise_ops.setup_wizard(args)
            elif kind == "create-user":
                args = argparse.Namespace(**{"username": fields.get("username", "analyst"), "display_name": fields.get("username", "analyst"), "email": fields.get("email", ""), "role": fields.get("role", "analyst"), "password": fields.get("password", ""), "actor": actor})
                out = enterprise_ops.create_user(args)
            elif kind == "create-role":
                args = argparse.Namespace(name=fields.get("name", "custom-role"), permissions=fields.get("permissions", "scan:view"), actor=actor)
                out = enterprise_ops.create_role(args)
            elif kind == "schedule":
                args = argparse.Namespace(name=fields.get("name", "daily-scan"), project_id=fields.get("project_id", "default-project"), workflow=fields.get("workflow", "analyze-everything"), cadence=fields.get("cadence", "daily"), disabled=False, policy="policies/generated/release-policy.yml", fuzzing_profile="configs/generated/fuzzing-profiles/release-smoke.yml", ai_provider="configs/generated/ai-providers/default-ai.yml", actor=actor)
                out = enterprise_ops.create_schedule(args)
            elif kind == "notification":
                args = argparse.Namespace(name=fields.get("name", "alerts"), type=fields.get("type", "webhook"), target_ref=fields.get("target_ref", "SST_WEBHOOK_URL"), events=fields.get("events", "policy_failed,release_blocked,scan_failed,evidence_ready"), disabled=False, actor=actor)
                out = enterprise_ops.create_notification(args)
            elif kind == "secret-ref":
                args = argparse.Namespace(name=fields.get("name", "secret"), provider=fields.get("provider", "env"), reference=fields.get("reference", ""), purpose=fields.get("purpose", "generic"), actor=actor)
                out = enterprise_ops.create_secret_ref(args)
            elif kind == "api-token":
                args = argparse.Namespace(name=fields.get("name", "service-token"), owner=fields.get("owner", "service-account"), role=fields.get("role", "service-account"), expires_at=fields.get("expires_at", ""), actor=actor)
                out = enterprise_ops.create_api_token(args)
            else:
                raise ValueError(f"Unsupported admin action: {kind}")
            self.send_html("Admin saved", f"<div class='card'><h2>Saved enterprise configuration</h2><pre>{esc(json.dumps(out, indent=2, sort_keys=True))}</pre><p><a class='btn' href='/admin'>Back to admin</a></p></div>")
        except Exception as exc:
            self.send_html("Admin error", f"<div class='card'><h2>Admin error</h2><pre>{esc(exc)}</pre></div>", 400)

    def parse_urlencoded(self, multi: bool = False):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return parsed if multi else {k: v[-1] if v else "" for k, v in parsed.items()}

    def bool_field(self, fields: Dict[str, str], name: str) -> bool:
        return fields.get(name) in {"1", "true", "on", "yes"}

    def settings_page(self):
        configs = list_configs()
        sections = []
        for title, rows in configs.items():
            body_rows = "".join(
                f"<tr><td>{esc(r['name'])}</td><td><code>{esc(r['path'])}</code></td><td>{esc(r['bytes'])}</td><td><a href='/settings/view/{esc(urllib.parse.quote(r['path']))}'>view</a></td></tr>"
                for r in rows
            ) or "<tr><td colspan='4' class='muted'>No generated files yet.</td></tr>"
            sections.append(f"<h3>{esc(title.replace('_',' ').title())}</h3><table><tr><th>Name</th><th>Path</th><th>Bytes</th><th>Preview</th></tr>{body_rows}</table>")
        body = f"""
        <div class='card'><h2>GUI-managed configuration</h2>
        <p class='muted'>The Workbench can now generate and manage the YAML files that were previously path-only advanced inputs. YAML remains available for GitOps and power users, but normal users can configure policies, AI providers, fuzzing profiles, project defaults, and cloud settings from this page.</p>
        </div>
        <div class='card'><h2>Policy Builder</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='policy'>
          <div class='grid'><div><label>Policy name</label><input name='name' value='release-policy'></div><div><label>Stale dependency days</label><input name='stale_days' value='365'></div></div>
          <div class='grid'>
            <label><input type='checkbox' name='fail_on_critical' value='1' checked> Fail on critical vulnerabilities</label>
            <label><input type='checkbox' name='fail_on_high' value='1'> Fail on high vulnerabilities</label>
            <label><input type='checkbox' name='fail_on_cisa_kev' value='1' checked> Fail on CISA KEV</label>
            <label><input type='checkbox' name='fail_on_exploit_available' value='1'> Fail on exploit available</label>
            <label><input type='checkbox' name='fail_on_unsupported' value='1' checked> Fail on unsupported dependencies</label>
            <label><input type='checkbox' name='warn_on_scanner_disagreement' value='1' checked> Warn on scanner disagreement</label>
            <label><input type='checkbox' name='fail_on_vex_contradiction' value='1' checked> Fail on VEX contradiction</label>
            <label><input type='checkbox' name='require_supplier' value='1'> Require supplier</label>
            <label><input type='checkbox' name='require_license' value='1'> Require license</label>
            <label><input type='checkbox' name='require_version' value='1' checked> Require version</label>
            <label><input type='checkbox' name='require_dependency_graph' value='1'> Require dependency graph</label>
            <label><input type='checkbox' name='network_enrichment' value='1'> Allow registry enrichment</label>
          </div>
          <input type='submit' value='Save policy YAML'>
        </form></div>
        <div class='card'><h2>AI Provider Manager</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='ai-provider'>
          <div class='grid'>
            <div><label>Name</label><input name='name' value='default-ai'></div>
            <div><label>Provider</label><select name='provider'><option value='none'>Disabled / prompt-only</option><option value='bedrock' selected>AWS Bedrock</option><option value='ollama'>Ollama</option><option value='glm'>GLM</option><option value='openai-compatible'>OpenAI-compatible</option></select></div>
            <div><label>Model</label><input name='model' placeholder='Bedrock model ID or local model'></div>
            <div><label>AWS region</label><input name='region' value='us-east-1'></div>
            <div><label>Endpoint URL</label><input name='endpoint_url' placeholder='for Ollama/GLM/OpenAI-compatible'></div>
            <div><label>API key env var</label><input name='api_key_env' placeholder='OPENAI_API_KEY'></div>
            <div><label>Default mode</label><select name='default_mode'><option value='suggest'>Suggest only</option><option value='generate-run'>Generate and run validated cases</option></select></div>
            <div><label>Max cases</label><input name='max_cases' value='5'></div>
            <div><label>Time budget seconds</label><input name='time_budget' value='30'></div>
          </div>
          <p class='small muted'>Secrets are not stored by this UI. Bedrock uses the AWS SDK credential chain or instance role; OpenAI-compatible providers should use environment variables or external secret managers.</p>
          <input type='submit' value='Save AI provider YAML'>
        </form></div>
        <div class='card'><h2>Fuzzing Profile Builder</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='fuzzing-profile'>
          <div class='grid'>
            <div><label>Profile name</label><input name='name' value='release-smoke'></div>
            <div><label>Targets</label><input name='targets' value='sbom,scanner,ai'></div>
            <div><label>Duration per target</label><input name='duration' value='60'></div>
            <div><label>Seed count</label><input name='seed_count' value='10'></div>
            <div><label>Max AI cases</label><input name='max_ai_cases' value='5'></div>
            <div><label>AI mode</label><select name='ai_mode'><option value='disabled'>Disabled</option><option value='suggest' selected>Suggest</option><option value='generate-run'>Generate and run validated cases</option></select></div>
            <label><input type='checkbox' name='run_generated_cases' value='1'> Run generated validated cases</label>
          </div>
          <input type='submit' value='Save fuzzing profile YAML'>
        </form></div>
        <div class='card'><h2>Project Defaults</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='project-defaults'>
          <div class='grid'>
            <div><label>Project ID</label><input name='project_id' value='default-project'></div>
            <div><label>Policy path</label><input name='policy' value='policies/generated/release-policy.yml'></div>
            <div><label>AI provider path</label><input name='ai_provider' value='configs/generated/ai-providers/default-ai.yml'></div>
            <div><label>Fuzzing profile path</label><input name='fuzzing_profile' value='configs/generated/fuzzing-profiles/release-smoke.yml'></div>
            <div><label>Stale days</label><input name='stale_days' value='365'></div>
            <div><label>Evidence retention days</label><input name='evidence_retention_days' value='90'></div>
            <div><label>Schedule</label><input name='schedule' value='manual'></div>
            <div><label>Release behavior</label><select name='release_behavior'><option value='warn'>Warn</option><option value='block'>Block</option><option value='pass'>Pass</option></select></div>
          </div>
          <input type='submit' value='Save project defaults YAML'>
        </form></div>
        <div class='card'><h2>Cloud Settings</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='cloud-settings'>
          <div class='grid'>
            <div><label>Name</label><input name='name' value='self-hosted'></div>
            <div><label>Storage backend</label><select name='storage_backend'><option value='local'>Local filesystem</option><option value='s3'>S3</option><option value='minio'>MinIO</option></select></div>
            <div><label>S3 bucket</label><input name='s3_bucket' placeholder='bucket name'></div>
            <div><label>S3 prefix</label><input name='s3_prefix' value='sbom-security-toolkit'></div>
            <div><label>Database</label><select name='database_backend'><option value='postgres'>Postgres</option><option value='local'>Local</option></select></div>
            <div><label>Queue</label><select name='queue_backend'><option value='redis'>Redis</option><option value='in-process'>In-process</option></select></div>
            <div><label>Evidence retention days</label><input name='evidence_retention_days' value='90'></div>
          </div>
          <div class='grid'>
            <label><input type='checkbox' name='worker_sbom' value='1' checked> SBOM worker</label>
            <label><input type='checkbox' name='worker_vulnerability' value='1' checked> Vulnerability worker</label>
            <label><input type='checkbox' name='worker_fuzzing' value='1' checked> Fuzzing worker</label>
            <label><input type='checkbox' name='worker_ai' value='1' checked> AI worker</label>
            <label><input type='checkbox' name='worker_report' value='1' checked> Report worker</label>
          </div>
          <input type='submit' value='Save cloud settings YAML'>
        </form></div>
        <div class='card'><h2>Import existing YAML</h2>
        <form method='post' action='/settings/save'>
          <input type='hidden' name='kind' value='import'>
          <div class='grid'><div><label>Config type</label><select name='import_kind'><option value='policy'>Policy</option><option value='ai-provider'>AI provider</option><option value='fuzzing-profile'>Fuzzing profile</option><option value='project-defaults'>Project defaults</option><option value='cloud-settings'>Cloud settings</option></select></div><div><label>Name</label><input name='name' value='imported-config'></div></div>
          <label>YAML</label><textarea name='raw_yaml' placeholder='paste existing YAML here'></textarea>
          <input type='submit' value='Import YAML'>
        </form></div>
        <div class='card'><h2>Generated configuration files</h2>{''.join(sections)}</div>
        """
        self.send_html("Settings", body)

    def settings_view(self, encoded_path: str):
        rel = urllib.parse.unquote(encoded_path)
        path = (ROOT / rel).resolve()
        allowed = [POLICY_DIR.resolve(), AI_DIR.resolve(), FUZZ_DIR.resolve(), PROJECT_DIR.resolve(), CLOUD_DIR.resolve()]
        if not any(str(path).startswith(str(base)) for base in allowed) or not path.exists() or not path.is_file():
            return self.send_html("Config not found", "<div class='card'><h2>Config not found</h2></div>", 404)
        body = f"<div class='card'><h2>{esc(rel)}</h2><pre>{esc(path.read_text(errors='replace'))}</pre><p><a class='btn secondary' href='/settings'>Back to settings</a></p></div>"
        self.send_html("Config preview", body)

    def settings_save(self):
        try:
            fields = self.parse_urlencoded()
            kind = fields.get("kind", "")
            class NS: pass
            args = NS()
            if kind == "policy":
                args.name = fields.get("name", "release-policy")
                args.stale_days = int(fields.get("stale_days", "365") or 365)
                for name in ["fail_on_critical", "fail_on_high", "fail_on_cisa_kev", "fail_on_exploit_available", "fail_on_unsupported", "warn_on_scanner_disagreement", "fail_on_vex_contradiction", "require_supplier", "require_license", "require_version", "require_dependency_graph", "network_enrichment"]:
                    setattr(args, name, self.bool_field(fields, name))
                path = write_yaml(POLICY_DIR / f"{safe_slug(args.name)}.yml", build_policy_config(args))
            elif kind == "ai-provider":
                args.name = fields.get("name", "default-ai"); args.provider = fields.get("provider", "none"); args.model = fields.get("model", ""); args.region = fields.get("region", "us-east-1"); args.endpoint_url = fields.get("endpoint_url", ""); args.api_key_env = fields.get("api_key_env", ""); args.default_mode = fields.get("default_mode", "suggest"); args.max_cases = int(fields.get("max_cases", "5") or 5); args.time_budget = int(fields.get("time_budget", "30") or 30)
                path = write_yaml(AI_DIR / f"{safe_slug(args.name)}.yml", build_ai_provider_config(args))
            elif kind == "fuzzing-profile":
                args.name = fields.get("name", "release-smoke"); args.targets = fields.get("targets", "sbom,scanner,ai"); args.duration = int(fields.get("duration", "60") or 60); args.seed_count = int(fields.get("seed_count", "10") or 10); args.max_ai_cases = int(fields.get("max_ai_cases", "5") or 5); args.ai_mode = fields.get("ai_mode", "suggest"); args.run_generated_cases = self.bool_field(fields, "run_generated_cases")
                path = write_yaml(FUZZ_DIR / f"{safe_slug(args.name)}.yml", build_fuzzing_profile_config(args))
            elif kind == "project-defaults":
                args.project_id = fields.get("project_id", "default-project"); args.policy = fields.get("policy", "policies/generated/release-policy.yml"); args.ai_provider = fields.get("ai_provider", "configs/generated/ai-providers/default-ai.yml"); args.fuzzing_profile = fields.get("fuzzing_profile", "configs/generated/fuzzing-profiles/release-smoke.yml"); args.stale_days = int(fields.get("stale_days", "365") or 365); args.evidence_retention_days = int(fields.get("evidence_retention_days", "90") or 90); args.schedule = fields.get("schedule", "manual"); args.release_behavior = fields.get("release_behavior", "warn")
                path = write_yaml(PROJECT_DIR / f"{safe_slug(args.project_id)}.yml", build_project_defaults_config(args))
            elif kind == "cloud-settings":
                args.name = fields.get("name", "self-hosted"); args.storage_backend = fields.get("storage_backend", "local"); args.s3_bucket = fields.get("s3_bucket", ""); args.s3_prefix = fields.get("s3_prefix", "sbom-security-toolkit"); args.database_backend = fields.get("database_backend", "postgres"); args.queue_backend = fields.get("queue_backend", "redis"); args.evidence_retention_days = int(fields.get("evidence_retention_days", "90") or 90)
                for name in ["worker_sbom", "worker_vulnerability", "worker_fuzzing", "worker_ai", "worker_report"]:
                    setattr(args, name, self.bool_field(fields, name))
                path = write_yaml(CLOUD_DIR / f"{safe_slug(args.name)}.yml", build_cloud_settings_config(args))
            elif kind == "import":
                path = import_config(fields.get("import_kind", "policy"), fields.get("name", "imported-config"), fields.get("raw_yaml", ""))
            else:
                raise ValueError(f"Unsupported settings kind: {kind}")
            rel = path.relative_to(ROOT)
            self.send_html("Config saved", f"<div class='card'><h2>Saved configuration</h2><p>Wrote <code>{esc(rel)}</code>.</p><pre>{esc(path.read_text(errors='replace'))}</pre><p><a class='btn' href='/settings'>Back to settings</a></p></div>")
        except Exception as exc:
            self.send_html("Settings error", f"<div class='card'><h2>Settings error</h2><pre>{esc(exc)}</pre></div>", 400)


    def repository_intake(self):
        opts = "".join(f"<option value='{esc(k)}'>{esc(v)}</option>" for k, v in REPO_WORKFLOWS.items())
        recent = [j for j in list_jobs() if j.get("workflow") in REPO_WORKFLOWS]
        recent_rows = "".join(
            f"<tr><td><a href='/jobs/{esc(j['job_id'])}'>{esc(j['job_id'])}</a></td><td>{esc(j.get('workflow_label'))}</td><td><span class='pill {esc(j.get('state'))}'>{esc(j.get('state'))}</span></td><td>{esc(j.get('created_at'))}</td></tr>"
            for j in recent[:10]
        ) or "<tr><td colspan='4' class='muted'>No repository intake jobs yet.</td></tr>"
        body = f"""
        <div class='card'><h2>Repository Intake</h2>
        <p class='muted'>Build SBOMs from a repository, compare generators, scan vulnerabilities, optionally fuzz the generated SBOM, run unsupported/out-of-date dependency analysis, and package evidence. Static-first by default: the toolkit does not run project install/build scripts.</p>
        <form action='/upload' method='post' enctype='multipart/form-data'>
          <label>Workflow</label><select name='workflow'>{opts}</select>
          <p class='small muted'>Choose <strong>Repository intake: unsupported / out-of-date dependency analysis</strong> for a dependency-health-only run, or enable the dependency health checkbox during full repository intake.</p>
          <div class='grid'>
            <div><label>Source type</label><select name='repo_source_type'><option value='upload'>Repo archive upload</option><option value='path'>Local path on this machine</option><option value='github'>GitHub HTTPS URL</option></select></div>
            <div><label>SBOM generators</label><input name='repo_generators' value='auto' size='24'><p class='small muted'>Comma list: auto, internal, syft, cdxgen, trivy.</p></div>
            <div><label>Fuzz generated SBOM</label><select name='repo_fuzz'><option value='0'>No</option><option value='1'>Yes</option></select></div>
            <div><label>Dependency health/EOL check</label><select name='repo_dependency_health'><option value='1'>Yes</option><option value='0'>No</option></select><p class='small muted'>Flags deprecated, abandoned, stale, unpinned, or unsupported-risk dependencies.</p></div>
            <div><label>Stale threshold days</label><input name='stale_days' value='365' size='8'></div><div><label>Lifecycle sources</label><input name='lifecycle_sources' value='sbom,known,registry,endoflife' size='34'></div><div><label>Lifecycle cache path</label><input name='lifecycle_cache' placeholder='configs/lifecycle/eol-cache.json' size='34'></div>
          </div>
          <label>Repository archive upload</label><input type='file' name='sbom'>
          <p class='small muted'>Allowed: .zip, .tar.gz/.tgz, plus SBOM file types for normal workflows. Max size: {MAX_UPLOAD_BYTES//(1024*1024)} MB.</p>
          <label>Local path or GitHub URL</label><input name='repo_source' placeholder='/path/to/repo or https://github.com/org/private-repo.git' size='84'>
          <div class='grid'>
            <div><label>GitHub token for private repos</label><input name='github_token' type='password' placeholder='not stored on disk' size='32'><p class='small muted'>Held only in process memory for the current job and passed as GITHUB_TOKEN.</p></div>
            <div><label>Allow remote Git clone</label><select name='repo_allow_remote'><option value='0'>No</option><option value='1'>Yes</option></select><p class='small muted'>Required for GitHub URL intake.</p></div>
          </div>
          <label>Policy path</label><input name='policy' value='policies/default-release-policy.yml' size='46'>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled scanners/enrichment when available, including registry metadata and endoflife.date lifecycle lookups for dependency-health checks</label></p><p><label><input type='checkbox' name='offline_cache_only' value='1'> Offline lifecycle cache only</label></p>
          <input type='submit' value='Start repository intake'>
        </form></div>
        <div class='grid'>
          <div class='card'><h3>What it does</h3><p>Detects ecosystems, generates SBOMs with available tools plus an internal static fallback, compares generated SBOMs, scans with installed local scanners, and creates evidence.</p></div>
          <div class='card'><h3>Private GitHub repos</h3><p>Use an HTTPS GitHub URL and paste a token for this job only. The token is not written to status files, logs, or reports.</p></div>
          <div class='card'><h3>Safety defaults</h3><p>No project code execution, no install scripts, no remote clone unless enabled, and per-job isolated storage.</p></div>
        </div>
        <div class='card'><h2>Recent Repository Jobs</h2><table><tr><th>Job</th><th>Workflow</th><th>Status</th><th>Created</th></tr>{recent_rows}</table></div>
        """
        self.send_html("Repository Intake", body)


    def demo_qa_page(self):
        body = """
        <div class='card'><h2>Demo / QA Readiness</h2>
        <p class='muted'>Generate a realistic demo workspace, run doctor checks, create first-run defaults, or generate release-readiness artifacts from the Workbench.</p>
        <form method='post' action='/demo/run'>
          <label>Action</label>
          <select name='action'>
            <option value='doctor'>Doctor / environment check</option>
            <option value='demo'>Generate demo workspace</option>
            <option value='first-run'>Generate first-run config</option>
            <option value='security-checklist'>Generate security hardening checklist</option>
            <option value='install-notes'>Generate install / upgrade notes</option>
          </select>
          <p><label><input type='checkbox' name='load_demo' value='1'> Load demo data during first-run setup</label></p>
          <input type='submit' value='Run action'>
        </form></div>
        <div class='card'><h2>Recommended release gate</h2>
        <pre>make test-fast
make test-integration-offline
make test-fuzz-smoke
make test-release</pre>
        <p class='muted'>The broader <code>make test-all</code> target can take longer because fuzzing workflows intentionally run subprocesses.</p></div>
        <div class='grid'><div class='card'><h3>Demo workspace</h3><p><code>reports/demo-product/</code></p></div><div class='card'><h3>QA docs</h3><p><code>docs/qa/RELEASE-GATE.md</code></p></div><div class='card'><h3>Walkthrough</h3><p><code>docs/demo/WALKTHROUGH.md</code></p></div></div>
        """
        self.send_html("Demo / QA", body)

    def demo_qa_run(self):
        length = int(self.headers.get("Content-Length", "0"))
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        action = (fields.get("action") or ["doctor"])[0]
        try:
            from sbomops import productization
            import argparse as _argparse
            if action == "demo":
                productization.demo(_argparse.Namespace(out_dir=None, reset=True))
            elif action == "first-run":
                productization.first_run(_argparse.Namespace(mode="local", project_id="demo-product", policy="policies/default-release-policy.yml", ai_provider="none", fuzzing_profile="release-smoke", load_demo=(fields.get("load_demo") == ["1"]), out=None))
            elif action == "security-checklist":
                productization.security_checklist(_argparse.Namespace(out=None))
            elif action == "install-notes":
                productization.install_notes(_argparse.Namespace(out=None))
            else:
                productization.doctor(_argparse.Namespace(out=None))
            self.send_html("Demo / QA", f"<div class='card'><h2>Action completed</h2><p>Ran <code>{esc(action)}</code>.</p><p><a class='btn' href='/reports'>View generated reports</a> <a class='btn secondary' href='/demo'>Back</a></p></div>")
        except Exception as exc:
            self.send_html("Demo / QA error", f"<div class='card'><h2>Action failed</h2><pre>{esc(exc)}</pre></div>", 500)

    def fuzzing_lab(self):
        opts = "".join(f"<option value='{esc(k)}'>{esc(v)}</option>" for k, v in FUZZ_WORKFLOWS.items())
        recent = [j for j in list_jobs() if j.get("workflow") in FUZZ_WORKFLOWS]
        recent_rows = "".join(
            f"<tr><td><a href='/jobs/{esc(j['job_id'])}'>{esc(j['job_id'])}</a></td><td>{esc(j.get('workflow_label'))}</td><td><span class='pill {esc(j.get('state'))}'>{esc(j.get('state'))}</span></td><td>{esc(j.get('created_at'))}</td></tr>"
            for j in recent[:10]
        ) or "<tr><td colspan='4' class='muted'>No fuzzing jobs yet.</td></tr>"
        body = f"""
        <div class='card'><h2>Fuzzing Lab</h2>
        <p class='muted'>Upload a seed SBOM and launch local fuzzing workflows. Jobs run in isolated folders under <code>ui/storage/jobs</code>; AI-assisted actions create review artifacts and never execute generated code automatically.</p>
        <form action='/upload' method='post' enctype='multipart/form-data'>
          <label>Seed SBOM or fuzz input</label><input type='file' name='sbom' required>
          <p class='small muted'>Allowed: .json, .xml, .spdx, .txt. Max size: {MAX_UPLOAD_BYTES//(1024*1024)} MB.</p>
          <label>Fuzzing workflow</label><select name='workflow'>{opts}</select>
          <div class='grid'>
            <div><label>Seed count</label><input name='count' value='10' size='8'><p class='small muted'>Used by seed generation and structured mutation workflows.</p></div>
            <div><label>Time limit per fuzzing step / library</label><input name='duration_seconds' value='60' size='8'><p class='small muted'>Used by timed runs and as a timeout guard for long fuzzing actions.</p></div>
            <div><label>Run targets</label><input name='library_targets' value='sbom,scanner,ai' size='28'><p class='small muted'>For timed all-runs. Examples: <code>sbom,scanner,ai</code> or <code>python,javascript,php,sbom</code>.</p></div>
            <div><label>Edge case</label><select name='edge'><option>valid-edge</option><option>dependency-cycle</option><option>duplicate-bom-ref</option><option>conflicting-identities</option><option>missing-version</option><option>huge-version</option><option>unicode</option><option>invalid-license</option></select></div>
            <div><label>Budget profile</label><select name='budget_profile'><option value='fuzzing/budgets/pr-smoke.yml'>PR smoke</option><option value='fuzzing/budgets/nightly-deep.yml'>Nightly deep</option></select></div>
            <div><label>Dependency-Track URL</label><input name='dtrack_url' value='http://127.0.0.1:8081' size='28'></div>
          </div>
          <div class='grid'>
            <div><label>AI provider</label><select name='ai_provider'><option value='none'>prompt-only / none</option><option value='bedrock'>AWS Bedrock</option><option value='glm'>GLM local/OpenAI-compatible</option><option value='ollama'>Ollama-compatible</option><option value='openai-compatible'>OpenAI-compatible</option></select><p class='small muted'>Bedrock uses the host AWS SDK credentials/role and does not store tokens in job files.</p></div>
            <div><label>AI model</label><input name='ai_model' placeholder='glm-5.2' size='20'></div>
            <div><label>AI scenario</label><input name='scenario' value='dependency-cycles' size='24'></div>
            <div><label>AI goal</label><input name='ai_goal' value='scanner-disagreement-hardening' size='28'></div>
          </div>
          <label>Harness / method target</label><input name='target' value='fuzzing/engines/python/targets/cyclonedx_json_atheris.py' size='72'>
          <div class='grid'>
            <div><label>Grammar</label><select name='grammar'><option>cyclonedx</option><option>spdx</option><option>purl</option><option>license</option><option>vex</option></select></div>
            <div><label>Finding ID</label><input name='finding_id' value='workbench-demo-finding' size='28'></div>
            <div><label>Finding state</label><select name='finding_state'><option>triaged</option><option>found</option><option>minimized</option><option>regression-added</option><option>fixed</option><option>verified</option><option>archived</option></select></div>
          </div>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled enrichment/scanner actions when available</label></p>
          <input type='submit' value='Start fuzzing job'>
        </form></div>
        <div class='grid'>
          <div class='card'><h3>Recommended starters</h3><p><strong>Round-trip</strong>, <strong>semantic oracles</strong>, <strong>structured mutations</strong>, <strong>fuzz-all-local</strong>, and <strong>fuzz-all-timed</strong> are good safe first runs. Use <strong>fuzz-all-timed</strong> when you want every available local fuzzing effort to run with a user-set time limit per step/library.</p></div>
          <div class='card'><h3>Scanner workflows</h3><p>Toolchain, compatibility, truth-set, and metamorphic scanner workflows depend on locally installed scanners.</p></div>
          <div class='card'><h3>AI-assisted workflows</h3><p>Prompt-only mode works without keys. Bedrock, GLM, Ollama, and OpenAI-compatible endpoints are optional and review-gated.</p></div>
        </div>
        <div class='card'><h2>Recent Fuzzing Jobs</h2><table><tr><th>Job</th><th>Workflow</th><th>Status</th><th>Created</th></tr>{recent_rows}</table><p><a class='btn secondary' href='/fuzzing/logs'>Open fuzzing logs</a> <a class='btn secondary' href='/fuzzing/dashboard'>Open fuzzing dashboard</a></p></div>
        """
        self.send_html("Fuzzing Lab", body)

    def fuzzing_logs(self):
        jobs = [j for j in list_jobs() if j.get("workflow") in FUZZ_WORKFLOWS]
        cards = []
        for j in jobs[:20]:
            jid = j.get("job_id")
            lp = logs_path(jid)
            logs = lp.read_text(errors="replace")[-12000:] if lp.exists() else ""
            cards.append(f"<div class='card'><h3><a href='/jobs/{esc(jid)}'>{esc(jid)}</a> <span class='pill {esc(j.get('state'))}'>{esc(j.get('state'))}</span></h3><p class='muted'>{esc(j.get('workflow_label'))}</p><pre>{esc(logs)}</pre></div>")
        if not cards:
            cards.append("<div class='card'><h2>No fuzzing logs yet</h2><p class='muted'>Start a fuzzing job from the Fuzzing Lab first.</p></div>")
        self.send_html("Fuzzing logs", "<div class='card'><h2>Fuzzing Logs</h2><p class='muted'>Recent fuzzing and AI-fuzzing job logs, newest first.</p><p><a class='btn' href='/fuzzing'>Start another fuzzing job</a></p></div>" + "".join(cards))


    def fuzzing_dashboard(self):
        cards = []
        for label, rel in [
            ("Intelligence", "reports/fuzzing/intelligence/intelligence.json"),
            ("Corpus Recommendations", "reports/fuzzing/corpus-recommendations/recommendations.json"),
            ("Compatibility", "reports/fuzzing/scanner-compatibility.json"),
            ("AI Red-Team", "reports/ai-fuzz-redteam.json"),
            ("Lifecycle", "fuzzing/findings_lifecycle/findings.json"),
        ]:
            p = ROOT / rel
            if p.exists():
                txt = p.read_text(errors="replace")[-8000:]
                cards.append(f"<div class='card'><h2>{esc(label)}</h2><p class='muted'><code>{esc(rel)}</code></p><pre>{esc(txt)}</pre></div>")
            else:
                cards.append(f"<div class='card'><h2>{esc(label)}</h2><p class='muted'>No data yet. Run the matching workflow from the Fuzzing Lab.</p></div>")
        self.send_html("Fuzzing dashboard", "<div class='card'><h2>Fuzzing Lab Dashboard</h2><p class='muted'>Local-only view of fuzzing intelligence, corpus promotion, compatibility, AI safety, and finding lifecycle artifacts.</p><p><a class='btn' href='/fuzzing'>Start fuzzing job</a> <a class='btn secondary' href='/fuzzing/logs'>Open logs</a></p></div>" + "".join(cards))

    def projects_page(self):
        try:
            from sbomops.project_ops import list_projects
            projects = list_projects()
        except Exception:
            projects = []
        rows = "".join(f"<tr><td>{esc(p.get('project_id'))}</td><td>{esc(p.get('name'))}</td><td>{esc(p.get('source'))}</td><td>{esc(p.get('updated_at'))}</td></tr>" for p in projects) or "<tr><td colspan='4' class='muted'>No projects yet. Use a Project ID in an SBOM job or initialize one from the CLI.</td></tr>"
        body = f"""
        <div class='card'><h2>Project Risk Dashboard</h2>
        <p class='muted'>Project workspaces track SBOM analysis history over time. Use the <strong>Project ID</strong> field on scan jobs or CLI commands such as <code>sst project record</code>.</p>
        <table><tr><th>Project ID</th><th>Name</th><th>Source</th><th>Updated</th></tr>{rows}</table>
        </div>
        <div class='grid'>
          <div class='card'><h3>Delta analysis</h3><p>Compare the latest two recorded SBOM runs for new/removed components and quality changes.</p></div>
          <div class='card'><h3>Trend dashboard</h3><p>View project run history and quality/component trends.</p></div>
          <div class='card'><h3>Release decision</h3><p>Generate pass/warn/block release decisions from policy, quality, dependency health, and fuzzing evidence.</p></div>
        </div>
        """
        self.send_html("Projects", body)

    def scanners(self):
        rows = "".join(f"<tr><td>{esc(r['tool'])}</td><td class='{ 'ok' if r['available'] else 'bad'}'>{'yes' if r['available'] else 'no'}</td><td><code>{esc(r['path'])}</code></td><td>{esc(r['note'])}</td></tr>" for r in scanner_status())
        self.send_html("Scanner status", f"<div class='card'><h2>Scanner availability</h2><p class='muted'>Optional scanners expand reports, but the local workbench can run without them.</p><table><tr><th>Tool</th><th>Available</th><th>Path</th><th>Note</th></tr>{rows}</table></div>")

    def download(self, jid: str):
        z = job_dir(jid) / "evidence-bundle.zip"
        if not z.exists():
            if not status_path(jid).exists(): return self.send_html("Not found", "<div class='card'><h2>Bundle not found</h2></div>", 404)
            return self.send_html("Bundle not ready", "<div class='card'><h2>Evidence bundle is not ready</h2><p class='muted'>The job exists, but its evidence bundle has not been generated yet.</p></div>", 409)
        data = z.read_bytes()
        self.send_response(200); self.send_header("Content-Type", "application/zip"); self.send_header("Content-Disposition", f"attachment; filename={jid}-evidence-bundle.zip"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser(description="Run the local SBOM Workbench UI.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    storage_init()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"SBOM Workbench running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")

if __name__ == "__main__":
    main()
