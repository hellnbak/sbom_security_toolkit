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

CSS = """
:root{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#172033;background:#f6f7fb}body{margin:0}.top{background:#111827;color:white;padding:18px 28px}.wrap{max-width:1100px;margin:24px auto;padding:0 18px}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:20px;margin:16px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}h1,h2{margin:.2rem 0 1rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.btn,button,input[type=submit]{background:#2563eb;color:white;border:0;border-radius:10px;padding:10px 14px;text-decoration:none;display:inline-block;cursor:pointer}.btn.secondary{background:#374151}.btn.danger,button.danger{background:#dc2626}.muted{color:#6b7280}.pill{border-radius:999px;padding:4px 9px;font-size:12px;background:#e5e7eb}.completed{background:#dcfce7;color:#14532d}.failed{background:#fee2e2;color:#7f1d1d}.running,.queued{background:#dbeafe;color:#1e3a8a}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e5e7eb;text-align:left;padding:10px}code,pre{background:#f3f4f6;border-radius:8px}pre{padding:14px;overflow:auto;max-height:520px}.nav a{color:white;margin-right:16px}input,select,textarea{padding:9px;border:1px solid #d1d5db;border-radius:8px}textarea{width:100%;min-height:160px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}label{display:block;font-weight:600;margin:12px 0 6px}.small{font-size:13px}.ok{color:#166534}.bad{color:#991b1b}
"""

def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{CSS}</style></head><body><div class='top'><h1>SBOM Security Toolkit Workbench</h1><div class='nav'><a href='/'>Upload</a><a href='/jobs'>Jobs</a><a href='/scanners'>Scanner Status</a><a href='/repository'>Repository Intake</a><a href='/projects'>Projects</a><a href='/settings'>Settings</a><a href='/admin'>Admin</a><a href='/integrations'>Integrations</a><a href='/findings'>Findings</a><a href='/reports'>Reports</a><a href='/fuzzing'>Fuzzing Lab</a><a href='/fuzzing/dashboard'>Fuzz Dashboard</a></div></div><main class='wrap'>{body}</main></body></html>""".encode()

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
        raw = page(title, body)
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def send_json(self, data, code=200):
        raw = json.dumps(data, indent=2, sort_keys=True).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        if path == "/": return self.index()
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
        if self.path == "/settings/save": return self.settings_save()
        if self.path == "/admin/save": return self.admin_save()
        if self.path == "/integrations/save": return self.integrations_save()
        if self.path == "/findings/save": return self.findings_save()
        if self.path == "/reports/refresh": return self.reports_refresh()
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
          <label>Policy path</label><input name='policy' value='policies/default-release-policy.yml' size='46'>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled enrichment/scanner actions when available</label></p>
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
            options = {k: fields.get(k, "") for k in ["count", "duration_seconds", "library_targets", "edge", "budget_profile", "ai_provider", "ai_model", "ai_goal", "scenario", "dtrack_url", "target", "grammar", "finding_id", "finding_state", "repo_generators", "repo_source_type", "repo_allow_remote", "repo_fuzz", "repo_dependency_health", "stale_days", "ai_analysis_enabled", "ai_analysis_mode", "ai_max_cases", "project_id"]}
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
            if kind == 'exports':
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

    def parse_urlencoded(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[-1] if v else "" for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

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
            <div><label>Stale threshold days</label><input name='stale_days' value='365' size='8'></div>
          </div>
          <label>Repository archive upload</label><input type='file' name='sbom'>
          <p class='small muted'>Allowed: .zip, .tar.gz/.tgz, plus SBOM file types for normal workflows. Max size: {MAX_UPLOAD_BYTES//(1024*1024)} MB.</p>
          <label>Local path or GitHub URL</label><input name='repo_source' placeholder='/path/to/repo or https://github.com/org/private-repo.git' size='84'>
          <div class='grid'>
            <div><label>GitHub token for private repos</label><input name='github_token' type='password' placeholder='not stored on disk' size='32'><p class='small muted'>Held only in process memory for the current job and passed as GITHUB_TOKEN.</p></div>
            <div><label>Allow remote Git clone</label><select name='repo_allow_remote'><option value='0'>No</option><option value='1'>Yes</option></select><p class='small muted'>Required for GitHub URL intake.</p></div>
          </div>
          <label>Policy path</label><input name='policy' value='policies/default-release-policy.yml' size='46'>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled scanners/enrichment when available, including registry metadata for dependency-health checks</label></p>
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
            # Try creating a status-only placeholder if job exists.
            if not status_path(jid).exists(): return self.send_html("Not found", "<div class='card'><h2>Bundle not found</h2></div>", 404)
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
