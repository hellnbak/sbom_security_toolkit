#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

from .job_runner import (
    ROOT, JOBS, WORKFLOWS, FUZZ_WORKFLOWS, create_job, delete_job, list_jobs, read_status, save_upload,
    scanner_status, status_path, logs_path, job_dir, storage_init, MAX_UPLOAD_BYTES
)

CSS = """
:root{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#172033;background:#f6f7fb}body{margin:0}.top{background:#111827;color:white;padding:18px 28px}.wrap{max-width:1100px;margin:24px auto;padding:0 18px}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:20px;margin:16px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}h1,h2{margin:.2rem 0 1rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.btn,button,input[type=submit]{background:#2563eb;color:white;border:0;border-radius:10px;padding:10px 14px;text-decoration:none;display:inline-block;cursor:pointer}.btn.secondary{background:#374151}.btn.danger,button.danger{background:#dc2626}.muted{color:#6b7280}.pill{border-radius:999px;padding:4px 9px;font-size:12px;background:#e5e7eb}.completed{background:#dcfce7;color:#14532d}.failed{background:#fee2e2;color:#7f1d1d}.running,.queued{background:#dbeafe;color:#1e3a8a}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e5e7eb;text-align:left;padding:10px}code,pre{background:#f3f4f6;border-radius:8px}pre{padding:14px;overflow:auto;max-height:520px}.nav a{color:white;margin-right:16px}input,select{padding:9px;border:1px solid #d1d5db;border-radius:8px}label{display:block;font-weight:600;margin:12px 0 6px}.small{font-size:13px}.ok{color:#166534}.bad{color:#991b1b}
"""

def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{CSS}</style></head><body><div class='top'><h1>SBOM Security Toolkit Workbench</h1><div class='nav'><a href='/'>Upload</a><a href='/jobs'>Jobs</a><a href='/scanners'>Scanner Status</a><a href='/fuzzing'>Fuzzing Lab</a></div></div><main class='wrap'>{body}</main></body></html>""".encode()

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
        if path == "/fuzzing": return self.fuzzing_lab()
        if path == "/fuzzing/logs": return self.fuzzing_logs()
        if path.startswith("/api/jobs/"): return self.api_job(path.split("/", 3)[3])
        if path.startswith("/download/"): return self.download(path.split("/", 2)[2])
        self.send_html("Not found", "<div class='card'><h2>Not found</h2></div>", 404)

    def do_POST(self):
        if self.path == "/upload": return self.upload()
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
            upload = save_upload(filename, content)
            options = {k: fields.get(k, "") for k in ["count", "edge", "budget_profile", "ai_provider", "ai_model", "ai_goal", "scenario", "dtrack_url", "target"]}
            jid = create_job(fields.get("workflow", "analyze"), upload, policy=fields.get("policy", "policies/default-release-policy.yml"), network=fields.get("network") == "1", options=options)
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
        body = f"{refresh}<div class='card'><h2>Job {esc(jid)}</h2><p><span class='pill {esc(s.get('state'))}'>{esc(s.get('state'))}</span> {esc(s.get('workflow_label'))}</p><p class='muted'>Input: <code>{esc(s.get('input_file'))}</code></p><p><a class='btn' href='/download/{esc(jid)}'>Download evidence bundle</a> <a class='btn secondary' href='/api/jobs/{esc(jid)}'>JSON status</a></p><form method='post' action='/delete/{esc(jid)}'><button class='danger'>Delete job</button></form></div><div class='card'><h2>Workflow Options</h2>{options_html}</div><div class='card'><h2>Steps</h2><table><tr><th>Step</th><th>Exit</th><th>Seconds</th></tr>{steps}</table></div><div class='card'><h2>Results</h2>{result_links}</div><div class='card'><h2>Logs</h2><pre>{esc(logs[-20000:])}</pre></div>"
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
            <div><label>Edge case</label><select name='edge'><option>valid-edge</option><option>dependency-cycle</option><option>duplicate-bom-ref</option><option>conflicting-identities</option><option>missing-version</option><option>huge-version</option><option>unicode</option><option>invalid-license</option></select></div>
            <div><label>Budget profile</label><select name='budget_profile'><option value='fuzzing/budgets/pr-smoke.yml'>PR smoke</option><option value='fuzzing/budgets/nightly-deep.yml'>Nightly deep</option></select></div>
            <div><label>Dependency-Track URL</label><input name='dtrack_url' value='http://127.0.0.1:8081' size='28'></div>
          </div>
          <div class='grid'>
            <div><label>AI provider</label><select name='ai_provider'><option value='none'>prompt-only / none</option><option value='glm'>GLM local/OpenAI-compatible</option><option value='ollama'>Ollama-compatible</option><option value='openai-compatible'>OpenAI-compatible</option></select></div>
            <div><label>AI model</label><input name='ai_model' placeholder='glm-5.2' size='20'></div>
            <div><label>AI scenario</label><input name='scenario' value='dependency-cycles' size='24'></div>
            <div><label>AI goal</label><input name='ai_goal' value='scanner-disagreement-hardening' size='28'></div>
          </div>
          <label>Harness repair target</label><input name='target' value='fuzzing/engines/python/targets/cyclonedx_json_atheris.py' size='72'>
          <p><label><input type='checkbox' name='network' value='1'> Allow network-enabled enrichment/scanner actions when available</label></p>
          <input type='submit' value='Start fuzzing job'>
        </form></div>
        <div class='grid'>
          <div class='card'><h3>Recommended starters</h3><p><strong>Round-trip</strong>, <strong>semantic oracles</strong>, <strong>structured mutations</strong>, and <strong>fuzz-all-local</strong> are good safe first runs.</p></div>
          <div class='card'><h3>Scanner workflows</h3><p>Toolchain, compatibility, truth-set, and metamorphic scanner workflows depend on locally installed scanners.</p></div>
          <div class='card'><h3>AI-assisted workflows</h3><p>Prompt-only mode works without keys. GLM/Ollama/OpenAI-compatible endpoints are optional and review-gated.</p></div>
        </div>
        <div class='card'><h2>Recent Fuzzing Jobs</h2><table><tr><th>Job</th><th>Workflow</th><th>Status</th><th>Created</th></tr>{recent_rows}</table><p><a class='btn secondary' href='/fuzzing/logs'>Open fuzzing logs</a></p></div>
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
