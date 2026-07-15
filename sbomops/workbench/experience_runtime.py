#!/usr/bin/env python3
"""Executable guided experience and local UX routes for the Workbench."""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Dict


def install_server_hooks(namespace: Dict[str, Any]) -> None:
    if namespace.get("_SST_V214_EXPERIENCE_HOOKS_INSTALLED"):
        return
    namespace["_SST_V214_EXPERIENCE_HOOKS_INSTALLED"] = True

    Handler = namespace["Handler"]
    ROOT = namespace["ROOT"]
    esc = namespace["esc"]
    try:
        ux = namespace["ux"]
    except KeyError:
        from sbomops.workbench import ux
    original_do_get = Handler.do_GET
    original_do_post = Handler.do_POST
    guide_file = ROOT / "ui" / "storage" / "onboarding.json"

    def _guide_state(self):
        try:
            return json.loads(guide_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_guide_state(self, updates):
        state = self._guide_state(); state.update(updates)
        guide_file.parent.mkdir(parents=True, exist_ok=True)
        guide_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return state

    def welcome_page(self, url):
        q = urllib.parse.parse_qs(url.query); step = max(1, min(5, int(q.get("step", ["1"])[0])))
        state = self._guide_state()
        steps = "".join(f"<span class='pill {'running' if n==step else 'completed' if n<step else ''}'>{n}</span>" for n in range(1,6))
        forms = {
            1: "<input type='hidden' name='step' value='1'><h2>What do you need to accomplish?</h2><select name='goal'><option value='repository'>Analyze a repository</option><option value='sbom'>Analyze an SBOM</option><option value='release'>Review a release</option><option value='connector'>Configure a connector</option></select>",
            2: f"<input type='hidden' name='step' value='2'><h2>Choose the source</h2><input name='source' size='75' value='{esc(state.get('source',''))}' placeholder='Local path, repository URL, or SBOM file; blank uses the synthetic sample'>",
            3: "<input type='hidden' name='step' value='3'><h2>Choose the environment</h2><select name='environment'><option>development</option><option>staging</option><option selected>production</option><option>regulated</option></select>",
            4: "<input type='hidden' name='step' value='4'><h2>Choose the policy profile</h2><select name='policy'><option>basic</option><option selected>standard</option><option>production</option><option>high-assurance</option></select>",
            5: f"<input type='hidden' name='step' value='5'><h2>Run the first task</h2><input name='project_id' value='{esc(state.get('project_id','guided-project'))}'><p>The wizard will queue a real background job, create evidence, and automatically generate the detailed engineering report.</p>",
        }
        body=f"<div class='card'><h1>Quick Start</h1><p>{steps}</p><form method='post' action='/welcome/save'>{forms[step]}<p><button>{'Run now' if step==5 else 'Continue'}</button></p></form></div>"
        self.send_html("Quick Start", body)

    def welcome_save(self):
        fields=self.parse_urlencoded(); step=int(fields.pop("step","1")); self._save_guide_state({k:v for k,v in fields.items() if k!="complete"})
        if step<5:return self.redirect(f"/welcome?step={step+1}")
        self._save_guide_state({"complete":True})
        try:
            from sbomops.wizard_runtime import start_from_guide
            result=start_from_guide(self._guide_state()); ux.add_activity("guided_job_started",result.get("job_id",result.get("route",""))); return self.redirect(result["route"])
        except Exception as exc:return self.send_html("Quick Start error",f"<div class='card'><h2>Unable to start</h2><pre>{esc(exc)}</pre></div>",400)

    def workflows_page(self, url):
        q=urllib.parse.parse_qs(url.query); chosen=q.get("task",[""])[0]
        cards="".join(f"<div class='card'><h3>{esc(label)}</h3><p>Queues an executable job and automatic report.</p><a class='btn' href='/workflows?task={esc(key)}'>Configure</a></div>" for key,label in ux.TASKS)
        detail=""
        if chosen:
            label=dict(ux.TASKS).get(chosen,chosen);profiles="".join(f"<option value='{esc(k)}'>{esc(v['label'])}</option>" for k,v in ux.SCAN_PROFILES.items())
            detail=f"<div class='card'><h2>{esc(label)}</h2><form action='/workflows/run' method='post'><input type='hidden' name='task' value='{esc(chosen)}'><label>Source</label><input name='source' size='75' placeholder='Blank uses safe synthetic sample'><label>Profile</label><select name='profile'>{profiles}</select><label>Environment</label><select name='environment'><option>development</option><option>staging</option><option selected>production</option><option>regulated</option></select><label>Project ID</label><input name='project_id' value='guided-project'><p><button>Run workflow now</button></p></form></div>"
        self.send_html("Guided Workflows",f"<div class='card'><h1>Guided workflows</h1><p>Choose an outcome. These launch tasks; they are not navigation shortcuts.</p></div>{detail}<div class='grid'>{cards}</div>")

    def workflows_run(self):
        f=self.parse_urlencoded()
        try:
            from sbomops.wizard_runtime import start_guided
            jid=start_guided(task=f.get("task","analysis"),source=f.get("source",""),profile=f.get("profile","standard"),environment=f.get("environment","production"),project_id=f.get("project_id","guided-project"));ux.add_activity("guided_workflow_started",jid);return self.redirect(f"/jobs/{jid}")
        except Exception as exc:return self.send_html("Workflow error",f"<div class='card'><pre>{esc(exc)}</pre></div>",400)

    def project_wizard(self, url):
        body="""<div class='card'><h1>Create a project</h1><form method='post' action='/project/new/save'><div class='grid'><div><label>Name</label><input name='name' required></div><div><label>Source</label><input name='source'></div><div><label>Environment</label><select name='environment'><option>development</option><option>staging</option><option selected>production</option></select></div><div><label>Criticality</label><select name='criticality'><option>low</option><option>medium</option><option selected>high</option></select></div><div><label>Technical owner</label><input name='technical_owner'></div><div><label>Security owner</label><input name='security_owner'></div><div><label>Classification</label><select name='classification'><option>public</option><option>internal</option><option selected>confidential</option><option>restricted</option></select></div><div><label>Policy</label><select name='policy'><option>basic</option><option selected>standard</option><option>production</option><option>high-assurance</option></select></div></div><label><input type='checkbox' name='internet_exposed' value='1'> Internet-facing</label><label><input type='checkbox' name='run_initial' value='1' checked> Run initial analysis now</label><p><button>Create project</button></p></form></div>"""
        self.send_html("Create project",body)

    def project_wizard_save(self):
        f=self.parse_urlencoded(); name=namespace["safe_slug"](f.get("name","project")); target=ROOT/"configs/generated/projects"/f"{name}.yml";target.parent.mkdir(parents=True,exist_ok=True)
        data={"project_id":name,"name":f.get("name"),"source":f.get("source"),"environment":f.get("environment"),"business_criticality":f.get("criticality"),"internet_exposed":self.bool_field(f,"internet_exposed"),"data_classification":f.get("classification"),"default_policy":f.get("policy"),"owners":{"technical":f.get("technical_owner"),"security":f.get("security_owner")}}
        target.write_text(namespace["yaml"].safe_dump(data,sort_keys=False),encoding="utf-8");self._save_guide_state({"project_created":True,"project_id":name})
        if f.get("run_initial")=="1":
            try:
                from sbomops.wizard_runtime import start_project
                result=start_project(data);ux.add_activity("project_created_and_scan_started",result["job_id"]);return self.redirect(result["route"])
            except Exception as exc:return self.send_html("Project created",f"<div class='card'><p>{esc(target)}</p><pre>{esc(exc)}</pre></div>",400)
        ux.add_activity("project_created",name);return self.redirect("/projects")

    def connectors_setup(self):
        body="""<div class='card'><h1>Connector setup</h1><p>Configuration is read-only/dry-run by default. Tokens are referenced by environment variable.</p><form method='post' action='/connectors/setup/save'><label>Name</label><input name='name' value='snyk'><label>Type</label><select name='type'><option>snyk</option><option>dependency-track</option><option>defectdojo</option><option>github</option><option>webhook</option></select><label>Base URL</label><input name='base_url' size='70'><label>Token environment variable</label><input name='token_env' value='SNYK_TOKEN'><label>Mode</label><select name='mode'><option>read-only</option><option>dry-run</option><option>write</option></select><label><input type='checkbox' name='test_now' value='1' checked> Validate after saving</label><p><button>Save connector</button></p></form></div>"""
        self.send_html("Connector setup",body)

    def connectors_setup_save(self):
        import argparse
        from sbomops import connectors
        f=self.parse_urlencoded(); a=argparse.Namespace(config="configs/connectors.yml",name=f.get("name","connector"),type=f.get("type","webhook"),base_url=f.get("base_url",""),token_env=f.get("token_env",""),project=f.get("project",""),mode=f.get("mode","read-only"),disabled=False)
        saved=connectors.configure(a); result={"saved":saved}
        if f.get("test_now")=="1":
            result["test"]=connectors.test(argparse.Namespace(config=a.config,name=a.name,send=False))
        ux.add_activity("connector_configured",a.name);self.send_html("Connector saved",f"<div class='card'><h2>Connector saved</h2><pre>{esc(json.dumps(result,indent=2))}</pre><p><a class='btn' href='/connectors/setup'>Back</a></p></div>")

    def sample_page(self):
        self._save_guide_state({"sample_loaded":True});self.send_html("Live sample", "<div class='card'><h1>Live synthetic sample</h1><p>Runs the normal pipeline, logs, evidence archive, and automatic report.</p><form method='post' action='/demo/run'><button>Run live demo</button></form></div>")

    def demo_qa_page(self):
        jobs=[j for j in namespace["list_jobs"]() if j.get("workflow")=="demo-live"][:10];rows="".join(f"<tr><td><a href='/jobs/{esc(j.get('job_id'))}'>{esc(j.get('job_id'))}</a></td><td>{esc(j.get('state'))}</td><td>{esc((j.get('reporting') or {}).get('state','pending'))}</td></tr>" for j in jobs) or "<tr><td colspan='3'>No demo jobs yet.</td></tr>"
        self.send_html("Demo / QA",f"<div class='card'><h1>Demo / QA</h1><p>Credential-free and offline, but executes the real job runner.</p><form method='post' action='/demo/run'><button>Run live demo</button></form></div><div class='card'><table><tr><th>Job</th><th>State</th><th>Report</th></tr>{rows}</table></div>")

    def demo_qa_run(self):
        try:
            from sbomops.demo_runtime import start_demo
            jid=start_demo(wait=False);ux.add_activity("live_demo_started",jid);return self.redirect(f"/jobs/{jid}")
        except Exception as exc:return self.send_html("Demo error",f"<div class='card'><pre>{esc(exc)}</pre></div>",400)

    def saved_views_page(self):
        rows="".join(f"<tr><td>{esc(x.get('name'))}</td><td><code>{esc(json.dumps(x.get('filters',{})))}</code></td></tr>" for x in ux.saved_views()) or "<tr><td colspan='2'>No saved views.</td></tr>"
        self.send_html("Saved views",f"<div class='card'><h1>Saved views</h1><form method='post' action='/saved-views/save'><label>Name</label><input name='name' required><label>Filter JSON</label><input name='filters' value='{{\"severity\":\"critical\"}}' size='70'><button>Save</button></form></div><div class='card'><table>{rows}</table></div>")

    def saved_views_save(self):
        f=self.parse_urlencoded()
        try:filters=json.loads(f.get("filters","{}"))
        except Exception:filters={"query":f.get("filters","")}
        ux.save_view(f.get("name","view"),filters);ux.add_activity("saved_view_created",f.get("name","view"));self.redirect("/saved-views")

    def activity_page(self):
        rows="".join(f"<tr><td>{esc(x.get('at'))}</td><td>{esc(x.get('action'))}</td><td>{esc(x.get('subject'))}</td></tr>" for x in reversed(ux.load_state('activity.json',[])[-100:])) or "<tr><td colspan='3'>No activity yet.</td></tr>"
        self.send_html("Activity",f"<div class='card'><h1>Activity timeline</h1><table><tr><th>Time</th><th>Action</th><th>Subject</th></tr>{rows}</table></div>")

    def notifications_page(self):
        p=ux.preferences();n=p.get("notifications",{});checks="".join(f"<label><input type='checkbox' name='{k}' value='1' {'checked' if v else ''}> {k.replace('_',' ').title()}</label>" for k,v in n.items())
        self.send_html("Notifications",f"<div class='card'><h1>Notification preferences</h1><form method='post' action='/notifications/save'>{checks}<button>Save</button></form></div>")

    def notifications_save(self):
        f=self.parse_urlencoded();keys=['job_complete','release_blocked','exception_expiring'];p=ux.preferences();p['notifications']={k:f.get(k)=='1' for k in keys};ux.save_preferences(p);ux.add_activity("notification_preferences_updated");self.redirect('/notifications')

    def personas_page(self):
        opts="".join(f"<option value='{k}'>{esc(v)}</option>" for k,v in ux.PERSONAS.items());p=ux.preferences();self.send_html("Personas",f"<div class='card'><h1>Role-specific home view</h1><form method='post' action='/personas/save'><select name='persona'>{opts}</select><select name='mode'><option>guided</option><option>advanced</option></select><button>Save</button></form><p>Current: {esc(p.get('persona'))} / {esc(p.get('mode'))}</p></div>")

    def personas_save(self):
        f=self.parse_urlencoded();ux.save_preferences({'persona':f.get('persona','security'),'mode':f.get('mode','guided')});ux.add_activity("persona_updated",f.get('persona','security'));self.redirect('/personas')

    def policy_simulator_page(self, result=None):
        output=f"<pre>{esc(json.dumps(result,indent=2))}</pre>" if result else ""
        self.send_html("Policy simulator",f"<div class='card'><h1>Policy simulator</h1><form method='post' action='/policy-simulator/run'><label>Severity</label><select name='severity'><option>low</option><option>medium</option><option selected>high</option><option>critical</option></select><label><input type='checkbox' name='internet_exposed' value='1'> Internet exposed</label><label><input type='checkbox' name='kev' value='1'> Known exploited</label><label><input type='checkbox' name='exception' value='1'> Approved exception</label><button>Simulate</button></form>{output}</div>")

    def policy_simulator_run(self):
        f=self.parse_urlencoded();r=ux.simulate_policy(f.get('severity','high'),f.get('internet_exposed')=='1',f.get('kev')=='1',f.get('exception')=='1');ux.add_activity('policy_simulated',r['decision']);self.policy_simulator_page(r)

    def support_page(self):
        bundle=ux.support_bundle();self.send_html("Support",f"<div class='card'><h1>Sanitized support bundle</h1><p>Generated locally with secret-like fields redacted.</p><p><code>{esc(bundle)}</code></p></div>")

    def feedback_page(self):
        self.send_html("Feedback","<div class='card'><h1>Product feedback</h1><form method='post' action='/feedback/save'><label>Category</label><select name='category'><option>bug</option><option>usability</option><option>feature</option></select><label>Message</label><textarea name='message' required></textarea><button>Save locally</button></form></div>")

    def feedback_save(self):
        f=self.parse_urlencoded();items=ux.load_state('feedback.json',[]);items.append({'category':f.get('category'),'message':f.get('message'),'created_at':ux._now()});ux.save_state('feedback.json',items);ux.add_activity('feedback_saved',f.get('category'));self.redirect('/feedback')

    def capability_page(self, title, message):
        self.send_html(title, f"<div class='card'><h1>{esc(title)}</h1><p>{esc(message)}</p><p><a class='btn' href='/workflows'>Start a guided workflow</a></p></div>")

    def dashboard_page(self):
        return self.index()

    def decisions_page(self):
        return self.capability_page("Release Decisions", "Release-assurance decisions generated by completed jobs appear in job evidence and reports.")

    def actions_page(self):
        return self.capability_page("Action Center", "Prioritized remediation and workflow actions are generated from completed analyses.")

    def controls_page(self):
        return self.capability_page("Security Controls", "Run Release Assurance, VEX, Provenance, Evidence, Organization Context, and Remediation workflows from Guided Workflows.")

    def exceptions_page(self):
        return self.capability_page("Exceptions", "Risk exceptions remain local, scoped, approved, and time-bounded.")

    def evidence_page(self):
        return self.capability_page("Evidence", "Download evidence bundles from completed job pages.")

    def search_page(self):
        return self.capability_page("Search", "Use job, project, finding, and report pages to locate local evidence.")

    def help_page(self):
        self.send_html("Help","<div class='card'><h1>Help Center</h1><p><a href='/welcome'>Quick Start</a> · <a href='/workflows'>Guided workflows</a> · <a href='/demo'>Live demo</a> · <a href='/connectors/setup'>Connector setup</a></p><p>Every completed run automatically generates the detailed security engineering report. Generate additional variants from the job page without rerunning analysis.</p></div>")

    def reports_generate_variant(self):
        f=self.parse_urlencoded();jid=f.get("job_id","");variant=f.get("variant","executive")
        try:
            from sbomops.reporting_runtime import generate_variant
            status=namespace["read_status"](jid);options=status.get("options") or {};generate_variant(namespace["job_dir"](jid),variant,provider=options.get("report_provider") or options.get("ai_provider") or "none",model=options.get("report_model") or options.get("ai_model") or "");ux.add_activity("report_variant_generated",f"{jid}:{variant}")
            try:
                from sbomops.workbench.job_runner import create_evidence_zip, write_status
                bundle=create_evidence_zip(jid);status=namespace["read_status"](jid);status["bundle"]=str(bundle.relative_to(ROOT));write_status(jid,status)
            except Exception:pass
            return self.redirect(f"/jobs/{jid}")
        except Exception as exc:return self.send_html("Report error",f"<div class='card'><pre>{esc(exc)}</pre></div>",400)

    def job(self,jid):
        try:s=namespace["read_status"](jid)
        except FileNotFoundError:return self.send_html("Job not found","<div class='card'><h2>Job not found</h2></div>",404)
        logs=namespace["logs_path"](jid).read_text(errors="replace") if namespace["logs_path"](jid).exists() else "";options_html=self.options_table(s.get("options") or {});steps="".join(f"<tr><td>{esc(x.get('name'))}</td><td>{esc(x.get('returncode'))}</td><td>{esc(x.get('elapsed_seconds',''))}</td><td>{'no' if x.get('blocking') is False else 'yes'}</td></tr>" for x in s.get("steps",[])) or "<tr><td colspan='4'>No completed steps yet.</td></tr>";reporting=s.get("reporting") or {};variants="".join(f"<option value='{esc(v)}'>{esc(v.replace('-',' ').title())}</option>" for v in reporting.get("available_variants",["executive","developer","compliance","supplier","customer","release","fuzzing","lifecycle"]));refresh="<meta http-equiv='refresh' content='3'>" if s.get("state") in {"queued","running"} else ""
        body=f"{refresh}<div class='card'><h1>Job {esc(jid)}</h1><p><span class='pill {esc(s.get('state'))}'>{esc(s.get('state'))}</span> {esc(s.get('workflow_label'))}</p><p><a class='btn' href='/download/{esc(jid)}'>Download evidence</a> <a class='btn secondary' href='/api/jobs/{esc(jid)}'>JSON</a></p></div><div class='card'><h2>Automatic reporting</h2><p>State: {esc(reporting.get('state','pending'))}</p><p>Default: <code>{esc(reporting.get('default_report','pending'))}</code></p><form method='post' action='/reports/generate-variant'><input type='hidden' name='job_id' value='{esc(jid)}'><select name='variant'>{variants}</select><button>Generate another version</button></form></div><div class='card'><h2>Options</h2>{options_html}</div><div class='card'><h2>Steps</h2><table><tr><th>Step</th><th>Exit</th><th>Seconds</th><th>Blocking</th></tr>{steps}</table></div><div class='card'><h2>Results</h2>{self.result_links(jid)}</div><div class='card'><h2>Logs</h2><pre>{esc(logs[-20000:])}</pre></div>"
        self.send_html("Job",body)

    def do_GET(self):
        url=urllib.parse.urlparse(self.path);p=url.path
        routes={"/dashboard":self.dashboard_page,"/decisions":self.decisions_page,"/actions":self.actions_page,"/controls":self.controls_page,"/exceptions":self.exceptions_page,"/evidence":self.evidence_page,"/search":self.search_page,"/welcome":lambda:self.welcome_page(url),"/workflows":lambda:self.workflows_page(url),"/project/new":lambda:self.project_wizard(url),"/connectors/setup":self.connectors_setup,"/sample":self.sample_page,"/saved-views":self.saved_views_page,"/activity":self.activity_page,"/notifications":self.notifications_page,"/personas":self.personas_page,"/policy-simulator":self.policy_simulator_page,"/support":self.support_page,"/feedback":self.feedback_page,"/help":self.help_page}
        if p in routes:return routes[p]()
        return original_do_get(self)

    def do_POST(self):
        routes={"/welcome/save":self.welcome_save,"/workflows/run":self.workflows_run,"/project/new/save":self.project_wizard_save,"/connectors/setup/save":self.connectors_setup_save,"/demo/run":self.demo_qa_run,"/reports/generate-variant":self.reports_generate_variant,"/saved-views/save":self.saved_views_save,"/notifications/save":self.notifications_save,"/personas/save":self.personas_save,"/policy-simulator/run":self.policy_simulator_run,"/feedback/save":self.feedback_save}
        if self.path in routes:return routes[self.path]()
        return original_do_post(self)

    for name,value in locals().copy().items():
        if callable(value) and name not in {"install_server_hooks"} and (name.startswith("_") or name.endswith(("_page","_save","_run","_setup","_wizard")) or name in {"job","do_GET","do_POST","workflows_page","workflows_run","sample_page","demo_qa_page","demo_qa_run","reports_generate_variant","connectors_setup"}):
            setattr(Handler,name,value)
    Handler.do_GET=do_GET;Handler.do_POST=do_POST;Handler.job=job
