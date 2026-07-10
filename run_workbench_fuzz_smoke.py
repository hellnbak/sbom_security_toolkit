import time, json, shutil
from pathlib import Path
from sbomops.workbench.job_runner import create_job, read_status, FUZZ_WORKFLOWS, save_upload, STORAGE
# clean old jobs
shutil.rmtree(STORAGE/'jobs', ignore_errors=True); shutil.rmtree(STORAGE/'uploads', ignore_errors=True)
seed = Path('vuln-scan/cyclonedx-sbom.xml').read_bytes()
workflows = list(FUZZ_WORKFLOWS.keys())
results=[]
for wf in workflows:
    if wf in {'fuzz-python','fuzz-js','fuzz-php'}: continue
    upload=save_upload('seed.xml', seed)
    opts={'count':'2','duration_seconds':'2','library_targets':'sbom,scanner,ai','edge':'valid-edge','ai_provider':'none','ai_goal':'scanner-disagreement-hardening','budget_profile':'fuzzing/budgets/pr-smoke.yml','target':'fuzzing/engines/python/targets/cyclonedx_json_atheris.py','grammar':'cyclonedx'}
    jid=create_job(wf, upload, options=opts)
    deadline=time.time()+45
    st={}
    while time.time()<deadline:
        st=read_status(jid)
        if st.get('state') in {'completed','failed'}: break
        time.sleep(.2)
    log=(STORAGE/'jobs'/jid/'logs.txt').read_text(errors='replace') if (STORAGE/'jobs'/jid/'logs.txt').exists() else ''
    results.append({'workflow':wf,'state':st.get('state'),'exit_code':st.get('exit_code'),'error':st.get('error'),'log_tail':log[-1000:]})
    print(wf, st.get('state'), st.get('exit_code'), st.get('error'))
Path('/mnt/data/workbench_fuzz_results.json').write_text(json.dumps(results, indent=2))
fail=[r for r in results if r['state']!='completed' or r.get('exit_code') not in (0,None)]
print('failures', len(fail))
for f in fail: print('FAIL', f['workflow'], f['state'], f['exit_code'], f['error'], f['log_tail'][-300:])
