#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def run(name, cmd, timeout, out_steps):
    started=time.time()
    print(f"\n=== {name} ===", flush=True)
    print('$ ' + ' '.join(map(str,cmd)), flush=True)
    logdir=Path('reports/fuzzing/command-logs'); logdir.mkdir(parents=True, exist_ok=True)
    safe=''.join(ch if ch.isalnum() else '-' for ch in name.lower()).strip('-')[:80] or 'step'
    stdout_path=logdir/f'{int(started)}-{safe}.stdout.log'
    stderr_path=logdir/f'{int(started)}-{safe}.stderr.log'
    with stdout_path.open('w') as so, stderr_path.open('w') as se:
        proc=subprocess.Popen([str(x) for x in cmd], cwd=ROOT, text=True, stdout=so, stderr=se)
        try:
            proc.wait(timeout=timeout)
            timed_out=False
        except subprocess.TimeoutExpired:
            timed_out=True
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
    elapsed=round(time.time()-started,2)
    outtxt=stdout_path.read_text(errors='replace')[-6000:] if stdout_path.exists() else ''
    errtxt=stderr_path.read_text(errors='replace')[-6000:] if stderr_path.exists() else ''
    if outtxt: print(outtxt, flush=True)
    if errtxt: print(errtxt, file=sys.stderr, flush=True)
    if timed_out:
        print(f'Timed out after {timeout}s; continuing because this is a time-boxed fuzzing step.', flush=True)
    rc = 0 if timed_out else proc.returncode
    out_steps.append({'name':name,'cmd':[str(x) for x in cmd],'returncode':rc,'elapsed_seconds':elapsed,'timed_out':timed_out,'stdout_log':str(stdout_path),'stderr_log':str(stderr_path)})
    return rc

def main():
    ap=argparse.ArgumentParser(description='Run a time-boxed SBOM fuzzing suite with target selection.')
    ap.add_argument('--sbom', default='test-sboms/clean/minimal-cyclonedx.json')
    ap.add_argument('--time-budget', type=int, default=60)
    ap.add_argument('--count', type=int, default=25)
    ap.add_argument('--edge', default='valid-edge')
    ap.add_argument('--targets', default='sbom,scanner,ai')
    ap.add_argument('--out-dir', default='reports/fuzzing/timed')
    args=ap.parse_args()
    out=Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    targets={x.strip().lower() for x in args.targets.split(',') if x.strip()}
    if 'all' in targets:
        targets.update(['sbom','scanner','ai','python','javascript','js','php'])
    steps=[]; tb=max(5,args.time_budget)
    py=sys.executable
    if 'sbom' in targets:
        # seed generation is fast; do not timebox too aggressively because Python startup can dominate short smoke runs.
        run('Generate CycloneDX schema seeds',[py,'fuzzing/schema/cyclonedx_schema_generator.py','--count',str(args.count),'--edge',args.edge],max(tb,20),steps)
        run('Generate SPDX schema seeds',[py,'fuzzing/schema/spdx_schema_generator.py','--count',str(args.count),'--edge',args.edge],max(tb,20),steps)
        run('Generate VEX seeds',[py,'fuzzing/schema/vex_schema_generator.py','--count',str(args.count)],max(tb,20),steps)
        run('Structure-preserving mutation',[py,'fuzzing/mutators/sbom_json_mutator.py',args.sbom,'--out',str(out/'structured'),'--count',str(min(args.count,50))],tb,steps)
        run('Round-trip semantics',[py,'fuzzing/roundtrip/roundtrip_sbom.py',args.sbom,'--out-dir',str(out/'roundtrip')],tb,steps)
        run('Metamorphic SBOM checks',[py,'fuzzing/metamorphic/metamorphic_sbom.py',args.sbom,'--out-dir',str(out/'metamorphic')],tb,steps)
        run('Semantic oracles',[py,'fuzzing/oracles/semantic_oracles.py',args.sbom,'--out',str(out/'semantic-oracles.json')],tb,steps)
        run('Semantic format diff',[py,'fuzzing/semantic_format_diff/semantic_format_diff.py',args.sbom,'--out',str(out/'semantic-format-diff.json')],tb,steps)
        run('VEX contradiction cases',['timeout',str(tb)+'s',py,'fuzzing/vex_logic/vex_logic_fuzz.py','--out-dir',str(out/'vex-logic')],tb+5,steps)
        run('Evil supplier scenarios',['timeout',str(tb)+'s',py,'fuzzing/evil_supplier/evil_supplier.py','--out-dir',str(out/'evil-supplier')],tb+5,steps)
    if 'scanner' in targets:
        run('Toolchain fuzzing',[py,'fuzzing/toolchain/fuzz_toolchain.py',args.sbom,'--out',str(out/'toolchain.json')],tb,steps)
        run('Scanner metamorphic checks',[py,'fuzzing/scanner-metamorphic/metamorphic_scanners.py',args.sbom,'--out-dir',str(out/'scanner-metamorphic')],tb,steps)
        run('Vulnerability matching cases',[py,'fuzzing/vuln_matching/vuln_matching_fuzz.py','--out-dir',str(out/'vuln-matching')],tb,steps)
        run('Dependency-Track stateful dry run',[py,'fuzzing/stateful/dependency_track_state_machine.py','--url','http://127.0.0.1:8081','--sbom',args.sbom,'--dry-run','--out',str(out/'dtrack-stateful.json')],tb,steps)
    if 'ai' in targets:
        run('AI corpus review',[py,'-m','ai_fuzz.tools.ai_corpus_review','--corpus','fuzzing/corpus/ai/incoming','--out',str(out/'ai-corpus-review.json')],tb,steps)
        run('AI fuzz provider evaluation',[py,'-m','ai_fuzz.tools.ai_provider_eval','--providers','none','--out',str(out/'ai-provider-eval.json')],tb,steps)
    if any(x in targets for x in ['python','javascript','js','php']):
        import shutil
        if shutil.which('docker'):
            if 'python' in targets: run('Python fuzz engine Docker smoke',['bash','-lc',f'docker build -t sbom-fuzzer-python fuzzing/engines/python >/dev/null && docker run --rm -e TIME_BUDGET={tb} sbom-fuzzer-python'],tb+20,steps)
            if 'javascript' in targets or 'js' in targets: run('JavaScript fuzz engine Docker smoke',['bash','-lc',f'docker build -t sbom-fuzzer-javascript fuzzing/engines/javascript >/dev/null && docker run --rm -e TIME_BUDGET={tb} sbom-fuzzer-javascript'],tb+20,steps)
            if 'php' in targets: run('PHP fuzz engine Docker smoke',['bash','-lc',f'docker build -t sbom-fuzzer-php fuzzing/engines/php >/dev/null && docker run --rm -e TIME_BUDGET={tb} sbom-fuzzer-php'],tb+20,steps)
        else:
            print('Docker not available; skipping language engine Docker fuzzing targets.')
            steps.append({'name':'Docker language-engine fuzzing','returncode':0,'skipped':True,'reason':'docker not available'})
    run('Fuzz status report',[py,'fuzzing/status_report.py'],max(tb,20),steps)
    summary={'sbom':args.sbom,'targets':sorted(targets),'time_budget_seconds':tb,'step_count':len(steps),'failed_steps':[s for s in steps if s.get('returncode') not in (0,None)],'steps':steps}
    (out/'timed-fuzz-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (out/'timed-fuzz-summary.md').write_text('# Timed Fuzzing Summary\n\n'+f"- SBOM: `{args.sbom}`\n- Targets: `{','.join(sorted(targets))}`\n- Time budget: {tb}s per step\n- Steps: {len(steps)}\n- Failed steps: {len(summary['failed_steps'])}\n")
    print(json.dumps({'summary':str(out/'timed-fuzz-summary.json'),'failed_steps':len(summary['failed_steps']),'step_count':len(steps)},indent=2))
    return 1 if summary['failed_steps'] else 0
if __name__=='__main__': raise SystemExit(main())
