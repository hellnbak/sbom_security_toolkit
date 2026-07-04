#!/usr/bin/env python3
from __future__ import annotations
import argparse
from .ai_fuzz import write_artifact, call_or_prompt, prompt_header


def main():
    ap=argparse.ArgumentParser(description='Create a provider-neutral multi-agent fuzzing workflow plan for review.')
    ap.add_argument('--goal', default='sbom-parser-hardening'); ap.add_argument('--provider', default='none'); ap.add_argument('--model', default='')
    args=ap.parse_args()
    prompt=prompt_header('Multi-agent fuzzing workflow planning') + f"""\n\nGoal: {args.goal}\n\nDefine roles and outputs for:\n- Seed Agent\n- Harness Agent\n- Oracle Agent\n- Triage Agent\n- Campaign Agent\n- Report Agent\n\nRules: local-first, no automatic code execution, no automatic corpus promotion, no final VEX decisions, all outputs to review queues. Return a practical ordered plan with deterministic validation commands."""
    result=call_or_prompt(prompt, provider=args.provider, model=args.model)
    fallback='''# Multi-Agent Fuzzing Plan\n\n1. Seed Agent proposes SBOM edge cases.\n2. Harness Agent drafts harnesses to review.\n3. Oracle Agent suggests semantic invariants.\n4. Campaign Agent selects local campaign profiles.\n5. Triage Agent summarizes crashes/mismatches.\n6. Report Agent prepares reviewed evidence.\n\nHuman review is required before promotion or disclosure.\n'''
    files={'prompt.md':prompt+'\n','multi-agent-plan.md':(result.get('text') or fallback)+'\n'}
    out=write_artifact('multi-agent-fuzz-loop', files, {'kind':'ai-fuzz-loop','provider':result,'goal':args.goal})
    print(out)
    return 0
if __name__=='__main__': raise SystemExit(main())
