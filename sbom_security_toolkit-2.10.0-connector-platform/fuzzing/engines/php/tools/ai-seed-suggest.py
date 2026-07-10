#!/usr/bin/env python3
"""Ask a local Ollama model for candidate SBOM fuzzing seeds; human review required."""
from __future__ import annotations
import argparse, json, re, urllib.request
from pathlib import Path

def ollama_generate(model: str, prompt: str) -> str:
    data = json.dumps({'model': model, 'prompt': prompt, 'stream': False}).encode()
    req = urllib.request.Request('http://localhost:11434/api/generate', data=data, headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode()).get('response','')

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument('--target', default='CycloneDX JSON'); ap.add_argument('--count', type=int, default=10); ap.add_argument('--model', default='qwen2.5-coder:7b'); ap.add_argument('--out', default='fuzzing/generated-corpus/ai-reviewed-needed'); args = ap.parse_args()
    prompt = f'''Generate {args.count} malformed but plausible fuzzing seed inputs for {args.target} parsers.
Focus on deep dependency graphs, invalid package URLs, extreme version strings, malformed SPDX license expressions, unicode package names, null bytes, and missing required fields.
Output ONLY blocks delimited by <<<SEED>>> and <<<END>>>. No explanation.'''
    response = ollama_generate(args.model, prompt); out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    seeds = re.findall(r'<<<SEED>>>(.*?)<<<END>>>', response, flags=re.S)
    for i, seed in enumerate(seeds, 1): (out / f'ai-seed-{i:03d}.seed').write_text(seed.strip() + '\n')
    print(f'wrote {len(seeds)} unreviewed AI seed candidates to {out}')
    print('Review before promoting them into a committed corpus.')
    return 0
if __name__ == '__main__': raise SystemExit(main())
