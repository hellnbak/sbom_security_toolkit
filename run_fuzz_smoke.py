import subprocess, os, time, json
cmds = [
 ('fuzz-structured-json', 'COUNT=2 make fuzz-structured SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-structured-xml', 'COUNT=2 make fuzz-structured SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-roundtrip-json', 'make fuzz-roundtrip SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-roundtrip-xml', 'make fuzz-roundtrip SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-metamorphic-json', 'make fuzz-metamorphic SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-metamorphic-xml', 'make fuzz-metamorphic SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-oracles-json', 'make fuzz-oracles SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-oracles-xml', 'make fuzz-oracles SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-generate-cyclonedx', 'make fuzz-generate-cyclonedx COUNT=2'),
 ('fuzz-generate-spdx', 'make fuzz-generate-spdx COUNT=2'),
 ('fuzz-generate-vex', 'make fuzz-generate-vex COUNT=2'),
 ('fuzz-generate-dtrack-payloads-json', 'make fuzz-generate-dtrack-payloads COUNT=2 SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-generate-dtrack-payloads-xml', 'make fuzz-generate-dtrack-payloads COUNT=2 SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-toolchain-json', 'make fuzz-toolchain SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-toolchain-xml', 'make fuzz-toolchain SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-stateful-dtrack-json', 'make fuzz-stateful-dtrack SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-stateful-dtrack-xml', 'make fuzz-stateful-dtrack SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-metamorphic-scanners-json', 'make fuzz-metamorphic-scanners SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-metamorphic-scanners-xml', 'make fuzz-metamorphic-scanners SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-budget', 'make fuzz-budget'),
 ('fuzz-status', 'make fuzz-status'),
 ('fuzz-conversion-json', 'make fuzz-conversion SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('fuzz-conversion-xml', 'make fuzz-conversion SBOM=vuln-scan/cyclonedx-sbom.xml'),
 ('fuzz-kb-init', 'make fuzz-kb-init'),
 ('fuzz-kb-summary', 'make fuzz-kb-summary'),
 ('fuzz-plan', 'make fuzz-plan'),
 ('fuzz-benchmark-json', 'make fuzz-benchmark SBOM=test-sboms/clean/minimal-cyclonedx.json'),
 ('sbom-tool-compatibility', 'make sbom-tool-compatibility'),
 ('scanner-truthset', 'make scanner-truthset'),
 ('ai-fuzz-eval', 'make ai-fuzz-eval AI_PROVIDERS=none'),
 ('fuzz-intelligence', 'make fuzz-intelligence'),
 ('fuzz-corpus-recommend', 'make fuzz-corpus-recommend'),
 ('fuzz-harness-audit', 'make fuzz-harness-audit'),
 ('fuzz-grammar', 'make fuzz-grammar GRAMMAR=cyclonedx COUNT=2'),
 ('fuzz-semantic-format-diff', 'make fuzz-semantic-format-diff'),
 ('fuzz-vuln-matching', 'make fuzz-vuln-matching'),
 ('fuzz-vex-logic', 'make fuzz-vex-logic'),
 ('fuzz-evil-supplier', 'make fuzz-evil-supplier'),
 ('ai-fuzz-redteam', 'make ai-fuzz-redteam AI_PROVIDER=none'),
 ('cflite-import-results', 'make cflite-import-results'),
 ('fuzz-ci-dashboard', 'make fuzz-ci-dashboard'),
 ('fuzz-finding-update', 'make fuzz-finding-update FINDING_ID=demo FINDING_STATE=triaged'),
 ('fuzz-lab-dashboard', 'make fuzz-lab-dashboard'),
]
res=[]
for name, cmd in cmds:
    t=time.time()
    p=subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    out=p.stdout[-3000:]
    res.append({'name':name,'cmd':cmd,'rc':p.returncode,'sec':round(time.time()-t,2),'out':out})
    print('---', name, p.returncode)
    if p.returncode: print(out)
json.dump(res, open('/mnt/data/fuzz_smoke_results.json','w'), indent=2)
print('wrote /mnt/data/fuzz_smoke_results.json')
