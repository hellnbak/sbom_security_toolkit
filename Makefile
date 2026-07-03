SHELL := /usr/bin/env bash
FUZZ_FINDINGS ?= $(PWD)/fuzzing/findings
TIME_BUDGET ?= 60
TARGET ?=
CRASH ?=
SBOM ?= vuln-scan/cyclonedx-sbom.xml

.PHONY: fuzz-smoke fuzz-nightly fuzz-deep fuzz-python fuzz-js fuzz-php fuzz-repro fuzz-scorecard fuzz-corpus fuzz-differential fuzz-clean validate

fuzz-smoke:
	TIME_BUDGET=60 ./fuzzing/run-all.sh --mode smoke --findings $(FUZZ_FINDINGS)

fuzz-nightly:
	TIME_BUDGET=1800 ./fuzzing/run-all.sh --mode nightly --findings $(FUZZ_FINDINGS)

fuzz-deep:
	TIME_BUDGET=14400 ./fuzzing/run-all.sh --mode deep --findings $(FUZZ_FINDINGS)

fuzz-python:
	docker build -t sbom-fuzzer-python fuzzing/engines/python
	docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-python $(TARGET)

fuzz-js:
	docker build -t sbom-fuzzer-javascript fuzzing/engines/javascript
	docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-javascript $(TARGET)

fuzz-php:
	docker build -t sbom-fuzzer-php fuzzing/engines/php
	docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-php $(TARGET)

fuzz-repro:
	@if [ -z "$(CRASH)" ]; then echo "Usage: make fuzz-repro CRASH=fuzzing/findings/<target>/crash-..."; exit 2; fi
	python3 fuzzing/tools/reproduce-crash.py $(CRASH)

fuzz-scorecard:
	python3 fuzzing/tools/scorecard.py $(FUZZ_FINDINGS) --output fuzzing/reports/fuzz-scorecard.md

fuzz-corpus:
	python3 fuzzing/tools/build-corpus.py $(SBOM) --out fuzzing/generated-corpus

fuzz-differential:
	python3 fuzzing/differential/differential-sbom.py $(SBOM) --out fuzzing/reports/differential-report.json

fuzz-clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
	rm -rf fuzzing/findings fuzzing/crashes fuzzing/reports fuzzing/generated-corpus

validate:
	python3 -m compileall -q .
	find . -name '*.sh' -print0 | xargs -0 -n1 bash -n
	python3 -c "import json,pathlib; [json.load(open(p)) for p in pathlib.Path('.').rglob('*.json') if '/corpus/' not in str(p) and '/malformed/' not in str(p)]; print('json ok')"

.PHONY: sbom-score policy-check supplier-intake vex-template vex-validate vex-merge vex-explain prioritize scanner-compare openssf-scorecard guac-export report release-evidence ui demo

POLICY ?= policies/default-release-policy.yml
VULNS ?=
VEX ?=
CVE ?= CVE-2099-0001
COMPONENT ?= pkg:pypi/example-lib@1.0.0
STATE ?= under_investigation
REPO ?= https://github.com/hellnbak/sbom_security_toolkit
REPORTS ?= reports

sbom-score:
	python3 -m sbomops.score_sbom $(SBOM) --out-dir $(REPORTS)/sbom-quality

policy-check:
	python3 -m sbomops.policy_check $(SBOM) --policy $(POLICY) $(if $(VULNS),--vulns $(VULNS),) --out-dir $(REPORTS)/policy

supplier-intake:
	python3 -m sbomops.supplier_intake $(SBOM) --out-dir $(REPORTS)/supplier-intake

vex-template:
	python3 -m sbomops.vex template --cve $(CVE) --component $(COMPONENT) --state $(STATE) --output vex/generated-vex.cdx.json

vex-validate:
	@if [ -z "$(VEX)" ]; then echo "Usage: make vex-validate VEX=vex/examples/not_affected.cdx.json"; exit 2; fi
	python3 -m sbomops.vex validate $(VEX)

vex-merge:
	@if [ -z "$(VEX)" ]; then echo "Usage: make vex-merge SBOM=bom.cdx.json VEX=vex.cdx.json"; exit 2; fi
	python3 -m sbomops.vex merge --sbom $(SBOM) --vex $(VEX) --output $(REPORTS)/vex/merged-sbom.cdx.json

vex-explain:
	@if [ -z "$(VEX)" ]; then echo "Usage: make vex-explain VEX=vex/examples/not_affected.cdx.json"; exit 2; fi
	python3 -m sbomops.vex explain $(VEX)

prioritize:
	@if [ -z "$(VULNS)" ]; then echo "Usage: make prioritize VULNS=test-sboms/vulnerable/sample-trivy-report.json"; exit 2; fi
	python3 -m sbomops.prioritize $(VULNS) --out-dir $(REPORTS)/prioritization

scanner-compare:
	python3 -m sbomops.scanner_compare $(SBOM) --out-dir $(REPORTS)/scanner-compare

openssf-scorecard:
	python3 -m sbomops.scorecard --repo $(REPO) --out-dir $(REPORTS)/openssf-scorecard

guac-export:
	python3 -m sbomops.guac_export $(SBOM) --out $(REPORTS)/guac/guac-export.json

report:
	python3 -m sbomops.report $(SBOM) $(if $(VULNS),--vulns $(VULNS),) --out-dir $(REPORTS)/bundle

release-evidence:
	SBOM=$(SBOM) POLICY=$(POLICY) OUT=release-evidence ./scripts/release-evidence.sh

ui:
	python3 -m sbomops.ui --reports-dir $(REPORTS) --out $(REPORTS)/ui/index.html

demo:
	$(MAKE) sbom-score SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) policy-check SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) supplier-intake SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
	$(MAKE) prioritize VULNS=test-sboms/vulnerable/sample-trivy-report.json
	$(MAKE) scanner-compare SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) report SBOM=test-sboms/clean/minimal-cyclonedx.json VULNS=test-sboms/vulnerable/sample-trivy-report.json
	$(MAKE) ui
