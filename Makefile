SHELL := /usr/bin/env bash
FUZZ_FINDINGS ?= $(PWD)/fuzzing/findings
TIME_BUDGET ?= 60
TARGET ?=
CRASH ?=
SBOM ?= vuln-scan/cyclonedx-sbom.xml

.PHONY: fuzz-smoke fuzz-nightly fuzz-deep fuzz-python fuzz-js fuzz-php fuzz-repro fuzz-scorecard fuzz-corpus fuzz-differential fuzz-clean fuzz-structured fuzz-roundtrip fuzz-metamorphic fuzz-oracles fuzz-campaign fuzz-api fuzz-coverage fuzz-dedupe-crashes fuzz-regression fuzz-promote-crash fuzz-malicious-metadata validate

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


FUZZ_PROFILE ?= fuzzing/campaigns/sbom-parser-hardening.yml
REGRESSION_CORPUS ?= fuzzing/regression/corpus

fuzz-structured:
	python3 fuzzing/mutators/sbom_json_mutator.py $(SBOM) --out fuzzing/generated-corpus/structured --count $${COUNT:-50}
	python3 fuzzing/mutators/purl_mutator.py --out fuzzing/generated-corpus/purl --count $${COUNT:-100}
	python3 fuzzing/mutators/license_expression_mutator.py --out fuzzing/generated-corpus/licenses --count $${COUNT:-100}

fuzz-roundtrip:
	python3 fuzzing/roundtrip/roundtrip_sbom.py $(SBOM) --out-dir fuzzing/reports/roundtrip

fuzz-metamorphic:
	python3 fuzzing/metamorphic/metamorphic_sbom.py $(SBOM) --out-dir fuzzing/reports/metamorphic

fuzz-oracles:
	python3 fuzzing/oracles/semantic_oracles.py $(SBOM) --out fuzzing/reports/semantic-oracles.json

fuzz-campaign:
	python3 fuzzing/campaigns/run-campaign.py $(FUZZ_PROFILE)

fuzz-api:
	python3 fuzzing/api/dependency_track_api_fuzz.py --dry-run --out fuzzing/reports/dependency-track-api.json

fuzz-coverage:
	python3 fuzzing/coverage/coverage_report.py --out fuzzing/reports/fuzz-coverage.md

fuzz-dedupe-crashes:
	python3 fuzzing/tools/dedupe-crashes.py $(FUZZ_FINDINGS) --out fuzzing/reports/crash-dedupe.json

fuzz-regression:
	python3 fuzzing/regression/run-regression.py --corpus $(REGRESSION_CORPUS) --out fuzzing/reports/regression-report.json

fuzz-promote-crash:
	@if [ -z "$(CRASH)" ]; then echo "Usage: make fuzz-promote-crash CRASH=fuzzing/findings/<target>/crash"; exit 2; fi
	python3 fuzzing/regression/promote-crash.py $(CRASH) --corpus $(REGRESSION_CORPUS)

fuzz-malicious-metadata:
	python3 fuzzing/malicious-metadata/generate_scenarios.py --out fuzzing/generated-corpus/malicious-metadata

fuzz-clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
	rm -rf fuzzing/findings fuzzing/crashes fuzzing/reports fuzzing/generated-corpus

validate:
	python3 -m compileall -q .
	find . -name '*.sh' -print0 | xargs -0 -n1 bash -n
	python3 -c "import json,pathlib; [json.load(open(p)) for p in pathlib.Path('.').rglob('*.json') if '/corpus/' not in str(p) and '/malformed/' not in str(p)]; print('json ok')"


.PHONY: analyze sbom-score sbom-minimum-elements policy-check supplier-intake supplier-questions vex-template vex-validate vex-merge vex-explain prioritize scanner-confidence scanner-compare openssf-scorecard repo-posture guac-export guac-demo report release-evidence ui ui-bundle ui-server ui-clean redact-sbom watch-sbom exploitability-record validate-edr checksums sign-artifacts verify-artifacts ai-fuzz-seeds ai-mutation-plan ai-oracle-suggest ai-crash-triage ai-regression-test ai-fuzz-harness ai-coverage-suggest ai-fuzz-campaign ai-explain-disagreement ai-review-list ai-review-accept ai-review-reject test sst demo-good demo-bad demo-supplier demo-fuzzing demo

POLICY ?= policies/default-release-policy.yml
VULNS ?=
VEX ?=
CVE ?= CVE-2099-0001
COMPONENT ?= pkg:pypi/example-lib@1.0.0
STATE ?= under_investigation
REPO ?= https://github.com/hellnbak/sbom_security_toolkit
REPORTS ?= reports
PROJECT ?= .
EDR ?=
ARTIFACT_DIR ?= dist
FORMAT ?= cyclonedx
SCENARIO ?= dependency-cycles
AI_PROVIDER ?= none
AI_MODEL ?=
GOAL ?= sbom-parser-hardening
COVERAGE ?= fuzzing/reports/fuzz-coverage.md
ITEM ?=

analyze:
	python3 -m sbomops.analyze_project $(PROJECT) --out-dir $(REPORTS)/latest --policy $(POLICY) $(if $(VULNS),--vulns $(VULNS),)

sbom-score:
	python3 -m sbomops.score_sbom $(SBOM) --out-dir $(REPORTS)/sbom-quality

sbom-minimum-elements:
	python3 -m sbomops.minimum_elements $(SBOM) --out-dir $(REPORTS)/minimum-elements

policy-check:
	python3 -m sbomops.policy_check $(SBOM) --policy $(POLICY) $(if $(VULNS),--vulns $(VULNS),) --out-dir $(REPORTS)/policy

supplier-intake:
	python3 -m sbomops.supplier_intake $(SBOM) --out-dir $(REPORTS)/supplier-intake

supplier-questions:
	python3 -m sbomops.supplier_questions $(SBOM) --out-dir $(REPORTS)/supplier-questions

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

scanner-confidence:
	@if [ -z "$(VULNS)" ]; then echo "Usage: make scanner-confidence VULNS=report1.json"; exit 2; fi
	python3 -m sbomops.confidence $(VULNS) --out-dir $(REPORTS)/confidence

scanner-compare:
	python3 -m sbomops.scanner_compare $(SBOM) --out-dir $(REPORTS)/scanner-compare

openssf-scorecard:
	python3 -m sbomops.scorecard --repo $(REPO) --out-dir $(REPORTS)/openssf-scorecard

repo-posture:
	$(MAKE) openssf-scorecard REPO=$(REPO)
	python3 -m sbomops.minimum_elements $(SBOM) --out-dir $(REPORTS)/repo-posture/minimum-elements

guac-export:
	python3 -m sbomops.guac_export $(SBOM) --out $(REPORTS)/guac/guac-export.json

guac-demo:
	integrations/guac/ingest-sbom.sh $(SBOM)

report:
	python3 -m sbomops.report $(SBOM) $(if $(VULNS),--vulns $(VULNS),) --out-dir $(REPORTS)/bundle

release-evidence:
	SBOM=$(SBOM) POLICY=$(POLICY) OUT=release-evidence ./scripts/release-evidence.sh

ui:
	python3 -m sbomops.ui --reports-dir $(REPORTS) --out $(REPORTS)/ui/index.html

ui-bundle:
	python3 -m sbomops.ui_bundle --reports-dir $(REPORTS) --out-dir $(REPORTS)/ui

ui-server:
	python3 -m sbomops.workbench.server --host 127.0.0.1 --port 8080

ui-clean:
	rm -rf ui/storage/jobs/* ui/storage/uploads/*
	touch ui/storage/jobs/.gitkeep ui/storage/uploads/.gitkeep

redact-sbom:
	python3 -m sbomops.redact $(SBOM) --out $(REPORTS)/redacted/redacted-sbom.json --hash-internal-names

watch-sbom:
	python3 -m sbomops.watch $(SBOM) $(if $(VULNS),--vulns $(VULNS),) --out-dir $(REPORTS)/watch

exploitability-record:
	python3 -m sbomops.edr create --cve $(CVE) --component $(COMPONENT) --status $(STATE) --out-dir exploitability-records

validate-edr:
	@if [ -z "$(EDR)" ]; then echo "Usage: make validate-edr EDR=exploitability-records/CVE-...md"; exit 2; fi
	python3 -m sbomops.edr validate $(EDR)

checksums:
	ARTIFACT_DIR=$(ARTIFACT_DIR) scripts/artifact-signing.sh checksums

sign-artifacts:
	ARTIFACT_DIR=$(ARTIFACT_DIR) scripts/artifact-signing.sh sign

verify-artifacts:
	ARTIFACT_DIR=$(ARTIFACT_DIR) scripts/artifact-signing.sh verify

ai-fuzz-seeds:
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) seeds --format $(FORMAT) --scenario $(SCENARIO) --count $${COUNT:-3}

ai-mutation-plan:
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) mutation-plan --sbom $(SBOM)

ai-oracle-suggest:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make ai-oracle-suggest TARGET=sbomops/minimum_elements.py"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) oracle-suggest --target $(TARGET)

ai-crash-triage:
	@if [ -z "$(CRASH)" ]; then echo "Usage: make ai-crash-triage CRASH=fuzzing/findings/<target>/crash"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) crash-triage --crash $(CRASH)

ai-regression-test:
	@if [ -z "$(CRASH)" ]; then echo "Usage: make ai-regression-test CRASH=fuzzing/findings/<target>/crash"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) regression-test --crash $(CRASH)

ai-fuzz-harness:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make ai-fuzz-harness TARGET=sbomops/redact.py"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) harness --target $(TARGET)

ai-coverage-suggest:
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) coverage --coverage $(COVERAGE)

ai-fuzz-campaign:
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) campaign --goal "$(GOAL)"

ai-explain-disagreement:
	@if [ -z "$(REPORT)" ]; then echo "Usage: make ai-explain-disagreement REPORT=reports/scanner-compare/scanner-comparison.json"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_fuzz --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) disagreement --report $(REPORT)

ai-review-list:
	python3 -m ai_fuzz.tools.review_queue list

ai-review-accept:
	@if [ -z "$(ITEM)" ]; then echo "Usage: make ai-review-accept ITEM=<review-folder>"; exit 2; fi
	python3 -m ai_fuzz.tools.review_queue accept $(ITEM)

ai-review-reject:
	@if [ -z "$(ITEM)" ]; then echo "Usage: make ai-review-reject ITEM=<review-folder>"; exit 2; fi
	python3 -m ai_fuzz.tools.review_queue reject $(ITEM)

test:
	python3 -m unittest discover -s tests -v

sst:
	python3 -m sbomops.cli --help

demo-good:
	$(MAKE) analyze PROJECT=. SBOM=test-sboms/clean/minimal-cyclonedx.json

demo-bad:
	$(MAKE) sbom-minimum-elements SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
	$(MAKE) policy-check SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json

demo-supplier:
	$(MAKE) supplier-intake SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
	$(MAKE) supplier-questions SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json

demo-fuzzing:
	$(MAKE) fuzz-structured SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) fuzz-roundtrip SBOM=test-sboms/clean/minimal-cyclonedx.json

demo:
	$(MAKE) sbom-score SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) sbom-minimum-elements SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) policy-check SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) supplier-intake SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
	$(MAKE) supplier-questions SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
	$(MAKE) prioritize VULNS=test-sboms/vulnerable/sample-trivy-report.json
	$(MAKE) scanner-confidence VULNS=test-sboms/vulnerable/sample-trivy-report.json
	$(MAKE) scanner-compare SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) report SBOM=test-sboms/clean/minimal-cyclonedx.json VULNS=test-sboms/vulnerable/sample-trivy-report.json
	$(MAKE) ui
	$(MAKE) ui-bundle
	$(MAKE) fuzz-structured SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) fuzz-roundtrip SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) fuzz-metamorphic SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) fuzz-coverage
	$(MAKE) redact-sbom SBOM=test-sboms/clean/minimal-cyclonedx.json
	$(MAKE) watch-sbom SBOM=test-sboms/clean/minimal-cyclonedx.json VULNS=test-sboms/vulnerable/sample-trivy-report.json

# v1.7 coverage-guided fuzzing lab and SBOM experience improvements
.PHONY: fuzz-generate-cyclonedx fuzz-generate-spdx fuzz-generate-vex fuzz-generate-dtrack-payloads fuzz-afl-cyclonedx fuzz-afl-spdx fuzz-afl-purl fuzz-afl-license fuzz-toolchain fuzz-stateful-dtrack fuzz-metamorphic-scanners fuzz-budget ai-corpus-review ai-harness-repair fuzz-bugclass fuzz-advisory fuzz-status fuzz-conversion fuzz-all-local sbom-normalize sbom-explain sbom-repair sbom-diff sbom-inventory sbom-experience

COUNT ?= 25
EDGE ?= valid-edge
BUGCLASS ?= parser-dos
BUDGET_PROFILE ?= fuzzing/budgets/pr-smoke.yml
OLD_SBOM ?= test-sboms/clean/minimal-cyclonedx.json
NEW_SBOM ?= test-sboms/clean/minimal-cyclonedx.json
DTRACK_URL ?= http://127.0.0.1:8081

fuzz-generate-cyclonedx:
	python3 fuzzing/schema/cyclonedx_schema_generator.py --count $(COUNT) --edge $(EDGE)

fuzz-generate-spdx:
	python3 fuzzing/schema/spdx_schema_generator.py --count $(COUNT) --edge $(EDGE)

fuzz-generate-vex:
	python3 fuzzing/schema/vex_schema_generator.py --count $(COUNT)

fuzz-generate-dtrack-payloads:
	python3 fuzzing/schema/dependency_track_payload_generator.py $(SBOM) --count $(COUNT)

fuzz-afl-cyclonedx:
	TARGET=cyclonedx fuzzing/engines/aflplusplus/run-afl.sh cyclonedx

fuzz-afl-spdx:
	TARGET=spdx fuzzing/engines/aflplusplus/run-afl.sh spdx

fuzz-afl-purl:
	TARGET=purl fuzzing/engines/aflplusplus/run-afl.sh purl

fuzz-afl-license:
	TARGET=license fuzzing/engines/aflplusplus/run-afl.sh license

fuzz-toolchain:
	python3 fuzzing/toolchain/fuzz_toolchain.py $(SBOM)

fuzz-stateful-dtrack:
	python3 fuzzing/stateful/dependency_track_state_machine.py --url $(DTRACK_URL) --sbom $(SBOM) --dry-run

fuzz-metamorphic-scanners:
	python3 fuzzing/scanner-metamorphic/metamorphic_scanners.py $(SBOM)

fuzz-budget:
	python3 fuzzing/budgets/run_budget.py $(BUDGET_PROFILE)

ai-corpus-review:
	python3 ai_fuzz/tools/ai_corpus_review.py --corpus fuzzing/corpus/ai/incoming

ai-harness-repair:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make ai-harness-repair TARGET=fuzzing/engines/python/targets/foo.py LOG=build.log"; exit 2; fi
	python3 ai_fuzz/tools/ai_harness_repair.py --target $(TARGET) $(if $(LOG),--log $(LOG),)

fuzz-bugclass:
	python3 fuzzing/bugclasses/run_bugclass.py --bugclass $(BUGCLASS)

fuzz-advisory:
	@if [ -z "$(CRASH)" ]; then echo "Usage: make fuzz-advisory CRASH=fuzzing/findings/<target>/crash"; exit 2; fi
	python3 fuzzing/advisory/create_advisory.py $(CRASH)

fuzz-status:
	python3 fuzzing/status_report.py

fuzz-conversion:
	python3 fuzzing/conversion/convert_sbom.py $(SBOM) --format cyclonedx-json

fuzz-coverage-collect:
	python3 fuzzing/coverage/collect_coverage.py

fuzz-coverage-compare:
	@if [ -z "$(BASE)" ] || [ -z "$(NEW)" ]; then echo "Usage: make fuzz-coverage-compare BASE=old.json NEW=new.json"; exit 2; fi
	python3 fuzzing/coverage/compare_coverage.py $(BASE) $(NEW)

fuzz-coverage-dashboard:
	python3 fuzzing/coverage/coverage_dashboard.py

fuzz-all-local:
	$(MAKE) fuzz-generate-cyclonedx COUNT=5 EDGE=dependency-cycle
	$(MAKE) fuzz-generate-spdx COUNT=5 EDGE=dependency-cycle
	$(MAKE) fuzz-generate-vex COUNT=5
	$(MAKE) fuzz-structured SBOM=$(SBOM)
	$(MAKE) fuzz-roundtrip SBOM=$(SBOM)
	$(MAKE) fuzz-metamorphic SBOM=$(SBOM)
	$(MAKE) fuzz-oracles SBOM=$(SBOM)
	$(MAKE) fuzz-toolchain SBOM=$(SBOM)
	$(MAKE) fuzz-stateful-dtrack SBOM=$(SBOM)
	$(MAKE) fuzz-metamorphic-scanners SBOM=$(SBOM)
	$(MAKE) fuzz-budget
	$(MAKE) fuzz-status

sbom-normalize:
	python3 -m sbomops.normalize $(SBOM) --out $(REPORTS)/sbom-experience/normalized.json

sbom-explain:
	python3 -m sbomops.explain $(SBOM) --out $(REPORTS)/sbom-experience/explanation.md

sbom-repair:
	python3 -m sbomops.repair $(SBOM) --out $(REPORTS)/sbom-experience/repaired-sbom.json --notes $(REPORTS)/sbom-experience/repair-notes.md

sbom-diff:
	python3 -m sbomops.diff $(OLD_SBOM) $(NEW_SBOM) --out-dir $(REPORTS)/sbom-experience/diff

sbom-inventory:
	python3 -m sbomops.inventory $(SBOM) --out-dir $(REPORTS)/sbom-experience/inventory

sbom-experience:
	$(MAKE) sbom-normalize SBOM=$(SBOM)
	$(MAKE) sbom-explain SBOM=$(SBOM)
	$(MAKE) sbom-repair SBOM=$(SBOM)
	$(MAKE) sbom-inventory SBOM=$(SBOM)
