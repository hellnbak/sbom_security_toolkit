SHELL := /usr/bin/env bash
FUZZ_FINDINGS ?= $(PWD)/fuzzing/findings
TIME_BUDGET ?= 60
TARGET ?=
CRASH ?=
SBOM ?= vuln-scan/cyclonedx-sbom.xml

.PHONY: fuzz-workflow-smoke fuzz-smoke fuzz-nightly fuzz-deep fuzz-python fuzz-js fuzz-php fuzz-repro fuzz-scorecard fuzz-corpus fuzz-differential fuzz-clean fuzz-structured fuzz-roundtrip fuzz-metamorphic fuzz-oracles fuzz-campaign fuzz-api fuzz-coverage fuzz-dedupe-crashes fuzz-regression fuzz-promote-crash fuzz-malicious-metadata validate

fuzz-workflow-smoke:
	SBOM=$(SBOM) XML_SBOM=vuln-scan/cyclonedx-sbom.xml COUNT=$(COUNT) TIME_BUDGET=$(TIME_BUDGET) scripts/smoke-fuzz-workflows.sh

fuzz-smoke:
	TIME_BUDGET=60 ./fuzzing/run-all.sh --mode smoke --findings $(FUZZ_FINDINGS)

fuzz-nightly:
	TIME_BUDGET=1800 ./fuzzing/run-all.sh --mode nightly --findings $(FUZZ_FINDINGS)

fuzz-deep:
	TIME_BUDGET=14400 ./fuzzing/run-all.sh --mode deep --findings $(FUZZ_FINDINGS)

fuzz-python:
	@if ! command -v docker >/dev/null 2>&1; then echo "[skip] Docker not installed; skipping Python engine fuzzing."; else \
		docker build -t sbom-fuzzer-python fuzzing/engines/python && \
		docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-python $(TARGET); \
	fi

fuzz-js:
	@if ! command -v docker >/dev/null 2>&1; then echo "[skip] Docker not installed; skipping JavaScript engine fuzzing."; else \
		docker build -t sbom-fuzzer-javascript fuzzing/engines/javascript && \
		docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-javascript $(TARGET); \
	fi

fuzz-php:
	@if ! command -v docker >/dev/null 2>&1; then echo "[skip] Docker not installed; skipping PHP engine fuzzing."; else \
		docker build -t sbom-fuzzer-php fuzzing/engines/php && \
		docker run --rm -e TIME_BUDGET=$(TIME_BUDGET) -v "$(FUZZ_FINDINGS):/fuzz/findings" sbom-fuzzer-php $(TARGET); \
	fi

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
	python3 fuzzing/mutators/sbom_json_mutator.py $(SBOM) --out fuzzing/generated-corpus/structured --count $(COUNT)
	python3 fuzzing/mutators/purl_mutator.py --out fuzzing/generated-corpus/purl --count $(COUNT)
	python3 fuzzing/mutators/license_expression_mutator.py --out fuzzing/generated-corpus/licenses --count $(COUNT)

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


.PHONY: analyze sbom-score sbom-minimum-elements policy-check supplier-intake supplier-questions vex-template vex-validate vex-merge vex-explain prioritize scanner-confidence scanner-compare openssf-scorecard repo-posture guac-export guac-demo report release-evidence ui ui-bundle ui-server ui-clean redact-sbom watch-sbom exploitability-record validate-edr checksums sign-artifacts verify-artifacts ai-fuzz-seeds ai-mutation-plan ai-oracle-suggest ai-crash-triage ai-regression-test ai-fuzz-harness ai-coverage-suggest ai-fuzz-campaign ai-explain-disagreement ai-review-list ai-review-accept ai-review-reject ai-provider-test ai-fuzz-analysis test sst demo-good demo-bad demo-supplier demo-fuzzing demo

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
AI_ANALYSIS_MODE ?= suggest
AI_MAX_CASES ?= 5
AI_TIME_BUDGET ?= 30
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
	rm -rf ui/storage/jobs ui/storage/uploads ai_fuzz/review/incoming/harness-quality-loop ai_fuzz/review/incoming/generators
	mkdir -p ui/storage/jobs ui/storage/uploads
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

ai-provider-test:
	python3 -m ai_fuzz.tools.provider_test --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),)

ai-fuzz-analysis:
	@if [ -z "$(SBOM)" ]; then echo "Usage: make ai-fuzz-analysis SBOM=./bom.json AI_PROVIDER=bedrock AI_MODEL=<model-id> AI_ANALYSIS_MODE=suggest|generate-run"; exit 2; fi
	python3 -m sbomops.ai_fuzz_analysis $(SBOM) --out-dir reports/ai-assisted-fuzz-analysis --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) --mode $(AI_ANALYSIS_MODE) --max-cases $(AI_MAX_CASES) --time-budget $(AI_TIME_BUDGET)

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
.PHONY: fuzz-generate-cyclonedx fuzz-generate-spdx fuzz-generate-vex fuzz-generate-dtrack-payloads fuzz-afl-cyclonedx fuzz-afl-spdx fuzz-afl-purl fuzz-afl-license fuzz-toolchain fuzz-stateful-dtrack fuzz-metamorphic-scanners fuzz-budget ai-corpus-review ai-harness-repair fuzz-bugclass fuzz-advisory fuzz-status fuzz-conversion fuzz-all-local fuzz-all-timed test-all-components sbom-normalize sbom-explain sbom-repair sbom-diff sbom-inventory sbom-experience

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

fuzz-all-timed:
	@echo "Running local fuzzing workflows with TIME_BUDGET=$(TIME_BUDGET) seconds per step. Use SBOM=... COUNT=... EDGE=... LIBRARY_TARGETS=sbom,scanner,ai or all."
	python3 scripts/run-timed-fuzz-suite.py --sbom $(SBOM) --time-budget $(TIME_BUDGET) --count $(COUNT) --edge $(EDGE) --targets "$(LIBRARY_TARGETS)" --out-dir reports/fuzzing/timed

# Workbench/debug parity target: exercise the broad SBOM component checks without requiring external scanners.
test-all-components:
	python3 scripts/run-timed-fuzz-suite.py --sbom $(SBOM) --time-budget $(TIME_BUDGET) --count $(COUNT) --edge $(EDGE) --targets "sbom" --out-dir reports/fuzzing/test-all-components

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

# v1.8 usability, packaging, release hardening
.PHONY: setup install docker-build docker-ui docker-dtrack docker-guac demo-full coverage preflight-release release version clean-generated
VERSION ?= 2.6.0

setup:
	./setup.sh

install:
	./install.sh

version:
	python3 -m sbomops.cli version

docker-build:
	docker compose -f docker/docker-compose.yml build

docker-ui:
	docker compose -f docker/docker-compose.yml up

docker-dtrack:
	@echo "Set DTRACK_POSTGRES_PASSWORD before running this target."
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dtrack.yml up

docker-guac:
	docker compose -f docker/docker-compose.guac.yml up

demo-full:
	$(MAKE) sbom-score SBOM=test-sboms/demo/good-sbom.json REPORTS=reports/demo
	$(MAKE) sbom-minimum-elements SBOM=test-sboms/demo/good-sbom.json REPORTS=reports/demo
	$(MAKE) policy-check SBOM=test-sboms/demo/good-sbom.json REPORTS=reports/demo
	$(MAKE) supplier-intake SBOM=test-sboms/demo/supplier-sbom-needs-followup.json REPORTS=reports/demo
	$(MAKE) supplier-questions SBOM=test-sboms/demo/supplier-sbom-needs-followup.json REPORTS=reports/demo
	$(MAKE) scanner-confidence VULNS=test-sboms/demo/scanner-disagreement-example.json REPORTS=reports/demo
	$(MAKE) report SBOM=test-sboms/demo/good-sbom.json VULNS=test-sboms/demo/scanner-disagreement-example.json REPORTS=reports/demo
	$(MAKE) sbom-experience SBOM=test-sboms/demo/bad-sbom.json REPORTS=reports/demo
	COUNT=3 $(MAKE) fuzz-structured SBOM=test-sboms/demo/good-sbom.json
	$(MAKE) fuzz-roundtrip SBOM=test-sboms/demo/good-sbom.json
	$(MAKE) release-evidence SBOM=test-sboms/demo/good-sbom.json POLICY=policies/default-release-policy.yml
	mkdir -p reports/demo
	python3 -m sbomops.ui_bundle --reports-dir reports/demo --out-dir reports/demo/ui
	(cd reports && zip -qr demo/evidence-bundle.zip demo || true)
	@echo "Demo bundle generated under reports/demo"

coverage:
	python3 -m coverage run -m unittest discover -s tests
	python3 -m coverage report

preflight-release:
	scripts/preflight-release.sh .

release:
	VERSION=$(VERSION) scripts/release.sh

clean-generated:
	rm -rf reports release-evidence dist fuzzing/findings fuzzing/reports fuzzing/generated-corpus fuzzing/crashes test-sboms/evil-supplier fuzzing/findings_lifecycle/findings.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
	rm -rf ui/storage/jobs ui/storage/uploads ai_fuzz/review/incoming/harness-quality-loop ai_fuzz/review/incoming/generators
	mkdir -p ui/storage/jobs ui/storage/uploads
	touch ui/storage/jobs/.gitkeep ui/storage/uploads/.gitkeep

# v2.0 adaptive fuzzing platform additions
.PHONY: fuzz-kb-init fuzz-kb-summary fuzz-plan ai-harness-loop ai-fuzz-loop fuzz-benchmark fuzz-benchmark-compare sbom-tool-compatibility scanner-truthset fuzz-replay-pack ai-fuzz-eval clusterfuzzlite-smoke
AI_PROVIDERS ?= none,glm
FINDING ?= test-sboms/truthset/log4j-direct.json
BENCH_BASE ?=
BENCH_NEW ?=

fuzz-kb-init:
	python3 fuzzing/kb/fuzz_kb.py init

fuzz-kb-summary:
	python3 fuzzing/kb/fuzz_kb.py summary

fuzz-plan:
	python3 fuzzing/planner/fuzz_plan.py

ai-harness-loop:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make ai-harness-loop TARGET=sbomops/minimum_elements.py AI_PROVIDER=glm"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_harness_loop --target $(TARGET) --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),)

ai-fuzz-loop:
	python3 -m ai_fuzz.tools.ai_fuzz_loop --goal "$(GOAL)" --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),)

fuzz-benchmark:
	python3 fuzzing/benchmarks/run_benchmark.py --sbom $(SBOM)

fuzz-benchmark-compare:
	@if [ -z "$(BENCH_BASE)" ] || [ -z "$(BENCH_NEW)" ]; then echo "Usage: make fuzz-benchmark-compare BENCH_BASE=old.json BENCH_NEW=new.json"; exit 2; fi
	python3 fuzzing/benchmarks/compare_benchmark.py $(BENCH_BASE) $(BENCH_NEW)

sbom-tool-compatibility:
	python3 fuzzing/compatibility/scanner_compatibility.py --corpus test-sboms

scanner-truthset:
	python3 fuzzing/truthset/scanner_truthset.py

fuzz-replay-pack:
	python3 fuzzing/replay/create_replay_pack.py $(FINDING)

ai-fuzz-eval:
	python3 -m ai_fuzz.tools.ai_eval --providers "$(AI_PROVIDERS)"

clusterfuzzlite-smoke:
	mkdir -p /tmp/sst-cfl-out
	OUT=/tmp/sst-cfl-out .fuzz/build.sh
	/tmp/sst-cfl-out/sbom_smoke_fuzzer test-sboms/clean/minimal-cyclonedx.json

# v2.1 intelligent fuzzing operations
.PHONY: fuzz-intelligence fuzz-corpus-recommend fuzz-harness-audit ai-harness-quality-loop ai-seed-generator ai-seed-generator-test fuzz-grammar fuzz-target-coverage fuzz-semantic-format-diff fuzz-vuln-matching fuzz-vex-logic fuzz-evil-supplier ai-fuzz-redteam cflite-import-results fuzz-ci-dashboard fuzz-finding-update fuzz-lab-dashboard
HARNESS ?= fuzzing/engines/python/targets/cyclonedx_json_atheris.py
GENERATOR ?=
GRAMMAR ?= cyclonedx
FORMAT_DIFF_SBOMS ?= test-sboms/clean/minimal-cyclonedx.json test-sboms/clean/minimal-cyclonedx.json
FINDING_ID ?= demo-finding
FINDING_STATE ?= triaged

fuzz-intelligence:
	python3 fuzzing/intelligence/intelligence_score.py --out-dir reports/fuzzing/intelligence

fuzz-corpus-recommend:
	python3 fuzzing/corpus/recommend.py --corpus fuzzing/corpus/ai/incoming --out-dir reports/fuzzing/corpus-recommendations

fuzz-harness-audit:
	python3 fuzzing/harness/audit.py $(HARNESS) --out reports/fuzzing/harness-audit.json

ai-harness-quality-loop:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make ai-harness-quality-loop TARGET=sbomops/minimum_elements.py AI_PROVIDER=glm"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_harness_quality_loop --target $(TARGET) --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),)

ai-seed-generator:
	python3 -m ai_fuzz.tools.ai_seed_generator --goal "$(GOAL)" --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),)

ai-seed-generator-test:
	@if [ -z "$(GENERATOR)" ]; then echo "Usage: make ai-seed-generator-test GENERATOR=ai_fuzz/review/incoming/generators/<name>.py"; exit 2; fi
	python3 -m ai_fuzz.tools.ai_seed_generator_test --generator $(GENERATOR)

fuzz-grammar:
	python3 fuzzing/grammar/run_grammar_mutator.py --grammar $(GRAMMAR) --count $(COUNT) --out fuzzing/generated-corpus/grammar/$(GRAMMAR)

fuzz-target-coverage:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make fuzz-target-coverage TARGET=sbomops.minimum_elements:main"; exit 2; fi
	python3 fuzzing/coverage/target_coverage.py --target $(TARGET) --out reports/fuzzing/target-coverage.json

fuzz-semantic-format-diff:
	python3 fuzzing/semantic_format_diff/semantic_format_diff.py $(FORMAT_DIFF_SBOMS) --out reports/fuzzing/semantic-format-diff.json

fuzz-vuln-matching:
	python3 fuzzing/vuln_matching/vuln_matching_fuzz.py --out-dir fuzzing/generated-corpus/vuln-matching

fuzz-vex-logic:
	python3 fuzzing/vex_logic/vex_logic_fuzz.py --out-dir fuzzing/generated-corpus/vex-logic

fuzz-evil-supplier:
	python3 fuzzing/evil_supplier/evil_supplier.py --out-dir test-sboms/evil-supplier

ai-fuzz-redteam:
	python3 -m ai_fuzz.tools.ai_redteam --provider $(AI_PROVIDER) $(if $(AI_MODEL),--model $(AI_MODEL),) --out reports/ai-fuzz-redteam.json

cflite-import-results:
	python3 fuzzing/clusterfuzzlite/import_results.py --input-dir fuzzing/clusterfuzzlite/results --out reports/fuzzing/clusterfuzzlite-results.json

fuzz-ci-dashboard:
	python3 fuzzing/clusterfuzzlite/ci_dashboard.py --results reports/fuzzing/clusterfuzzlite-results.json --out reports/fuzzing/ci-dashboard.html

fuzz-finding-update:
	python3 fuzzing/findings_lifecycle/lifecycle.py --finding $(FINDING_ID) --state $(FINDING_STATE) --notes "$(NOTES)"

fuzz-lab-dashboard:
	python3 fuzzing/visualize/fuzzing_lab_dashboard.py --out reports/fuzzing/lab-dashboard.html

# Repository intake and SBOM build pipeline
REPO_SOURCE ?= .
REPO_OUT ?= reports/repo-intake
REPO_GENERATORS ?= auto
GITHUB_TOKEN_ENV ?= GITHUB_TOKEN
ALLOW_REMOTE ?= 0

.PHONY: repo-intake repo-sbom repo-scan repo-fuzz repo-evidence repo-detect dependency-health lifecycle-intelligence repo-dependency-health

dependency-health:
	@if [ -z "$(SBOM)" ]; then echo "Usage: make dependency-health SBOM=./bom.json [NETWORK=1] [STALE_DAYS=365]"; exit 2; fi
	python3 -m sbomops.dependency_health $(SBOM) --out-dir reports/dependency-health --stale-days $${STALE_DAYS:-365} --lifecycle-sources $${LIFECYCLE_SOURCES:-sbom,known,registry,endoflife} $(if $(LIFECYCLE_CACHE),--lifecycle-cache $(LIFECYCLE_CACHE),) $(if $(filter 1,$(OFFLINE_CACHE_ONLY)),--offline-cache-only,) $(if $(filter 1,$(NETWORK)),--network,)

repo-detect:
	python3 -m sbomops.repo_intake detect $(REPO_SOURCE) --out $(REPO_OUT)/detected-ecosystems.json $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

repo-sbom:
	python3 -m sbomops.repo_intake analyze $(REPO_SOURCE) --out-dir $(REPO_OUT) --generators $(REPO_GENERATORS) --policy $(POLICY) --no-scan $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

repo-scan:
	python3 -m sbomops.repo_intake analyze $(REPO_SOURCE) --out-dir $(REPO_OUT) --generators $(REPO_GENERATORS) --policy $(POLICY) $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

repo-fuzz:
	python3 -m sbomops.repo_intake analyze $(REPO_SOURCE) --out-dir $(REPO_OUT) --generators $(REPO_GENERATORS) --policy $(POLICY) --fuzz $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

repo-evidence repo-intake:
	python3 -m sbomops.repo_intake analyze $(REPO_SOURCE) --out-dir $(REPO_OUT) --generators $(REPO_GENERATORS) --policy $(POLICY) --fuzz $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

# v2.7.2 lifecycle intelligence convenience target
lifecycle-intelligence:
	@if [ -z "$(SBOM)" ]; then echo "Usage: make lifecycle-intelligence SBOM=./bom.json [NETWORK=1] [LIFECYCLE_SOURCES=sbom,known,registry,endoflife]"; exit 2; fi
	python3 -m sbomops.dependency_health $(SBOM) --out-dir reports/lifecycle-intelligence --stale-days $${STALE_DAYS:-365} --lifecycle-sources $${LIFECYCLE_SOURCES:-sbom,known,registry,endoflife} $(if $(LIFECYCLE_CACHE),--lifecycle-cache $(LIFECYCLE_CACHE),) $(if $(filter 1,$(OFFLINE_CACHE_ONLY)),--offline-cache-only,) $(if $(filter 1,$(NETWORK)),--network,)

repo-dependency-health:
	python3 -m sbomops.repo_intake analyze $(REPO_SOURCE) --out-dir $(REPO_OUT) --generators $(REPO_GENERATORS) --policy $(POLICY) --no-scan --dependency-health --lifecycle-sources $${LIFECYCLE_SOURCES:-sbom,known,registry,endoflife} $(if $(LIFECYCLE_CACHE),--lifecycle-cache $(LIFECYCLE_CACHE),) $(if $(filter 1,$(OFFLINE_CACHE_ONLY)),--offline-cache-only,) $(if $(filter 1,$(NETWORK)),--network,) $(if $(filter 1,$(ALLOW_REMOTE)),--allow-remote,) --github-token-env $(GITHUB_TOKEN_ENV)

# v2.3 project risk dashboard and full all-actions scan workflows
.PHONY: project-init project-list project-record project-delta project-trend release-decision ci-generate policy-tune owners-template ai-executive-summary evidence-index project-watch
PROJECT_ID ?= demo-project
RUN_DIR ?= reports/latest
EVIDENCE_DIR ?= reports/latest
CI_OUT ?= .github/workflows/sbom-security-toolkit.yml
OWNERS_OUT ?= owners.yml

project-init:
	python3 -m sbomops.project_ops init $(PROJECT_ID) --source "$(REPO_SOURCE)" --policy $(POLICY) --ai-provider $(AI_PROVIDER) --fuzz-profile "$(LIBRARY_TARGETS)"

project-list:
	python3 -m sbomops.project_ops list

project-record:
	python3 -m sbomops.project_ops record $(PROJECT_ID) --sbom $(SBOM) --run-dir $(RUN_DIR) --note "$(NOTE)"

project-delta:
	python3 -m sbomops.project_ops delta $(PROJECT_ID) --out-dir $(REPORTS)/project-delta

project-trend:
	python3 -m sbomops.project_ops trend $(PROJECT_ID) --out-dir $(REPORTS)/project-trend

release-decision:
	python3 -m sbomops.project_ops release-decision --sbom $(SBOM) --out-dir $(REPORTS)/release-decision

ci-generate:
	python3 -m sbomops.project_ops ci-generate --out $(CI_OUT)

policy-tune:
	python3 -m sbomops.project_ops policy-tune --out policies/generated/generated-release-policy.yml --stale-days $(STALE_DAYS)

owners-template:
	python3 -m sbomops.project_ops owners-template --out $(OWNERS_OUT)

ai-executive-summary:
	python3 -m sbomops.project_ops ai-summary --input-dir $(EVIDENCE_DIR) --out-dir $(REPORTS)/ai-executive-summary

evidence-index:
	python3 -m sbomops.project_ops evidence-index $(EVIDENCE_DIR) --out-dir $(REPORTS)/evidence-viewer

project-watch:
	@echo "Add this cron entry locally if desired:"; echo "0 6 * * * cd $(PWD) && make repo-intake REPO_SOURCE=$(REPO_SOURCE) REPORTS=reports/watch/$$(date +\%Y\%m\%d)"

# v2.3 cloud-capable self-hosted mode additions
.PHONY: cloud-config cloud-doctor cloud-schedule-template cloud-compose-up cloud-compose-down cloud-worker-smoke
CLOUD_CONFIG ?= cloud/sst-cloud-config.json
CLOUD_SCHEDULE ?= cloud/run-scheduled-scan.sh

cloud-config:
	python3 -m sbomops.cloud init-config --output $(CLOUD_CONFIG)

cloud-doctor:
	python3 -m sbomops.cloud doctor --out reports/cloud-doctor.json

cloud-schedule-template:
	python3 -m sbomops.cloud schedule-template --output $(CLOUD_SCHEDULE)

cloud-compose-up:
	docker compose -f docker/docker-compose.cloud.yml up --build

cloud-compose-down:
	docker compose -f docker/docker-compose.cloud.yml down

cloud-worker-smoke:
	python3 -m sbomops.cloud worker

.PHONY: config-list config-validate config-policy config-ai-provider config-fuzzing-profile config-project-defaults config-cloud-settings
CONFIG_PATH ?=
CONFIG_NAME ?= gui-policy
CONFIG_PROVIDER ?= bedrock
CONFIG_MODEL ?=
CONFIG_REGION ?= us-east-1
CONFIG_TARGETS ?= sbom,scanner,ai
CONFIG_DURATION ?= 60
CONFIG_PROJECT_ID ?= default-project
CONFIG_STORAGE_BACKEND ?= local
CONFIG_S3_BUCKET ?=

config-list:
	python3 -m sbomops.config_manager list

config-validate:
	@if [ -z "$(CONFIG_PATH)" ]; then echo "Usage: make config-validate CONFIG_PATH=policies/generated/gui-policy.yml"; exit 2; fi
	python3 -m sbomops.config_manager validate $(CONFIG_PATH)

config-policy:
	python3 -m sbomops.config_manager policy --name $(CONFIG_NAME) --fail-on-critical --fail-on-cisa-kev --fail-on-unsupported --require-version --stale-days $(STALE_DAYS)

config-ai-provider:
	python3 -m sbomops.config_manager ai-provider --name $(CONFIG_NAME) --provider $(CONFIG_PROVIDER) --model "$(CONFIG_MODEL)" --region $(CONFIG_REGION)

config-fuzzing-profile:
	python3 -m sbomops.config_manager fuzzing-profile --name $(CONFIG_NAME) --targets "$(CONFIG_TARGETS)" --duration $(CONFIG_DURATION)

config-project-defaults:
	python3 -m sbomops.config_manager project-defaults --project-id $(CONFIG_PROJECT_ID)

config-cloud-settings:
	python3 -m sbomops.config_manager cloud-settings --name $(CONFIG_NAME) --storage-backend $(CONFIG_STORAGE_BACKEND) --s3-bucket "$(CONFIG_S3_BUCKET)" --worker-sbom --worker-vulnerability --worker-fuzzing --worker-ai --worker-report

# v2.4 enterprise cloud hardening helpers
.PHONY: enterprise-health enterprise-setup enterprise-list enterprise-audit-list enterprise-schedule enterprise-notification enterprise-secret-ref enterprise-api-token

enterprise-health:
	python3 -m sbomops.enterprise health

enterprise-setup:
	python3 -m sbomops.enterprise setup-wizard --admin-username $(or $(ADMIN_USER),admin) --project-id $(or $(PROJECT_ID),default-project)

enterprise-list:
	python3 -m sbomops.enterprise list

enterprise-audit-list:
	python3 -m sbomops.enterprise audit-list --limit $(or $(LIMIT),25)

enterprise-schedule:
	python3 -m sbomops.enterprise schedule --name $(or $(SCHEDULE_NAME),nightly-full-scan) --project-id $(or $(PROJECT_ID),default-project) --workflow $(or $(WORKFLOW),analyze-everything) --cadence $(or $(CADENCE),daily)

enterprise-notification:
	python3 -m sbomops.enterprise notification --name $(or $(NOTIFICATION_NAME),security-alerts) --type $(or $(NOTIFICATION_TYPE),webhook) --target-ref $(or $(TARGET_REF),SST_WEBHOOK_URL)

enterprise-secret-ref:
	python3 -m sbomops.enterprise secret-ref --name $(or $(SECRET_NAME),github-token) --provider $(or $(SECRET_PROVIDER),env) --reference $(or $(SECRET_REFERENCE),GITHUB_TOKEN) --purpose "$(or $(SECRET_PURPOSE),private repository access)"

enterprise-api-token:
	python3 -m sbomops.enterprise api-token --name $(or $(TOKEN_NAME),ci-service-account) --owner $(or $(TOKEN_OWNER),ci) --role $(or $(TOKEN_ROLE),service-account)

# v2.5 production integrations and deployment readiness
.PHONY: export-sarif export-openvex export-jira export-defectdojo ci-templates github-app-scaffold k8s-generate oidc-config worker-limits notify-test demo-enterprise
SARIF_OUT ?= reports/sarif/sbom-security-toolkit.sarif
OPENVEX_OUT ?= reports/openvex/openvex.json
CI_PROVIDER ?= all
CI_TEMPLATE_DIR ?= reports/ci-templates
JIRA_PROJECT_KEY ?= SEC

export-sarif:
	python3 -m sbomops.integrations sarif --sbom $(SBOM) --out $(SARIF_OUT) --project $(PROJECT_ID)

export-openvex:
	python3 -m sbomops.integrations openvex --sbom $(SBOM) --out $(OPENVEX_OUT) --status $(or $(VEX_STATUS),under_investigation)

export-jira:
	python3 -m sbomops.integrations jira-export --sbom $(SBOM) --project-key $(JIRA_PROJECT_KEY)

export-defectdojo:
	python3 -m sbomops.integrations defectdojo-export --sbom $(SBOM)

ci-templates:
	python3 -m sbomops.integrations ci-generate --provider $(CI_PROVIDER) --out-dir $(CI_TEMPLATE_DIR)

github-app-scaffold:
	python3 -m sbomops.integrations github-app-scaffold

k8s-generate:
	python3 -m sbomops.integrations k8s-generate --out-dir deploy/kubernetes

oidc-config:
	python3 -m sbomops.integrations oidc-config --issuer $(or $(OIDC_ISSUER),https://issuer.example.com) --allowed-domains "$(or $(OIDC_ALLOWED_DOMAINS),example.com)"

worker-limits:
	python3 -m sbomops.integrations worker-limits

notify-test:
	python3 -m sbomops.integrations notify --type $(or $(NOTIFICATION_TYPE),webhook) --target-ref $(or $(TARGET_REF),SST_WEBHOOK_URL) --title "SBOM Security Toolkit test" --message "Notification configuration test"

demo-enterprise:
	python3 -m sbomops.integrations demo-enterprise --out-dir reports/demo-enterprise

# v2.6 live integrations and operational workflows
.PHONY: jira-test jira-create defectdojo-test defectdojo-upload github-pr-summary scheduler-run jobs-list job-cancel job-retry job-rerun evidence-cleanup integration-smoke
JIRA_TOKEN_ENV ?= JIRA_API_TOKEN
DEFECTDOJO_TOKEN_ENV ?= DEFECTDOJO_TOKEN
JOBS_DIR ?= ui/storage/jobs
RETENTION_DAYS ?= 90

jira-test:
	python3 -m sbomops.integrations jira-test --token-env $(JIRA_TOKEN_ENV) $(if $(SEND),--send,)

jira-create:
	python3 -m sbomops.integrations jira-create --sbom $(SBOM) --project-key $(JIRA_PROJECT_KEY) --token-env $(JIRA_TOKEN_ENV) $(if $(SEND),--send,)

defectdojo-test:
	python3 -m sbomops.integrations defectdojo-test --token-env $(DEFECTDOJO_TOKEN_ENV) $(if $(SEND),--send,)

defectdojo-upload:
	python3 -m sbomops.integrations defectdojo-upload --sbom $(SBOM) --token-env $(DEFECTDOJO_TOKEN_ENV) $(if $(SEND),--send,)

github-pr-summary:
	python3 -m sbomops.integrations github-pr-summary --sarif $(SARIF_OUT) $(if $(RELEASE_DECISION),--release-decision $(RELEASE_DECISION),)

scheduler-run:
	python3 -m sbomops.integrations scheduler-run --once $(if $(EXECUTE),--execute,--dry-run)

jobs-list:
	python3 -m sbomops.integrations jobs list --jobs-dir $(JOBS_DIR)

job-cancel:
	python3 -m sbomops.integrations jobs cancel --jobs-dir $(JOBS_DIR) --job-id $(JOB_ID)

job-retry:
	python3 -m sbomops.integrations jobs retry --jobs-dir $(JOBS_DIR) --job-id $(JOB_ID)

job-rerun:
	python3 -m sbomops.integrations jobs rerun --jobs-dir $(JOBS_DIR) --job-id $(JOB_ID) $(if $(NEW_JOB_ID),--new-job-id $(NEW_JOB_ID),)

evidence-cleanup:
	python3 -m sbomops.integrations evidence-cleanup --retention-days $(RETENTION_DAYS) $(if $(DELETE),--delete,--dry-run)

integration-smoke:
	python3 -m sbomops.integrations integration-smoke --sbom $(SBOM)

# v2.7 findings and remediation operations
.PHONY: findings-import findings-list findings-dashboard findings-sla findings-remediation findings-ticket findings-assign findings-accept findings-suppress findings-verify findings-next-actions findings-export findings-smoke remediation-smoke
FINDINGS_PROJECT ?= default-project
FINDING_ID ?=
FINDING_OWNER ?= platform-security
FINDING_STATUS ?= triaged
FINDING_REASON ?= Remediation is temporarily deferred with documented owner review.
FINDING_EXPIRES_AT ?= 2026-12-31
FINDINGS_OUT_DIR ?= reports/findings
FIXED_VERSION ?=

findings-import:
	python3 -m sbomops.findings import-sbom --sbom $(SBOM) --project $(FINDINGS_PROJECT) --owner $(FINDING_OWNER)

findings-list:
	python3 -m sbomops.findings list --project $(FINDINGS_PROJECT) --limit $(or $(LIMIT),50)

findings-dashboard:
	python3 -m sbomops.findings dashboard --project $(FINDINGS_PROJECT)

findings-sla:
	python3 -m sbomops.findings sla --project $(FINDINGS_PROJECT)

findings-remediation:
	python3 -m sbomops.findings remediation-plan --project $(FINDINGS_PROJECT) $(if $(FINDING_ID),--finding-id $(FINDING_ID),) $(if $(FIXED_VERSION),--fixed-version $(FIXED_VERSION),)

findings-ticket:
	python3 -m sbomops.findings ticket --finding-id $(FINDING_ID) $(if $(FIXED_VERSION),--fixed-version $(FIXED_VERSION),)

findings-assign:
	python3 -m sbomops.findings assign --finding-id $(FINDING_ID) --owner $(FINDING_OWNER)

findings-accept:
	python3 -m sbomops.findings accept --finding-id $(FINDING_ID) --reason "$(FINDING_REASON)" --owner $(FINDING_OWNER) --expires-at $(FINDING_EXPIRES_AT)

findings-suppress:
	python3 -m sbomops.findings suppress --finding-id $(FINDING_ID) --reason "$(FINDING_REASON)" --owner $(FINDING_OWNER) --expires-at $(FINDING_EXPIRES_AT)

findings-verify:
	python3 -m sbomops.findings verify --project $(FINDINGS_PROJECT) $(if $(SBOM),--sbom $(SBOM),)

findings-next-actions:
	python3 -m sbomops.findings next-actions --project $(FINDINGS_PROJECT) --limit $(or $(LIMIT),10)

findings-export:
	python3 -m sbomops.findings export --project $(FINDINGS_PROJECT) --out-dir $(FINDINGS_OUT_DIR)

findings-smoke remediation-smoke:
	python3 -m sbomops.findings smoke --sbom $(or $(SBOM),test-sboms/example-spdx-2.3.json) --project $(FINDINGS_PROJECT)

# v2.7.1 report viewer
.PHONY: reports-index reports-view
REPORT_ID ?=
reports-index:
	python3 -m sbomops.reports_viewer index

reports-view:
	@if [ -z "$(REPORT_ID)" ]; then echo "Usage: make reports-view REPORT_ID=reports/report-index.md"; exit 2; fi
	python3 -m sbomops.reports_viewer view "$(REPORT_ID)"

# v2.7.3 AI report writer
.PHONY: ai-report ai-report-facts ai-report-templates ai-report-smoke
AI_REPORT_TYPE ?= full
AI_REPORT_AUDIENCE ?= security
AI_REPORT_TONE ?= action-oriented
AI_REPORT_PROVIDER ?= none
AI_REPORT_MODEL ?=
AI_REPORT_OUT_DIR ?= reports/ai
AI_REPORT_PROJECT ?=
AI_REPORT_EVIDENCE_ROOTS ?=

ai-report:
	python3 -m sbomops.ai_report_writer generate $(if $(SBOM),--sbom $(SBOM),) --project "$(AI_REPORT_PROJECT)" --report-type $(AI_REPORT_TYPE) --audience $(AI_REPORT_AUDIENCE) --tone $(AI_REPORT_TONE) --provider $(AI_REPORT_PROVIDER) $(if $(AI_REPORT_MODEL),--model $(AI_REPORT_MODEL),) --out-dir $(AI_REPORT_OUT_DIR) $(if $(AI_REPORT_EVIDENCE_ROOTS),--evidence-roots $(AI_REPORT_EVIDENCE_ROOTS),)

ai-report-facts:
	python3 -m sbomops.ai_report_writer facts $(if $(SBOM),--sbom $(SBOM),) --project "$(AI_REPORT_PROJECT)" --out-dir $(AI_REPORT_OUT_DIR) $(if $(AI_REPORT_EVIDENCE_ROOTS),--evidence-roots $(AI_REPORT_EVIDENCE_ROOTS),)

ai-report-templates:
	python3 -m sbomops.ai_report_writer templates

ai-report-smoke:
	python3 -m sbomops.ai_report_writer smoke --sbom $(or $(SBOM),test-sboms/example-spdx-2.3.json) --out-dir reports/ai-smoke
