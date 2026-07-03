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
	python3 -c "import json,pathlib; [json.load(open(p)) for p in pathlib.Path('.').rglob('*.json') if '/corpus/' not in str(p)]; print('json ok')"
