# SBOM Security Toolkit

Two source-available workflows for analyzing CycloneDX/SPDX SBOMs and then fuzzing the parser/input-handling libraries they expose:

1. **`vuln-scan/`** — find *known* vulnerabilities (CVEs/advisories) in the libraries you already ship.
2. **`fuzzing/`** — hunt for *unknown* bugs by fuzzing the parser/input-handling libraries with coverage-guided fuzzing.

This toolkit is released under the Functional Source License 1.1, ALv2 Future License (`FSL-1.1-ALv2`). It wraps well-known third-party OSS tools. The scan and fuzz stages can run locally; optional AI-assisted triage/target generation uses Claude/Claude Code only when you configure those features.

## The quick path: `orchestrate.sh`

```bash
./orchestrate.sh path/to/any-sbom
```

Feed it any SBOM (CycloneDX XML/JSON or SPDX JSON, any tool that produced it, any spec version) and it runs the pipeline: scan it (Stage 1), have Claude triage the results (Stage 2, if `ANTHROPIC_API_KEY` is set), hand the component list to Claude Code to pick what's worth fuzzing and write new harnesses for it (Stage 3, if `claude` is on PATH), then fuzz everything that exists (Stage 4, if Docker is available). Each stage degrades gracefully and says so if its dependency is missing, rather than failing the whole run. Output lands in `runs/<timestamp>/`, ending in one `SUMMARY.md`.

**Multi-ecosystem support:** Stage 1 (vuln scanning) is genuinely ecosystem-agnostic — OSV-Scanner and Trivy work across all languages. Stage 3/4 (fuzzing) now supports **PHP (php-fuzzer), JavaScript/TypeScript (Jazzer.js), and Python (Atheris)** with engines ready to use. Java, Go, and Rust templates exist but need testing. When you run `orchestrate.sh`, it detects which ecosystems are in your SBOM and automatically runs the appropriate fuzzing engines. Ecosystems without engines still get scanned for CVEs; they just skip fuzzing with a clear message.

"Takes over" here means the deterministic and delegate-able steps run unattended — it does not mean nothing needs a human afterward. `SUMMARY.md` ends with an explicit "still needs a human" list every run: generated targets to read before trusting, P0/P1 triage calls to confirm against real code, any crash to actually go minimize and judge. See `--auto`, `--budget`, `--skip-new-targets`, `--skip-fuzz` in the script header for the available flags — `--auto` unattends Claude Code's permission prompts too (`--dangerously-skip-permissions`), which is fine in CI and not something to reach for on a dev machine by default.

---

## 1. Known-vulnerability analysis (`vuln-scan/`)

```bash
cd vuln-scan
chmod +x scan.sh
./scan.sh                       # uses ./cyclonedx-sbom.xml, writes reports/<timestamp>/
```

- **OSV-Scanner** (Google) and **Trivy** (Aqua) run independently against the SBOM and cross-check each other. Different advisory sources → fewer missed CVEs.
- Both read CycloneDX directly, so no PHP toolchain is needed — but **internet access is required** the first time (they download advisory databases).
- Outputs: human-readable tables, plus JSON/SARIF/CycloneDX-VEX for CI and GitHub code scanning.

**Continuous monitoring (recommended):** `docker compose up -d` brings up **OWASP Dependency-Track** (backed by Postgres — see `docker-compose.yml`). Upload the SBOM once via the UI, or run `./upload-to-dependency-track.sh` to do it via API, and it re-evaluates as new CVEs are published — so a flaw disclosed next month against a version you currently ship alerts you automatically.

**`triage-2026-06.md`** is a preliminary manual triage I did from public advisories. It already flags likely hits on `laravel/framework 11.35.0` (debug-page XSS, file-validation bypass) and several `symfony/* 7.2.x` components (May–June 2026 advisories). **Treat it as a starting point — `scan.sh` is the authoritative list.** I matched version ranges by hand, which is error-prone across 91 packages.

---

## 2. Fuzzing apparatus (`fuzzing/`)

Coverage-guided fuzzing for **PHP, JavaScript/TypeScript, and Python** libraries extracted from your SBOM. Each ecosystem uses its best-in-class open-source fuzzer:

- **PHP:** [nikic/PHP-Fuzzer](https://github.com/nikic/PHP-Fuzzer) — libFuzzer-style with AST instrumentation
- **JavaScript/TypeScript:** [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) — V8 native coverage
- **Python:** [Atheris](https://github.com/google/atheris) — libFuzzer for Python via C API

All engines are containerized and follow a common interface. See `fuzzing/README-ENGINES.md` for full documentation.

Targets are pinned to your **exact SBOM versions** (see `composer.json`) so you fuzz what you actually deploy:

| Target | Library (SBOM version) | Why it's a good fuzz target |
|---|---|---|
| `commonmark`       | league/commonmark 2.6.0      | Markdown parser; attacker-controlled text in many apps |
| `php_parser`       | nikic/php-parser 5.3.1       | Full PHP-grammar parser (the classic case) |
| `psr7_uri`         | guzzlehttp/psr7 2.7.0        | URI parse/serialize; feeds routing & SSRF defenses |
| `psr7_message`     | guzzlehttp/psr7 2.7.0        | Raw HTTP message parse/serialize — the exact surface behind CVE-2026-48998/49214/55766, see below |
| `league_uri`       | league/uri 7.5.1             | Second URI parser → differential bugs vs. PSR-7 |
| `symfony_yaml`     | symfony/yaml 7.2.0           | YAML parser; historic DoS / type-confusion bugs, corpus now seeded to probe three confirmed 2026 CVEs, see below |
| `email_validator`  | egulias/email-validator 4.0.2| RFC email lexer behind your mailer |
| `brick_math`       | brick/math 0.12.1            | Numeric-string parsing + bignum arithmetic |

> **Building this surfaced real findings.** `composer install` failed on the first build: Composer's built-in security-advisory blocking (on by default since 2.9) refused to install `league/commonmark 2.6.0`, `guzzlehttp/psr7 2.7.0`, and `symfony/yaml 7.2.0` because all three carry active, currently-unpatched-at-that-version CVEs — nine advisories total. `composer.json` now explicitly allows installing them anyway (that's the entire point: fuzz what's deployed, vulnerabilities included), with the full list in a comment there and in `vuln-scan/triage-2026-06.md`. Two targets were sharpened in response: `psr7_message.php` is new because the psr7 CVEs live in raw-message parse/serialize, not the URI parsing the original `psr7_uri` target exercised; and `symfony_yaml`'s corpus now includes seeds built directly from the three confirmed YAML CVEs (deep-nesting stack exhaustion, alias-expansion "billion laughs," and a ReDoS-prone directive-header regex) — since `Yaml::parse()` on raw fuzzer input is exactly the vulnerable call shape, this harness has a real shot at rediscovering those independently.

### Run it

```bash
cd fuzzing
docker build -t sbom-fuzzer .

# Short smoke test (5 min/target), persist findings to ./findings:
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer

# A real campaign — 4 hours per target:
docker run --rm -e TIME_BUDGET=14400 -v "$PWD/findings:/fuzz/findings" sbom-fuzzer

# One target only:
docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer commonmark
```

Corpora and crash files accumulate in `./findings/<target>/`. Resuming a run reuses the grown corpus, so coverage compounds over time.

### When a crash is found
```bash
php-fuzzer minimize-crash targets/<t>.php findings/<t>/crash-XXXX.txt   # shrink it
php-fuzzer run-single     targets/<t>.php findings/<t>/minimized-XXXX.txt # read trace
php-fuzzer report-coverage targets/<t>.php findings/<t>/corpus cov-<t>/   # HTML coverage
```

A whitelisted exception (e.g. `PhpParser\Error`) on bad input is normal. An **uncaught `\Error`, a hang, or runaway memory is a real bug.** Whether it's a *security* bug depends on whether that input is attacker-reachable in your application — triage by reachability, not just by the fact that it crashed.

### Adding a target
Drop a `targets/<name>.php` that sets `$config->setTarget(fn(string $input) => /* call the library */)`, add the library to `composer.json` at its SBOM version, add seeds under `corpus/<name>/`, rebuild. Good candidates still on the table: `league/flysystem`, `monolog` formatters, `nette/schema`, `ramsey/uuid`, `symfony/mime`.

---

## Deploying this

None of this runs inside a chat sandbox — it needs an environment with Docker and internet access: your machine, a CI runner, or a server. Three tiers, roughly in the order most teams adopt them:

### 1. Local, one-off (try it out)
```bash
# vuln scan — install the two binaries once, then:
cd vuln-scan && ./scan.sh

# fuzzing — needs Docker:
cd fuzzing && docker build -t sbom-fuzzer . && docker run --rm -v "$PWD/findings:/fuzz/findings" sbom-fuzzer
```
Install OSV-Scanner and Trivy via Homebrew (`brew install osv-scanner trivy`) or see their installation docs linked in `scan.sh`'s error output.

### 2. CI (automatic, every build + on a schedule)
`ci/github-actions-vuln-scan.yml` and `ci/github-actions-fuzz-scheduled.yml` are ready to copy into `.github/workflows/`. The vuln-scan workflow installs OSV-Scanner and Trivy as pinned, checksum-verified binaries rather than via the `aquasecurity/trivy-action` / `setup-trivy` GitHub Actions — **read the comment block at the top of that file**: those two Actions had their version tags force-pushed to malicious commits in a March 2026 supply-chain compromise (remediated within hours, but it's the reason "pin third-party Actions to a commit SHA, not a tag" is in there as a standing rule, not just trivia). Not on GitHub Actions? The same two `curl`+binary steps drop into a GitLab CI, Jenkins, or CircleCI job with only syntax changes — the underlying commands don't change.

### 3. Persistent server (continuous monitoring)
Point-in-time scans miss CVEs disclosed *after* the scan ran. `docker compose up -d` in `vuln-scan/` brings up OWASP Dependency-Track (with a real Postgres backend, not the eval-only embedded H2) so newly-published advisories against your current versions alert automatically. This needs a host that stays up — not a laptop.
- Change the admin/admin login immediately (Dependency-Track forces this on first web login).
- Keep it off the public internet — internal network or VPN only — since it's a map of every vulnerable thing you run.
- `vuln-scan/upload-to-dependency-track.sh` pushes a fresh SBOM to it via API; call it from CI so the picture stays current without anyone clicking "upload."

Fuzzing doesn't fit the "persistent service" model the way Dependency-Track does — it's a batch job. Best run as the scheduled CI job above, or on a spare box with `findings/` bind-mounted permanently so the corpus keeps growing across runs instead of resetting each time.

---

## AI-assisted analysis

Two integration points, deliberately kept separate from the core engines. **The fuzzer's coverage-guided mutation and the scanners' advisory-database matching stay exactly as they are** — those are well-defined algorithmic problems that PHP-Fuzzer and OSV-Scanner/Trivy already solve better than an LLM would. What AI adds is the judgment layer on top: turning raw findings into prioritized, plain-English triage, and extending investigation into places nobody's pointed a human yet.

### Tier 1 — synthesizing scanner/fuzzer output (works anywhere, just needs an API key)

`vuln-scan/ai-triage.sh` sends `scan.sh`'s raw OSV/Trivy JSON to Claude and gets back a priority-sorted, plain-English draft — the same kind of synthesis that went into `triage-2026-06.md` by hand (read the advisory, pull out the gating condition, decide if it's a P0 or a non-issue), but for all 91 components instead of the handful checked manually.

```bash
export ANTHROPIC_API_KEY="your_anthropic_api_key_here"
cd vuln-scan
./ai-triage.sh reports/osv.json reports/trivy.json
```

It does **not** read your application code — it only reasons over the scanner JSON, which already carries the advisory description, so it can't tell you whether a finding is actually reachable. Treat its output as a sorted first draft, not a verdict. `ci/github-actions-vuln-scan.yml` now runs this automatically after every scan if you add an `ANTHROPIC_API_KEY` repository secret — it's skipped cleanly if you don't.

### Tier 2 — repo-aware investigation (needs Claude Code)

For "is this actually reachable in *our* code," you need something that can read the codebase, not just the advisory text. That's a natural fit for [Claude Code](https://docs.claude.com/en/docs/claude-code/overview)'s headless mode (`claude -p`), which runs non-interactively and can read/search files.

**Reachability check** — run this from your *application's* repo (not this toolkit, which doesn't contain the app source):
```bash
cd /path/to/your/laravel/app
claude -p --allowedTools "Read,Grep,Glob" --output-format json \
  "A dependency scan flagged guzzlehttp/psr7 2.7.0 for CVE-2026-48998/49214/55766 — CRLF injection and host confusion, all in GuzzleHttp\Psr7\Message::parseRequest(), Message::toString(), and ServerRequest::fromGlobals()/getUriFromGlobals(), NOT in normal Guzzle client usage. Search this codebase for direct calls to those methods. Report every call site with file:line, what feeds it, and whether that input could be attacker-controlled. If there are none, say so explicitly." \
  > psr7-reachability.json
```

**Extending fuzz coverage** — we've hand-built targets for 8 of the 91 SBOM components. Claude Code can draft more, following the existing pattern:
```bash
cd fuzzing
# Make the installed library source readable on the host first —
# vendor/ only exists inside the built image otherwise:
docker create --name tmp-fuzz-extract sbom-fuzzer >/dev/null
docker cp tmp-fuzz-extract:/fuzz/vendor ./vendor
docker rm tmp-fuzz-extract >/dev/null

claude -p --allowedTools "Read,Write,Bash" --max-turns 15 \
  "Look at targets/commonmark.php and targets/symfony_yaml.php as examples of this project's php-fuzzer target pattern. Read vendor/league/flysystem's public API (composer.json for the exact pinned version, then src/). Write targets/flysystem.php fuzzing a sensible entry point — path handling or adapter resolution — for that exact version, following the same structure: setMaxLen, setAllowedExceptions for the library's own declared exception types, and a setTarget closure. Add 3-5 seed files under corpus/flysystem/."
```
Review whatever it writes before trusting it the way you'd review any generated code — it's a draft to accelerate the same manual process used for the 8 existing targets, not a replacement for reading it.

For unattended/scheduled runs of either command, add `--bare --dangerously-skip-permissions` (only in CI, never on a dev machine) so it doesn't stop for approval prompts.

### What the current evidence actually says about local/security-specific models

Worth grounding this before building on it, since the space moves fast and is easy to oversell:

- A 2026 reproducibility study (["Revisiting Vul-RAG"](https://arxiv.org/pdf/2606.04739)) testing a range of open-weight models — code-specialized, general-purpose, and reasoning models of varying sizes — on RAG-augmented vulnerability detection found a **performance plateau around 0.30 pairwise accuracy that persists even for the most recent, most capable open-weight models.** More parameters and more reasoning didn't move the needle much. Read that as: don't expect a local model, however large, to reliably tell you whether something is *actually* exploitable.
- A separate 2026 benchmark of real-world web vulnerability detection across six frontier and open-weight models found **Claude Opus 4.6 leading at 63% detection, with every other model — including self-hosted open-weight ones — under 50%.**
- There is no single obviously-best "security-specific" open-weight model to reach for. What people actually run locally for security tasks right now are general-purpose open-weight reasoning models (DeepSeek-R1, Qwen3, GLM-class models), prompted toward the task — not a narrow fine-tune that reliably beats general capability.

None of that means local models are useless here — it means the honest allocation is: **local models for narrow, high-frequency, low-judgment tasks; Claude for anything where a wrong call costs something.** That's the split used below.

### Local models — where they actually help: fuzzing seed generation

This is a real, separately-studied use case, not a stretch: [SeedMind](https://arxiv.org/html/2411.18143v1), [LLAMAFUZZ](https://arxiv.org/pdf/2406.07714), and [ISC4DGF](https://arxiv.org/pdf/2409.14329) (2024–2026) all show LLM-suggested seeds measurably improving coverage-guided fuzzing, using models well below frontier scale — because generating plausible, edge-case-y inputs for a known format doesn't require deep security judgment, just format fluency and a nudge toward boundary conditions.

`fuzzing/local-model-seed-suggest.sh` does this against [Ollama](https://ollama.com) running locally:
```bash
ollama pull qwen2.5-coder:7b   # once
cd fuzzing
./local-model-seed-suggest.sh commonmark 10
```
It reads the target definition + a few existing seeds, asks the local model for more in the same format, and drops them into `corpus/<target>/`. It does **not** touch PHP-Fuzzer's own mutation engine — a bad suggestion is inert; the coverage-guided algorithm just never selects it. Cheap enough to re-run every few minutes during a long campaign, which an API call to any cloud model wouldn't be.

**Directed follow-up:** when `ai-triage.sh` or Dependency-Track flags a new advisory against a library we fuzz, that's a signal about *where* to point fuzzing effort next, not just what to patch — directed greybox fuzzing research (ISC4DGF) is built on exactly this idea. In practice, that's just:
```bash
docker run --rm -e TIME_BUDGET=3600 -v "$PWD/findings:/fuzz/findings" sbom-fuzzer symfony_yaml
```
— pointing a bigger time budget at the specific target implicated by a fresh finding, rather than spreading budget evenly across all 8.

### Claude Code + local models together, not instead of each other

Fully replacing Claude Code's brain with a local model is possible — Ollama has a documented [Anthropic-compatible endpoint](https://docs.ollama.com/integrations/claude-code) (`ollama launch claude`) that points Claude Code at a local or Ollama-hosted model instead of Anthropic's API. That's the right call only if the actual requirement is "nothing leaves this machine, full stop" — worth being honest that this trades Claude's judgment for a model sitting on the wrong side of that Vul-RAG plateau, so it's a real capability cost, not a free swap. It's also worth naming plainly: `ai-triage.sh` and the Claude Code examples elsewhere in this README already send data to Anthropic's API. If air-gapping is the actual goal, that constraint applies to those too, not just anything new.

The more useful pattern for most teams is the other direction: **keep Claude Code on the real API for judgment, delegate high-volume/low-judgment sub-steps to a local model it calls out to.** This is an established pattern with existing community MCP servers built for exactly it — e.g. [`claude-sidekick`](https://github.com/andrewbrereton/claude-sidekick) and [`OllamaClaude`](https://github.com/Jadael/OllamaClaude), both wiring a local Ollama instance in as tools Claude Code can call, reporting up to ~98% token savings on the sub-tasks they offload. These are third-party community projects, not Anthropic's — read the code before pointing them at anything sensitive, same as you would any tool with API/filesystem access. Concretely for this toolkit: pointing Claude Code's target-scaffolding task (see Tier 2 above) at such a bridge lets the *local* model do the mechanical work — reading through an entire vendor library's source tree and summarizing its API surface — while Claude still makes the actual judgment call about what's worth fuzzing and writes the target.

### Where this doesn't help

An LLM guessing at "interesting" fuzz inputs directly would be a *worse* fuzzer than PHP-Fuzzer's actual edge-coverage feedback loop — don't replace `run.sh` with prompting; use local models to widen the seed pool, not to replace the mutation engine. Likewise, don't let Tier 1's output, or a local model's opinion, skip the reachability check: given the plateau in open-weight vulnerability-detection accuracy above, a confident-sounding severity label from any model that hasn't seen your code — local or otherwise — is a prioritization hint, not clearance to patch-and-forget without a human looking at the actual call sites.

---

## Running this on EC2 with Amazon Bedrock

For teams that want this on AWS infrastructure billing through the existing AWS account, with IAM instead of a separate Anthropic API key floating around.

**Read this first, it'll save you time:** Claude Sonnet 5 reached Bedrock through a distinct, very new endpoint Anthropic calls "Mantle" (`AnthropicBedrockMantle` in the SDK) — separate from the older `AnthropicBedrock` client used for earlier, ARN-versioned model IDs. `vuln-scan/call_claude.py` tries Mantle first and falls back to the legacy client with a clear warning if your installed SDK doesn't have it yet. If both paths fail, that's a sign this corner of the API moved again since this was written — check `docs.claude.com`'s Bedrock pages rather than trusting either hardcoded model ID blindly. This isn't hedging for its own sake: this exact endpoint was days old when this was built, so treat the model ID as something to verify once, not gospel.

### One-time AWS setup
1. **Request model access** — AWS Console → Bedrock → Model access → enable the Anthropic models you want. Per-account, one-time, takes a few minutes to a few hours to grant.
2. **Have an EC2 key pair** ready (`aws ec2 describe-key-pairs` to check, or create one in the console).

### Launch
```bash
cd aws
export YOUR_IP=$(curl -s https://checkip.amazonaws.com)/32
export KEY_NAME=your-key-pair-name
./launch-ec2.sh
```
This creates an IAM role scoped to exactly `bedrock:InvokeModel`/`InvokeModelWithResponseStream` on Anthropic models — no broader AWS access, and no static credentials anywhere — a security group open for SSH from your IP only, looks up the *current* Amazon Linux 2023 AMI via SSM rather than a hardcoded ID that goes stale, and launches with `bootstrap.sh` as user-data. **This targets AL2023, not AL2** — Amazon Linux 2 reaches end-of-support on 2026-06-30, so starting anything new on it isn't a reasonable default anymore.

Bootstrap installs Docker, Node + Claude Code, OSV-Scanner, pinned+checksum-verified Trivy (same approach as the CI file), and the `anthropic[bedrock]` Python SDK. It does not fetch this toolkit onto the box — after it finishes (`ssh` in, `sudo tail -50 /var/log/cloud-init-output.log` to confirm), pull the toolkit yourself (git clone your fork/mirror, or scp the zip).

### Point everything at Bedrock
```bash
export CLAUDE_BACKEND=bedrock          # ai-triage.sh / call_claude.py
export CLAUDE_CODE_USE_BEDROCK=1       # Claude Code itself
export AWS_REGION=us-east-1            # wherever you granted model access
```
With those set, `./orchestrate.sh path/to/sbom.xml` runs exactly as documented above — every stage that talks to Claude now goes through Bedrock using the instance's IAM role, with zero code changes and no API key on the box at all. Verify with `aws sts get-caller-identity` (confirms the role is assumed) followed by `python3 vuln-scan/call_claude.py --backend bedrock --prompt "Say OK"` (confirms inference actually works) — **not** `aws bedrock list-foundation-models`, which needs `bedrock:ListFoundationModels`, a permission `iam-bedrock-policy.json` deliberately doesn't grant. An error on the second command citing `bedrock-mantle:CreateInference` means the role's policy predates that statement (Claude Sonnet 5 runs through a Mantle endpoint with its own separate IAM namespace from classic `bedrock:InvokeModel` — confirmed against AWS's own `AmazonBedrockMantleInferenceAccess` managed policy, not guessed) — re-run the `put-role-policy` command from `launch-ec2.sh` with the current `iam-bedrock-policy.json` to update the existing role. An error about model access instead means Step 1 above hasn't been granted yet.

**On the Dependency-Track piece specifically:** if you also stand that up on this box, do not open its port in the security group `launch-ec2.sh` created — it's intentionally SSH-only. Reach the UI via `ssh -L 8080:localhost:8080 ec2-user@<ip>` instead. Same reasoning as before: it's a live map of every vulnerable thing you run.

---

## License

This toolkit is released under the **Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`)**. Each version converts to Apache-2.0 under the Future License terms described in `LICENSE`.

This is source-available/Fair Source licensing, not OSI-approved open source. Do not describe this package as OSI open source unless you change to an OSI-approved license.

Third-party tools and libraries retain their own licenses.

---

## Scope & honest limitations

- **Fuzzing finds crashes/DoS-class bugs in input handling.** It does not find authz flaws, business-logic bugs, SQLi in your own queries, or stored XSS. It complements — does not replace — known-CVE scanning, SAST, and code review.
- **A crash isn't automatically a CVE.** Confirm reachability and impact before filing or patching.
- Run all of this only against software your organization owns or is authorized to test.
- Pin the `php-fuzzer.phar` version in the Dockerfile once you've validated a release, rather than tracking `latest`.

## Fuzzing Capabilities

The toolkit includes an expanded fuzzing subsystem for SBOM security research and parser hardening:

- SBOM-specific fuzz targets for CycloneDX JSON, SPDX JSON, package-url strings, and SPDX-style license expressions.
- Dockerized Python/Atheris, JavaScript/Jazzer.js, and PHP/php-fuzzer engines.
- `make fuzz-smoke`, `make fuzz-nightly`, and `make fuzz-deep` workflows.
- Crash metadata and reproducer scaffolding under `fuzzing/findings/<target>/`.
- Corpus generation and mutation tools for real SBOMs.
- Differential SBOM testing across locally installed tools such as Trivy, Grype, Syft, and CycloneDX CLI.
- AI-assisted seed suggestion using a local Ollama model, with human review required before seeds are promoted.

Start with:

```bash
make fuzz-smoke
make fuzz-scorecard
make fuzz-corpus SBOM=vuln-scan/cyclonedx-sbom.xml
make fuzz-differential SBOM=vuln-scan/cyclonedx-sbom.xml
```

See `docs/fuzzing/CONTINUOUS-FUZZING.md` and `fuzzing/README-ENGINES.md` for details.


## SBOM Operations Workbench

The toolkit now includes a lightweight SBOM operations layer in addition to vulnerability scanning and fuzzing.

Useful commands:

```bash
make sbom-score SBOM=vuln-scan/cyclonedx-sbom.xml
make policy-check SBOM=vuln-scan/cyclonedx-sbom.xml POLICY=policies/default-release-policy.yml
make supplier-intake SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
make vex-template CVE=CVE-2099-0001 COMPONENT=pkg:pypi/example-lib@1.0.0 STATE=under_investigation
make vex-validate VEX=vex/examples/not_affected.cdx.json
make prioritize VULNS=test-sboms/vulnerable/sample-trivy-report.json
make scanner-compare SBOM=vuln-scan/cyclonedx-sbom.xml
make release-evidence SBOM=vuln-scan/cyclonedx-sbom.xml
make demo
```

New capabilities include:

- SBOM quality scoring.
- Policy-as-code release gates.
- Supplier SBOM intake review.
- CycloneDX VEX template, validation, merge, and explanation helpers.
- Vulnerability prioritization using CVSS/EPSS/KEV-style fields when available.
- Scanner comparison scaffolding for Trivy, Grype, and OSV-Scanner.
- OpenSSF Scorecard wrapper scaffolding.
- GUAC-friendly export scaffolding.
- Static local dashboard generation.
- Release evidence bundle generation.

### UI direction

The current UI approach is intentionally lightweight: generate a static local dashboard with:

```bash
make ui
open reports/ui/index.html
```

A full multi-user web application is not included yet. The recommended path is to stabilize the CLI/report schemas first, then add a local-only FastAPI UI if needed.


### Local SBOM Workbench UI

Start a localhost-only UI for uploading SBOMs and running toolkit workflows:

```bash
make ui-server
```

Then open `http://127.0.0.1:8080`. The UI supports SBOM upload, workflow execution, job status/logs, scanner availability checks, delete controls, and evidence-bundle download. It stores data locally under `ui/storage/` and is not intended to be internet-facing.

See `docs/ui/LOCAL-WORKBENCH.md`.
