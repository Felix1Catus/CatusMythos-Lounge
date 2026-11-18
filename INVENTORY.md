# Skill inventory

Structural inventory of every skill: intended use, CLIs and their purpose,
dependencies, test coverage, scope controls, integrations, overlaps, and the
clearest coverage gaps. This is a map for prioritizing deeper per-skill review;
it is not itself a line-by-line doc-vs-code audit (that happens per skill).

## 2026-11-18 addendum — expanded campaign integrations

The shared request gate now includes direct HTTP clients in DOM XSS, cache,
four AI/LLM testers, and the chain executor, plus upload tester TCP probes and
API authz. The authz CLI has campaign-required context validation, and tests
exercise it through loopback and the registered runner. The external adapter
supports bounded curl, single-query dig, and one-port Nmap connect probes with
explicit endpoint declarations. Other variable-volume network executables,
shell-mediated commands, and unknown child processes fail closed. Campaign
Python processes also guard DNS resolution and TCP/UDP socket destinations and
disable ambient proxies. This is process-level defense in depth, not a host
firewall; native code and copied installations outside the campaign bootstrap
still require OS isolation. Validation and push details follow after the full
suite. Full pytest: **957 tests + 143 subtests**; focused campaign/authz tests:
**115 tests + 29 subtests**. Ruff, compileall, common-sync, CLI-docs
(**10/116/63**), and diff checks passed. Loopback fixtures only; no external
target was contacted. The follow-up was pushed to `main`.
Inventory structure originated at `f870a85`. Coverage status was refreshed
2026-11-16 through the scoped closeout in `HANDOVER.md`; the final verification
and commit are recorded in the latest dated addendum below. Earlier checkpoints
remain historical snapshots; `git log -1` is the source of truth for the tip.

## 2026-11-18 addendum — shared campaign request gate

Campaign-launched registered scanner CLIs now reserve request counts through a
central SQLite gate integrated at the five network skills' common
`scoped_urlopen` boundary. `run-cli` currently covers cloud detection, API
authorization, web crawling, SQLi, XSS, and IDOR with fixed script entrypoints.
The gate validates exact origin, active step state, persisted step budget, and
campaign budget; same-origin redirects consume budget too. Direct standalone
runs, copied skill installations, external HTTP clients/executables, and
non-scanning chain/report tools remain outside the aggregate counter. No authz
tester source or API breaker tests were changed.
Campaign cloud detection uses only the in-scope HTTP header probe; DNS/CNAME
and WHOIS lookups are suppressed.
Validation: **949 pytest tests + 143 subtests**; focused campaign/gate matrix
**49 + 7 subtests**; Ruff, compileall, common-sync, CLI-docs (**10/116/63**),
and diff checks pass. No external target was contacted.

## 2026-11-18 addendum — coordinated campaign foundations (#1–#6)

Added an offline campaign manifest/planner, scoped role/object matrix evaluator,
coverage registry and evaluator, common finding evidence review, and contextual
business-document scope validation. The planner can read sanitized target
knowledge and emits an ordered plan. Its opt-in SQLite ledger persists step
state, enforces dependencies, reserves requests atomically, and blocks
completed-step replay. Three native adapters execute: business workflows,
technology fingerprinting, and anonymous API discovery. Other tools can be
recorded by operator attestation until native adapters are available; their
requests are outside the aggregate counter. Existing testers retain their
independent probe behavior and request controls.

The shared target-knowledge store now migrates schema-v1 databases to schema v2
and retains the newest 20,000 local history events per engagement for auditing;
current lookups remain latest-value views. New tests cover campaign scope,
role/state policy, knowledge migration/history, report integration, and labeled
coverage metrics. The standalone web report now supports evidence-gated
business-context tiers without changing technical CVSS or severity. Full suite:
**942 passed + 143 subtests**; focused campaign/evidence/context/knowledge/recon
matrix: **160 passed + 47 subtests**. Ruff, compileall, common-sync, CLI docs
(**10/116/63**), and diff checks pass. See `scripts/ASSESSMENT_CAMPAIGN.md`
and the corresponding dated handover/audit records for explicit execution and
accuracy limits.

## Shape of the toolkit

A `recon -> exploit -> chain -> report` pipeline plus specialized side skills.
The **core pipeline is stdlib-only by design** (no third-party packages);
`requirements.txt` carries just two optional packages:

- `requests>=2.31.0` — used by 4 scripts (chiefly `16-ai-llm-security`).
- `playwright>=1.48.0` — used by exactly one script
  (`webapp-exploit-hunter/scripts/browser_security_auditor.py`); bootstrap
  installs its Chromium binary with `python3 -m playwright install chromium`.

Plugin wiring (`.claude-plugin/plugin.json`): `skills -> ./skills`,
`agents -> ./agents/swarm-operator.md`, `hooks -> ./hooks/hooks.json`
(SessionStart bootstrap). One agent, no slash-command directory.

Supporting infrastructure outside `skills/`: `scripts/` (bootstrap +
check_common_sync + check_skill_cli_docs), `doctrine/`, `lounge/` (multi-seat
orchestration), `standalone-advanced/hooks/`, `research_notes/`, `tests/`.
The bootstrap's install commands and strict/narrow preflight are covered
offline by `tests/test_bootstrap.py`; SessionStart wiring and LF metadata are
checked by `tests/test_plugin_bootstrap_hook.py` and the same matrix.

## Test coverage at a glance

| Coverage | Skills |
|---|---|
| Broad script-level regression matrices | `recon-dominator` (59), `cloud-pivot-finder` (38), `attack-path-architect` (28), `16-ai-llm-security` (87), `03-exploit-development` (14), `vuln-chain-composer` (88), legacy `webapp-exploit-hunter` testers (87) |
| Focused or partial coverage | `api-breaker` (focused scope/discovery/business-logic/GraphQL/BOLA/BFLA/auth-analyzer/rate-limit/report regressions); `webapp-exploit-hunter` browser/crawler/DOM and selected CLI paths; `web-cache-auditor` (12 focused tests for its script) |
| Plugin infrastructure | `tests/test_bootstrap.py` (30): parsing, install command construction, retry/cache validation, browser setup, PATH readiness, and nonzero preflight gates |
| No scripts (manual methodology) | `web-protocol-auditor` |

The closeout verification passed **553 unittest cases** on Python 3.14.8. It
includes local-fixture Playwright/Chromium integration, bootstrap regressions,
and the API-breaker closeout tests. Playwright 1.48.0 minimum-version browser
integration also passed separately. Coverage is uneven:
these matrices emphasize logic and edge cases, and do not constitute end-to-end
validation of every CLI or prove the absence of bugs. See `HANDOVER.md` for
specific fixes, test themes, browser limitations, and the latest verification.

## Per-skill inventory

### recon-dominator — `[59-TEST MATRIX; all scripts covered]`
- **Use:** full-scope recon from a domain/list — subdomains, ports, tech
  fingerprint, OSINT, Google dorking, Wayback, JS/source-map recon.
- **CLIs (10):** `passive_recon`, `active_recon`, `port_scanner`,
  `tech_fingerprint`, `osint_correlator`, `google_dorker`, `wayback_analyzer`,
  `cve_lookup`, `js_recon`, `generate_report`. Shares `_common.py` (109 ln).
- **Deps:** stdlib; may shell out to user-scoped Go recon tools when present.
- **Tool setup:** the bootstrap manages Go, subfinder, httpx, puredns, naabu,
  and allowlisted DNS/WHOIS/Nmap/Perl commands. `amass` remains manual and is
  not in `GO_TOOLS`: v5 removed `enum`'s one-shot `-o`/`-json` output, the
  documented `subs` readback CLI moved between point releases, and an Apr 2026
  v5.1.1/`develop` report says `-brute`/`-w` wordlists are accepted but unused
  by the engine. Re-evaluate from the installed `amass --help` and `amass enum
  --help`, a visible wordlist-guess fixture, and a reliable structured-output
  check; see `bootstrap.py`'s `MANUAL_OPTIONAL_TOOLS` note.
- **Coverage:** `tests/test_recon_dominator.py` covers all scripts' key parsers,
  classifiers, source-map handling, CVE matching, WAF/service parsing, dork
  generation, and report rendering. Includes fixes for prose version ranges,
  trailing-period versions, cache-busted source-map URLs, and a `None` body.
  The matrix is mostly unit-level; full live recon workflows remain unverified.
- **Overlaps:** `cve_lookup` vs `vuln-chain` impact; `js_recon` endpoint
  discovery vs `webapp` crawler.

### webapp-exploit-hunter — `[PARTIAL TESTS]`
- **Use:** active web vuln scanning + PoC from domains/URLs — SQLi, XSS, SSRF,
  IDOR, SSTI, auth bypass, upload bypass, race, WAF/rate-limit bypass, LFI/XXE,
  DOM XSS (static + browser), command injection, plus browser runtime auditor.
- **CLIs (19):** `crawler`, `auth_tester`, `sqli_tester`, `xss_tester`,
  `dom_xss_auditor`, `ssrf_tester`, `ssti_tester`, `idor_tester`, `lfi_tester`,
  `upload_tester` (largest, 1201 ln), `race_tester`, `waf_bypass_tester`,
  `workflow_tester` (new 2026-11-16), `browser_security_auditor`,
  `generate_poc`, `vuln_report`, `command_injection_tester`,
  `javascript_challenge_tester`, `csp_form_tester`. `_common.py` (162); new support module
  `_waf_escalation.py` (2026-11-17, not a CLI — see below).
- **Deps:** stdlib + playwright (browser auditor and CSP form tester).
- **Coverage:** `tests/test_webapp_legacy_testers.py` adds a 99-test offline
  matrix for LFI, upload, race, SSRF, SSTI, IDOR, XSS, and WAF-bypass logic;
  network calls are mocked. Browser auditor has pure-function and local
  Playwright/Chromium integration coverage; DOM reviewer, crawler, redirect
  helper, and selected auth/SQLi/PoC/report paths have targeted coverage.
  `command_injection_tester` has a dedicated five-case offline matrix and a
  harmless marker-confirmed DVWA integration result. The upload regression now
  covers named submit/hidden controls and same-origin path resolution; live
  DVWA proof confirmed self-cleaning PHP execution. The JavaScript and CSP
  challenge verifiers each have focused tests and live lab confirmations.
  **Still partial:** auth_tester/sqli_tester's remaining network workflows
  (boolean/time-based), generate_poc, vuln_report, browser state/redaction
  boundaries, and full multi-step upload paths are not exhaustively exercised.
- **Adaptive WAF-evasion retry (2026-11-16):** `sqli_tester.test_error_based`
  and `xss_tester.test_xss_payloads` no longer give up on the first blocked
  response. Generalizing `16-ai-llm-security/prompt_injection_tester.py`'s
  best-of-N mutate/retry pattern: when a response actually looks
  filtered/blocked (not merely "no signal yet" — a genuinely clean parameter
  must not trigger extra requests), each tool automatically tries evasion
  before moving on. SQLi gets 3 new syntax-preserving mutation primitives
  (keyword case-randomization, inline-comment keyword-splitting, whitespace
  -to-comment substitution — the same family as sqlmap's `randomcase`/
  `space2comment` tampers), bounded by `--max-mutations` (default 2, 0
  disables). XSS auto-escalates to its existing `waf_bypass` payload
  category instead of requiring the operator to pass `--waf-bypass` by hand.
  Every escalated finding is marked (`waf_evasion_used`/`auto_escalated`) so
  a report never silently hides that evasion was needed.
- **New capability: multi-step workflow (sequence) testing (2026-11-16).**
  Every other tester above probes one endpoint/parameter at a time; nothing
  built a sequence out of what the crawler already saw. New
  `scripts/workflow_tester.py` discovers candidate multi-step business flows
  (checkout, signup/onboarding, verification wizards) from crawl data via
  two independent signals — a form-chain graph built from the crawler's own
  `found_on`/`url` fields (a form on page A targeting page B is a real
  edge; linear 2+-step chains are candidates), and a path-prefix/keyword
  grouping (checkout/signup/onboarding/register/wizard/setup/verify/
  activate/enroll/apply/invite) ordered by explicit step number first, then
  a start/mid/review/confirm keyword rank, crawl order as the tiebreak. For
  every step after the first it sends exactly ONE GET directly to that step
  (never a form submission, never progressing the flow itself) and
  classifies the response: a redirect to an earlier step/login, a 401/403,
  or a "complete the prior step"/session-expired message all count as the
  workflow's own enforcement working; an ordinary 200 is reported ONLY as
  an unverified candidate (INFO/low confidence) — same confirmed-vs-
  candidate discipline as api-breaker's BOLA/BFLA/JWT hardening. 34 tests in
  `tests/test_workflow_tester.py`, including a real step-ordering bug caught
  during development (keyword rank must be the PRIMARY sort key — a
  numberless "start" must sort before a numbered "step2", not after it) and
  the branch-point/cycle termination behavior of the form-chain walker.
- **Operator-authored stateful business scenarios (2026-11-17).** The same
  workflow CLI now supports plan-only scenario JSON and explicit execution
  against an operator-approved origin. Explicit baseline assertions gate
  misuse cases; bounded requests, same-origin routes, separate write consent,
  fixture cleanup declarations, and throttle-stop behavior are enforced.
  Results expose HTTP statuses and assertion outcomes only, and remain
  unverified observations. Explicit JSON-pointer captures can feed later
  same-run paths, headers, JSON bodies, and cleanup; values remain in memory
  and are excluded from reports. Scenario rules are not inferred or persisted.
- **Crawler-derived form context for SQLi/XSS (2026-11-18).** GET submit
  controls remain in generated query variants; POST targets now carry safe
  sibling fields, hidden tokens, and one selected named submit button per
  variant while omitting password/file sibling values. POST XSS checks the
  resulting page on a follow-up GET and reports persistence as an unverified
  candidate until browser execution is confirmed.
- **DVWA coverage follow-up (2026-11-18).** Authenticated crawling is needed
  to expose DVWA's full vulnerability menu. The target-knowledge campaign
  confirmed 11/15 menu modules after targeted browser and manual follow-up.
  SSTI reflected-payload false positives were fixed with unique evaluation
  wrappers; SSRF response-size changes and IDOR response/status differences
  now remain candidates without fetch or ownership proof. See the dated audit
  addendum and external scan report for module results and remaining coverage.
- **Baseline-exclusion false-positive fixes (2026-11-16): ssrf_tester.py,
  ssti_tester.py.** Real bugs, not just hardening — `ssrf_tester.py`'s
  `SSRF_SUCCESS_PATTERNS["localhost"]` included a bare `r"<html"` (matches
  virtually every HTML page) with no check against the baseline response,
  so nearly every tested parameter on an ordinary site was flagged SSRF
  HIGH/CRITICAL regardless of whether anything happened; `ssti_tester.py`'s
  `fingerprint_engine` never fetched a baseline at all, so an unmodified
  page that happened to show "49" anywhere (a price, an age) confirmed
  CRITICAL SSTI on every request. Both now require a match to be absent
  from the baseline response before confirming — the same technique
  `sqli_tester.py`'s `test_error_based` already used. 5 new tests (legacy
  matrix: 82 -> 87).
- **Automatic bounded WAF escalation (2026-11-17, supervised improvement
  #6; new `_waf_escalation.py`).** `sqli_tester.test_error_based` and
  `xss_tester.test_xss_payloads` previously left an operator to notice a
  block and separately run `waf_bypass_tester.py` by hand. Now, when every
  payload (plus its mutation retries / in-category bypass attempts) for a
  parameter is blocked by what `classify_block()` identifies as attack
  filtering specifically — never bare rate limiting (429/Retry-After/"too
  many requests") — and nothing is confirmed, both auto-invoke a small,
  fixed, budget-capped subset of `waf_bypass_tester.py`'s own differential
  tests (parameter pollution, then one inspection-size-limit step)
  in-process, via `--waf-escalation-budget` (default 4, 0 disables). A
  shared `EscalationTracker` stops the same (url, param) escalating twice
  per run; the call graph is one-directional (never imported back by
  `waf_bypass_tester.py`, locked by a source-scan regression). Escalated
  findings are tagged `origin: "auto_waf_escalation"` and explicitly noted
  as WAF-bypass evidence, not SQLi/XSS confirmation. Off by default at the
  function level, so pre-existing callers/tests are unaffected; existing
  mutation-retry and in-category bypass behavior is unchanged. Auto escalation
  is limited to GET query parameters, forwards authorization headers, and
  honors rate-limit/Retry-After classification. New
  `tests/test_waf_auto_escalation.py`: 43 tests, including a loopback-only
  integration through the real lazy-loaded `waf_bypass_tester` module; no
  external targets are contacted.
- **Scope controls:** `--active`, `--submit-forms`, `--callback-url`,
  `--allow-destructive-poc`, `--skip-lfi-chains`, `--max-mutations` (sqli);
  HTTPS-verified default. `workflow_tester.py` is read-only by design (GET
  only) and has no write gate because it never needs one.

### api-breaker — `[100 FOCUSED TESTS; SCOPED CLOSEOUT COMPLETE]`
- **Use:** API security from domains — discover REST/GraphQL/SOAP, rebuild
  schemas, test BOLA/IDOR, BFLA, mass assignment, JWT, rate-limit bypass, logic.
- **CLIs (8; `_common.py` and `response_safety.py` are support modules):** `api_discovery`, `schema_builder` (1814 ln),
  `auth_analyzer`, `authz_tester`, `mass_assignment`, `rate_limiter`,
  `logic_tester`, `api_report`.
- **Coverage:** `tests/test_api_breaker.py` covers same-origin JavaScript
  discovery, imported endpoint scoping in `schema_builder`/`rate_limiter`/
  `logic_tester`, bounded rate-test counts, active-probe preservation, duplicate
  single-endpoint submissions, candidate-confidence/report mapping, GraphQL
  query-name/input bounds and evidence classifications, nested-field candidate
  handling, User A/User B cookie isolation, bounded authz delay, sanitized
  response previews across auth/authz/business-logic/mass-assignment outputs,
  iterative ID extraction, URL-keyed GraphQL/OpenAPI rate-limit imports,
  clean GraphQL batch/alias response validation and candidate report mappings,
  local HTTP rate-limit header/GraphQL fixtures, and a local HTTP BOLA/BFLA
  workflow fixture. Coupon stacking requires a structured applied collection;
  generic success text or echoed request fields do not qualify. Race probes
  have local stateful HTTP fixtures for idempotent and excess-counter-change
  outcomes, JSON Pointer validation, and same-origin read-back scope. Active
  GraphQL CSRF GET/form submits still require the explicit cookie/canary, and
  mutation writes remain opt-in.
  `tests/test_targeted_audit_fixes.py` covers hostile imports and write gating
  in `auth_analyzer`, `authz_tester`, and `mass_assignment`. This is not a full
  per-script matrix: JWT attack cases still need isolated HTTP integration and
  RS/PS relabel review; GraphQL has offline regressions but no real HTTP
  integration; BOLA/BFLA has local loopback integration but no live API
  integration; rate-limit and batching have loopback fixtures but no live
  authorized API integration. Without configured state read-back, business
  race 2xx counts remain candidates. With `--race-state-url` and
  `--race-state-json-pointer`, each case compares a sequential control with a
  concurrent burst against a numeric counter. The run-wide
  `--race-request-budget` includes bursts, controls, and read-backs. This is
  still generic payload coverage, not target-specific workflow validation.
  Business-state read-back semantics and broad report input shapes remain
  lightly tested or untested. Response redaction is pattern-based; application-specific
  secrets embedded in arbitrary JSON strings may still escape detection.
- **N-role authorization matrix (2026-11-17):** `authz_tester.py` previously
  tested exactly two identities (`--token`/`--token-b`). New repeatable
  `--role NAME:TOKEN` (declared lowest-privilege first) generalizes BOLA to
  cross-test every role's objects against every OTHER role (not just a fixed
  pair), and generalizes BFLA so only a role ranked BELOW the highest-declared
  role succeeding at a privileged endpoint is reported -- the top role
  reaching its own admin surface is expected and not flagged, a distinction
  the single-token mode has no way to make since it can't know whether its
  one token IS the admin. `test_bola`/`test_bfla` and `--token`/`--token-b`
  are completely unchanged; the matrix path (`test_bola_matrix`/
  `test_bfla_matrix`) only activates when `--role` is used. 18 new tests.
- **Scope controls:** explicit trusted `--api-base` for imported endpoints in
  schema, auth, authz, mass assignment, rate-limit, and business-logic testing;
  off-origin imported endpoints are skipped. `--allow-mutation-write` gates
  BOLA/BFLA, GraphQL mutation-BOLA, and mass-assignment writes. GraphQL CSRF
  GET/form mutations require `--cookie` and `--csrf-test-id`. Business-logic
  POST/PUT/PATCH payloads remain active without a new flag when selected.
  Rate-limit `--count` is bounded to 1–1000 (default 120); logic race traffic
  is capped at 840 requests per run by default, including optional controls and
  state reads.

### cloud-pivot-finder — `[38-TEST MATRIX; all 7 scripts covered]`
- **Use:** map cloud infra from domains; external->internal pivot paths —
  provider detection, S3/GCS/Azure enum, subdomain takeover, serverless, CI/CD
  and IaC leaks, metadata pivot paths.
- **CLIs (7 + `_common`):** `cloud_detector`, `bucket_enum`, `takeover_scanner`,
  `serverless_finder`, `cicd_finder`, `metadata_paths`, `cloud_report`.
- **Coverage:** `tests/test_cloud_pivot_finder.py` covers all seven scripts'
  key classification, parsing, scope, and report logic. It fixes the empty
  `<Region>` extraction crash and tests takeover false-positive exclusions,
  including S3 account-regional names and edge-case platform confidence.
  Full live cloud discovery is not covered.

### attack-path-architect — `[28-TEST MATRIX; all 5 scripts covered]`
- **Use:** attack trees/kill chains from recon or domain input; MITRE ATT&CK
  mapping, chaining opportunities, trust relationships, prioritization.
- **CLIs (5 + `_common`):** `classify_assets`, `map_trust`,
  `generate_attack_tree`, `mitre_mapper`, `engagement_planner`.
- **Coverage:** `tests/test_attack_path_architect.py` covers all five scripts'
  key lookup, scoring, tree/path generation, exposure, trust-graph, and planning
  behavior. It fixes a `NameError` in tech-fingerprint merging. Full end-to-end
  engagement orchestration remains unverified.
- **Overlaps:** prioritization/chaining logic overlaps `vuln-chain-composer`.

### vuln-chain-composer — `[88-TEST MATRIX; chain pipeline, executor, and context severity covered]`
- **Use:** correlate findings across domains into multi-step chains, compute
  chained impact, generate guarded PoC previews, and produce bug-bounty reports.
- **CLIs (7 + pure helper):** `import_findings` (771 ln), `correlate`,
  `build_chains`, `calculate_impact`, `execute_chain`, `generate_chain_poc`,
  `generate_report`; `context_severity` is a pure shared helper.
- **Coverage:** `tests/test_vuln_chain_composer.py` and
  `tests/test_contextual_severity.py` cover finding normalization, evidence,
  chaining, technical CVSS, the bounded executor, evidence-linked contextual
  severity, PoC preview safety, and reporting. Business context is an explicit
  exact-host asset profile with provenance and chain-specific impact evidence;
  its separate contextual tier never alters CVSS and is assigned only to
  confirmed chains. The executor supports only confirmed redirect-allowlist to
  SSRF chains; other chains remain manual analyses.

Context severity accepts evidence-linked business context from finding
artifacts or `calculate_impact.py --business-context`. Context is exact-host
scoped and requires both business-classification evidence and chain-specific
impact evidence. It is separate from technical CVSS and only assigned on
confirmed chains; unconfirmed chains receive a potential-only tier. The rubric
reports the highest documented criticality, sensitivity, or affected-scope
factor and does not independently verify operator-supplied evidence.

### 16-ai-llm-security — `[87-TEST MATRIX; all 5 tester scripts covered]`
- **Use:** LLM/AI app security — prompt injection, jailbreak, OWASP LLM Top 10,
  RAG/vector-store, MCP/agent tool-use, model supply chain, unbounded
  consumption.
- **CLIs (5):** `prompt_injection_tester`, `rag_security_tester` (1128 ln),
  `mcp_security_tester` (968 ln), `model_supply_chain`,
  `unbounded_consumption_tester`.
- **Deps:** `requests` (HTTP to target API); `model_supply_chain` stdlib
  (bounded model/archive scanning, 64 MiB caps, streamed pickle opcodes).
- **Coverage:** `tests/test_ai_llm_security.py` adds regression coverage across
  all five testers, including prompt verdicts, model-artifact parsing, MCP
  schema/CVE/token checks, RAG leakage and membership checks, and consumption
  limits. Tests use monkeypatched network seams; no live LLM providers were
  contacted.

### 03-exploit-development — `[14-TEST MATRIX; its single script covered]`
- **Use:** PoC development + payload generation for a confirmed finding (CVE
  write-up -> working PoC; reverse/bind/web-shell delivery).
- **CLI (1):** `payload_generator` (351 ln). Stdlib-only.
- **Coverage:** `tests/test_exploit_development.py` covers payload-type
  consistency, platform/language filtering, interpolation, demo execution, and
  generated syntax details including Perl braces and PowerShell encoding.

### web-cache-auditor — `[12-TEST TARGETED MATRIX; STILL PARTIAL]`
- **Use:** CDN/cache behavior — cache-key inputs, unkeyed header reflection,
  poisoning preconditions, deception indicators, URL normalization.
- **CLI (1):** `cache_audit` (453 ln). Stdlib.
- **Coverage:** `test_cache_audit.py` (URL validation/redaction, evidence,
  bounded reads, redirect isolation, findings import, finite timing bounds,
  sensitive-query suppression, same-nonce query-key replay, and a local
  unkeyed-`utm_content` cache fixture). Separates reflection from cache replay.
- **Scope controls:** `--probe-unkeyed`; staging replay adds
  `--confirm-cache-replay`.

### web-protocol-auditor — `[MANUAL — NO SCRIPTS]`
- **Use:** research-guided HTTP desync / proxy-transition / WebSocket
  assessment methodology. No automated scanner; explicit human review gates
  high-risk live confirmation.
- **Coverage:** no automated protocol tests (none expected — it's a playbook).

## Cross-cutting observations

### Shared `_common.py` duplication
Copied across 6 skills at diverging sizes: `webapp` 162, `api-breaker` 118,
`recon` 109, `cloud` 108, `attack-path` 89, `vuln-chain` 52. A logging core is
synced across 6 pipeline skills and the scoped-redirect helper across 5 network
skills (`scripts/check_common_sync.py` guards drift), but the files are not
otherwise consolidated. Consolidation is a candidate — map imports, CLI
examples, plugin refs, and tests before moving anything.

### Scope-control / safety-flag catalog
`--api-base` (13), `--allow-mutation-write` (8), `--callback-url` (3),
`--active` (3), `--submit-forms` (2), `--probe-unkeyed` (2),
`--confirm-cache-replay` (2), `--allow-destructive-poc` (2),
`--skip-lfi-chains` (1). Plus env `CATUS_INSECURE_TLS=1` (HTTPS opt-out) and
the lounge `--dangerously-skip-permissions`. The two API write gates are the
clearest friction with the active-testing doctrine — keep them, but authorized
workflows must document and pass the flags, not silently skip write testing.

### Branding inconsistency
Most CLI descriptions still read `- orizon.one`; a few are rebranded to
`CatusMythos-Lounge` (`js_recon`, `dom_xss_auditor`, the AI/LLM and cache/
protocol skills). Cosmetic, but a cleanup pass would make provenance consistent.

### Metadata note (fixed in this pass)
`requirements.txt` referenced the SessionStart hook at
`.claude-plugin/hooks.json`; the hook actually lives at `hooks/hooks.json`
(as `plugin.json` correctly declares). The stale comment was corrected.

## Coverage limits (descriptive; not active closeout tasks)

- API-breaker and webapp-exploit-hunter coverage mixes pure unit tests with
  local HTTP/Chromium fixtures. No live external targets were used for this
  closeout, so application-specific ownership and business-state semantics are
  not asserted.
- Some legacy webapp auth/SQLi network paths and generated-report workflows
  have less integration coverage than the browser auditor and upload paths.
- Vuln-chain-composer has a broad script matrix; arbitrary real-world imported
  finding shapes and a complete recon-to-report workflow are not covered by a
  single end-to-end fixture.
- `web-protocol-auditor` is intentionally manual methodology, not executable
  scanning code.

These notes describe where the existing test evidence is narrower. The scoped
closeout checklist is in `HANDOVER.md`; they do not reopen the other skills or
authorize a repository-wide restructuring pass.

## 2026-11-17 addendum — shared target knowledge (#5)

New infrastructure: [`scripts/target_knowledge.py`](scripts/target_knowledge.py),
with [usage and scope](scripts/TARGET_KNOWLEDGE.md). One opt-in SQLite store,
explicit engagement isolation, exact-origin/resource/context keys, provenance,
confidence, expiry, process-safe transactions, and a network-free query CLI.
It is intentionally outside the per-skill `_common.py` vendoring system.

The three integrations are `recon-dominator/tech_fingerprint` (publish stack,
advertised versions, WAF observations), `webapp-exploit-hunter/sqli_tester`
(error-based negative-probe reuse and auth/rate/WAF observation context), and
`vuln-chain-composer/import_findings` (advisory enrichment only). Disabled mode
preserves the existing CLI behavior without loading shared infrastructure.
Copied-out skills require the full checkout only when opting in.

Coverage: `tests/test_target_knowledge.py` has **30 tests + 29 subtests**;
full pytest **667 passed + 102 subtests passed**. Ruff, compileall, CLI docs (**10/101/59**),
common-sync, and final diff checks passed. Reuse never crosses auth contexts,
engagements, origins, or the 15-minute negative-observation TTL. Fresh baselines
are required; error/block/rate-limit responses are not cached as clean misses.
No bodies, raw auth headers, query values, or raw payload strings are stored
by integrations. Paths and technology metadata still need private handling.

V2 adds opt-in positive cloud-provider caching in `cloud-pivot-finder` and
sanitized endpoint-inventory reuse in `api-breaker`; these are documented in
the follow-up addendum below. Other cloud/API stages and vulnerability-specific
reuse remain unwired. Tasks #6–#8 are documented in their later addenda.

### 2026-11-17 — target-knowledge v2 integrations

`cloud_detector.py` stores only positive provider/service labels (1-hour TTL;
no IPs); `api_discovery.py` stores sanitized endpoint metadata (15-minute TTL;
exact origin/base path and request-header digest). Both require explicit
engagement DB flags, support scoped forced refresh, and leave empty results
uncached. API inventory reuse skips only repeated common-path and same-origin
JavaScript discovery, not GraphQL/OpenAPI/method/legacy checks. Regression
matrix: `tests/test_shared_knowledge_pipeline.py` and
`tests/test_target_knowledge.py`; focused validation: 41 passed + 29 subtests,
full suite: 816 passed + 125 subtests. Ruff, compileall, common-sync, CLI docs
(10/109/60), and diff checks pass.

## 2026-11-17 addendum — unattended supervisor infrastructure

New `tools/agent-supervisor/`: one stdlib controller, a disabled example config,
and setup/permission/recovery documentation. It coordinates approved coding
tasks across Codex and Claude through a Git-common-dir SQLite queue and event
stream; this is separate from target knowledge and lounge target-probe cells.
Runtime transcripts preserve historical mailbox files. Worker worktrees live
outside Git metadata; reviewer clones have independent metadata.

V1 provides fenced ownership, file claims, finite queues, dependencies, bounded
repairs, exact-SHA cross-model review, validation, stop/quarantine recovery,
non-force integration and ambiguous-push reconciliation. One author task runs
at a time; no recurring service, speculative backlog, or #6–#8 work is enabled.
Default config is disabled, and only explicitly approved task specs execute.

`tests/test_agent_supervisor.py`: **39 tests + 20 subtests** with disposable local
Git remotes and offline model adapters. Both real CLI author/reviewer directions
also passed bounded disposable-repository smoke tests. Final full pytest: **724 passed + 122 subtests passed**;
Ruff, compileall, helper sync, CLI docs (**10/102/59**) and diff checks passed.
Independent Claude CLI review approved implementation `ceab93c7421c0423f9af847d49da69ac5ff0cf01` with no remaining findings. File claims are post-edit validation plus normal
CLI sandbox/tool controls; worktrees share the OS user and are not a security
boundary against hostile executables. Runtime logs/prompts require private
handling; no model secrets are provisioned or committed by this tool.

## 2026-11-17 addendum — shared-goal session view

`tools/agent-supervisor/live_view.py` provides a read-only compact terminal
monitor, JSON session listing and explicit bounded simultaneous read-only
Codex/Claude demonstration. Native UUIDs, provider names, task roles, heartbeats,
messages/tool activity and goal progress are visible together. Claude JSONL
streams retain strict result validation and historical JSON compatibility.
An independent reviewer caught/fixed completed structured-result display and
non-atomic marker flicker. `tests/test_supervisor_live_view.py`: **13 tests**.
Full-suite baseline: **735 passed + 122 subtests**; Final focused rerun: **52 passed + 20 subtests passed**.
Ruff/compileall/common-sync/CLI-docs (**10/102/59**) pass. Independent Claude CLI review approved `f152ba0554a9c72a8892e9f8cf5a73f428a83abf` with no remaining findings.

The user selected Codex desktop terminal visibility; one command paste starts
watch because app tools expose open/read, not terminal input. The view does not
embed Claude into Codex's native chat sidebar, approve tasks, or enable parallel
coding authors. Real two-provider read-only demonstration passed.

## 2026-11-17 addendum — auth/rate context and offline transfer

The shared store now supports role-labeled auth outcomes keyed by request
header digest and bounded rate-limit observations with normalized Retry-After
and numeric rate headers. `authz_tester.py` and `rate_limiter.py` publish these
facts; `idor_tester.py` displays exact endpoint/auth-context matches while
retaining normal probes. `import_findings.py` continues to include knowledge
as advisory metadata. `target_knowledge.py --export/--import` provides
validated offline transfer with same-engagement/origin checks, kind allowlists,
TTL limits, and newer-local-wins conflict handling. No network sync or
cryptographic trust mechanism is provided.

Focused regression matrix: **228 passed + 61 subtests**. Full pytest:
**827 passed + 128 subtests**. Ruff, compileall, common-sync, CLI docs
(10/111/60), and diff checks pass. No live target was tested.
