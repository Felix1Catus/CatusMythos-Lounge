# Handover and closeout status

Living status note for the ongoing CatusMythos-Lounge improvement work. Keep it
current; it records what has and has **not** been deeply reviewed so later work
doesn't mistake uneven coverage for uniform coverage.

## 2026-11-18 addendum — three-lab benchmark and sensitive-file detector

Added a bounded `web_exposure` campaign tool after the local crAPI run showed
that crawl discovery surfaced `/.env` but did not verify its contents. The
verifier detected the stock crAPI configuration leak from sensitive assignment
names while omitting values; it returned no finding for Juice Shop's HTML SPA
fallback at `/.env` and `/.git/HEAD`. Request counts were 10/12 for each app,
origin-scoped through the campaign gate.

Provisioned official DVWA, Juice Shop, and crAPI Docker labs inside WSL2. All
published endpoints were bound to loopback. The benchmark report and pinned
image/source versions are in
`doctrine/benchmarks/lab-run-2026-11-18.json`; raw scan outputs and SQLite
campaign ledgers remain in ignored `targets/benchmark/`. After the scans were
saved, all lab containers and persistent volumes were stopped and removed;
the WSL Docker package and image cache remain installed for future reruns.

The DVWA low-security SQLi CLI reported one error-based finding across two
parameters (32/80 campaign requests). The XSS CLI returned one reflected
candidate, not a confirmed execution (2/80). Crawlers used 51/100 requests on
DVWA, 55/100 on Juice Shop, and 49/100 on crAPI. API discovery completed on
crAPI at 72/120 requests with three anonymous routes; Juice Shop discovery
reported 40 routes and four GraphQL endpoints but exhausted its 240-request
cap, so it is partial. These inventory results are not vulnerability counts.

The four-case cross-lab score is **2 confirmed true positives, 1 clean true
negative, 0 false positives, 0 false negatives, and 1 unresolved positive**
(DVWA XSS). The resolved subset shows 100% precision/recall, but one positive
is unresolved and this small challenge set does not estimate real-world
recall. Full suite: **978 tests + 143 subtests**. Ruff, compileall,
common-sync, CLI-docs (**10 docs / 119 command references / 64 CLIs**), and
`git diff --check` passed. No lab container remains running.

## 2026-11-18 addendum — application behavior handoff and test prioritization

Added the bounded `web_exposure` campaign CLI. It tests nine common sensitive
file paths, compares candidate bodies with the root response, suppresses HTML
SPA fallbacks, and confirms `.env` only when non-placeholder secret-like
assignments are present. It reports key names but never configuration values.
The verifier found the stock local crAPI `.env` disclosure and correctly
returned no finding for Juice Shop's `/.env` and `/.git/HEAD` HTML shell
fallbacks. Both campaign runs used 10/12 request slots and stayed origin-scoped.
The `.env` values were not written to artifacts or output.

Added `scripts/run_local_benchmark.py` and
`doctrine/templates/ASSESSMENT_LOCAL_BENCHMARK.json`. The benchmark now tests
BOLA, BFLA, a protected-admin negative control, secret-file exposure, and a
stateful duplicate-coupon flow with safe baseline, read-back, and reset. Its
fixture score is **4/4 positives confirmed, 1/1 negative clean**; this remains
a narrow regression score, not an estimate of external recall.

Lab smoke runs used current local builds: DVWA SQLi run reported one
error-based finding; reflected XSS returned one candidate requiring browser
execution proof. Juice Shop crawl/API discovery recorded 8 endpoints and 40
API route candidates; crAPI recorded 5 crawl endpoints and 3 API candidates.
Crawler path hits are discovery leads, not vulnerability findings: Juice
Shop's 38 hidden-path hits include SPA fallbacks, and crAPI's crawler found
`/.env` before the verifier confirmed its content. The API counts are inventory
results, not vulnerability detections. Per-lab artifact files are under the
ignored `targets/benchmark/` directory.

Added `scripts/assessment_intelligence.py` to normalize saved crawler, API
discovery, and browser reports into short-lived, same-origin endpoint knowledge.
The importer removes query/fragment data, drops out-of-origin routes, bounds
the inventory, and retains only status, methods, content type/API type, and
auth-required observations. `target_knowledge.py --ingest` imports that
inventory into the selected engagement. `authz_tester.py` can add those learned
routes to its test leads when `--knowledge-db` is enabled; it still relies on
its existing identity/object evidence checks before reporting access findings.

Browser audit output now carries bounded same-origin links and form action,
method, and field-name/type metadata, with no field values or URL query data.
`workflow_tester.py --browser-audit ... --api-base ...` converts that browser
map into its existing workflow discovery graph. Repeatable `--role
NAME:HEADER:ENV_VAR` checks discovered step-skip candidates independently under
named authenticated identities, reading secrets from the environment and
labeling output by role. The campaign `prioritize`
command orders unresolved labeled cases using explicit candidate/blocked,
authorization, and stateful-workflow signals; it never changes case results,
confirms findings, or skips tests. The existing coverage evaluator remains the
benchmark metric path and continues to require explicit gold labels/provenance.

N-role BFLA now sends a successful highest-privilege read control and can
auto-validate lower-role access only when meaningful structured JSON matches
after volatile-field removal; the `/api/admin` denied-role fixture remains a
negative control. Guided scenarios accept explicit `impact_assertions` that
must differ from a safe baseline value and match a final GET/HEAD read-back;
those cases return redacted proof metadata and can auto-validate without a
per-finding human review.

Offline regression: **128 tests + 34 subtests** across assessment intelligence,
browser audit, workflow discovery, and target knowledge. The BFLA/stateful
proof slice passed **123 tests + 29 subtests**. Full suite: **971
tests + 143 subtests**. Ruff, compileall, common-sync, CLI-docs (**10 docs /
117 references / 63 CLIs**) passed. No live target was contacted. A dedicated
loopback-only benchmark app now contains labeled BOLA, BFLA, and workflow-skip
behaviors plus a protected-route negative control. BOLA and BFLA positive
controls auto-validate from reproduced object identity / matching structured
admin-role JSON; workflow step-skip remains a candidate absent state-transition
proof. The suite does not measure
internet-wide recall; broader apps and
before/after baselines are needed to quantify accuracy gains.

## 2026-11-18 addendum — WSL network namespace isolation

Campaign scan commands (`run-cli`, `run-external`, `run-step`, and
`run-workflow`) now use a temporary Linux network namespace by default. It
installs an nftables allowlist for the confirmed origin's
resolved IPv4 addresses and manifest-declared protocol/port endpoints. IPv6
and every other egress route are dropped. The scan runs as `nobody` with no
Linux capabilities; temporary veth, nftables rules, and IP-forwarding state are
removed/restored after execution. It does not modify the Windows firewall.
On Windows WSL needs root access; on Linux the runner needs root access. Both
need `iproute2`, `nftables`, and `setpriv`. IPv6-only and loopback targets are
unsupported in this mode; target hostnames are resolved and pinned before
entering the namespace. `--process-only` explicitly opts out and uses the
weaker process-level gate.
Direct skill invocations outside the runner are still not contained.

Live local WSL fixture checks succeeded: `run-external` curl reserved 1/1
request; `run-cli` API authz completed at 68/100. A namespace test allowed its
declared host/port and blocked a second port. No external target was contacted.
Full pytest passed **961 tests + 143 subtests**; focused campaign/namespace
passed **59 tests + 7 subtests**. Ruff, compileall, common-sync, and CLI-docs
passed. A regression confirms OS isolation is selected by default.

## 2026-11-18 addendum — direct-client, API authz, and external-tool gate coverage

Expanded campaign gating to the DOM XSS auditor, cache auditor, four AI/LLM
HTTP clients, chain executor, upload tester TCP connections, and API authz.
`authz_tester.py` now requires campaign context when launched through the
campaign runner; campaign authz runs also reject mutation-write mode. Its
regressions cover missing context, real loopback request accounting, and a
campaign CLI run. `run-external` supports one curl request, one scoped `dig`
query, or one single-port Nmap TCP connect probe. Resolver and non-origin
network endpoints must be declared under `scope.network_endpoints`; retries,
redirects, URL globbing, query fan-out, shell commands, and unsupported network
tools are rejected. Campaign-launched Python processes also restrict DNS,
TCP/UDP sockets, and urllib proxy use to the selected origin and explicit
endpoints; `subprocess.Popen` and direct `os` process-launch APIs reject shell
execution and unknown child commands. This closes ordinary Python escape paths,
but it is not an OS firewall: native extensions, direct processes launched
outside the runner, and copied skill folders without the campaign bootstrap
still require host-level isolation. Full validation and push status follow
after the full suite. Full pytest: **957 tests + 143 subtests**; focused
campaign/authz suite: **115 tests + 29 subtests**. Ruff, compileall,
`check_common_sync.py`, `check_skill_cli_docs.py` (**10 docs / 116 references /
63 CLIs**), and `git diff --check` passed. All network integration tests used
loopback fixtures; no external target was contacted. The follow-up is pushed to
`main`; its SHA is reported in the completion note.

## 2026-11-18 addendum — shared campaign request gate

`scripts/campaign_request_gate.py` now lets campaign-launched scanner CLIs
reserve each HTTP request through the existing SQLite ledger. The five network
skills' synchronized `_common.scoped_urlopen` helpers invoke the gate only when
campaign environment is present; ordinary standalone use is unchanged. It
checks the selected exact origin, running step, persisted per-step ceiling, and
campaign-wide ceiling, and also counts same-origin redirects. A registered
`run-cli` command safely launches fixed entrypoints for cloud detection, API
authorization, web crawling, SQLi, XSS, and IDOR; it uses no shell and does not
persist scanner arguments or request data. `campaign_step_registry` stores the
declared step ceiling, including migration for existing ledger files.
Campaign cloud detection is deliberately limited to its scoped HTTP header
probe; DNS/CNAME and WHOIS lookups are suppressed because they bypass the gate.

Coverage remains intentionally bounded: directly launched/copy-installed
skills, separate HTTP clients, external network executables, and report/chain
analysis commands are outside this gate. Authentication tester implementation
and its tests were not modified. Focused campaign and gate regressions pass;
final validation: **949 pytest tests + 143 subtests**; focused campaign/gate
matrix: **49 tests + 7 subtests**. Ruff, compileall, common-sync, CLI-docs
(**10 docs / 116 references / 63 CLIs**), and diff checks pass. No external
target was contacted.

## 2026-11-18 addendum — assessment campaign and evidence foundations (#1–#6)

New offline infrastructure: `scripts/assessment_campaign.py` validates explicit
origin scope, engagement, registered tools, role labels, step dependencies,
per-step/global declared budgets, and state-change cleanup gates. It emits an
ordered plan, can attach allowlisted exact-origin knowledge as advisory data,
evaluates role/object observations, and reports coverage separately from
precision/recall. Coverage output also groups execution by tool, role, and
configuration. Only provenance-backed labeled cases feed accuracy metrics;
conflicting confirmed/negative results remain conflicts.

`scripts/role_matrix.py` builds role × object cases from operator-declared
ownership and access policy. Status-only cross-role success is a candidate;
confirmation requires verified role identity, owner control, object identity,
and unauthorized-data proof. No credential or request execution is performed.
The API authz tester and its regression file were not changed.

`scripts/finding_evidence.py` adds a shared, non-promoting proof review for
candidate/validated/confirmed state. It requires baseline, negative-control,
effect, reproduction, and impact evidence metadata for a complete proof record.
Vuln-report JSON and normalized vuln-chain imports include the review while
preserving existing validation and chainability fields.

`scripts/target_knowledge.py` migrates schema v1 to v2 and retains a bounded
20,000-row-per-engagement local history for observations, imports, migration
snapshots, and explicit deletion. The latest-value query behavior is unchanged;
`--history` provides read-only inspection. The campaign planner attaches only
portable/sanitized target knowledge and never suppresses vulnerability tests.
Business-context documents are validated against campaign scope and remain
compatible with `context_severity.py` / `calculate_impact.py`.

Templates and usage: `doctrine/templates/ASSESSMENT_CAMPAIGN.json`,
`doctrine/templates/ASSESSMENT_COVERAGE.json`, and
`scripts/ASSESSMENT_CAMPAIGN.md`. Three native campaign adapters execute:
`business_workflow`, `tech_fingerprint`, and anonymous `api_discovery`. The
opt-in SQLite ledger binds a campaign ID to an engagement and manifest hash,
enforces step dependencies, reserves scanner requests transactionally, reports
step/campaign status, and refuses completed-step replay. Unsupported scanner
steps can be marked complete only by operator attestation; the note is hashed,
not stored, and its requests are outside the central counter. API discovery is
serial, exact-origin, request-capped, skips Wayback and potentially mutating
method probes, and emits only sanitized output. The standalone web report now
accepts evidence-backed business context; contextual severity remains separate
from technical CVSS and is assigned only after complete proof review.

Tests use offline data and loopback only; no external target was contacted in
this implementation. Full validation: **942 pytest tests + 143 subtests**.
Focused campaign/evidence/context/knowledge/recon matrix: **160 tests + 47
subtests passed**. Ruff, compileall (`skills scripts tests tools`), common-sync,
CLI docs (**10 / 116 / 63**), and `git diff --check` passed.

## 2026-11-17 addendum — supervised improvement #6: automatic bounded WAF escalation

New `skills/webapp-exploit-hunter/scripts/_waf_escalation.py`. Previously, an
operator had to notice sqli_tester.py/xss_tester.py hit a WAF block and
separately run `waf_bypass_tester.py` by hand. Both testers now auto-invoke a
small, fixed, budget-capped subset of waf_bypass_tester's own differential
tests (parameter pollution, then a single-step inspection-size-limit probe)
in-process, but only when a response classifies as **attack filtering**
(403/406, WAF/CDN block-page body) with nothing confirmed yet — never on
bare **rate limiting** (429/Retry-After/"too many requests"), which
`classify_block()` distinguishes explicitly. `--waf-escalation-budget`
(default 4, 0 disables) bounds the extra requests; a shared
`EscalationTracker` stops the same (url, param) pair from escalating twice
in one run. The call graph is strictly one-directional
(sqli/xss -> `_waf_escalation` -> `waf_bypass_tester`; the latter does not
import the former) so there is no recursive escalation loop — locked by a
static source-scan regression. Escalated findings are waf_bypass_tester's
own (still-differential, so still real) findings, tagged
`origin: "auto_waf_escalation"`, and explicitly noted as evidence the WAF
can be bypassed, not confirmation of the SQLi/XSS itself. The feature is
OFF by default at the function level (`waf_escalation_budget=0`), so every
pre-existing caller/test is unaffected; only the CLIs enable it by default.
Existing adaptive-mutation behavior (sqli's keyword-mutation retries, xss's
in-category `waf_bypass` auto-escalation) is unchanged.

New `tests/test_waf_auto_escalation.py` (43 tests): block/rate-limit
classification including Retry-After precedence, the hard request budget,
finding metadata, tracker deduplication, and a static recursion guard.
Tester integrations cover SQLi/XSS escalation and the no-escalation cases
for rate limits, confirmed findings, disabled budgets, duplicate targets,
and non-GET requests. Auth headers are retained during escalation. A
loopback-only HTTP fixture exercises the real lazy-loaded
`waf_bypass_tester.py` functions and verifies the four-request cap. The
focused pair `tests/test_waf_auto_escalation.py` +
`tests/test_webapp_legacy_testers.py` passes **130 tests**; full pytest passes
**780 tests + 122 subtests**. Ruff, compileall, `check_common_sync.py`, and
`check_skill_cli_docs.py` (**10 docs / 102 references / 59 CLIs**) pass.
`git diff --check` remains the last pre-commit check. No external targets
were contacted; real HTTP traffic is confined to the localhost fixture.

## Current state

- Latest scoped closeout code commit: `6f8c4af3646043294682520d9ca551560a01f928`
  (`Close scoped audit checklist and verify regressions`), after the two local
  API-race commits `7f26773c848cf6ebcedc7adf046b79fb17d386fe` and
  `f5bff3d96aa53ac32693fdcca3983107bf01c459`. All three are pushed to `main`.
- API-breaker now has **82 tests + 29 subtests**; cache auditor has **12 tests +
  23 subtests**. The exact final full-suite run passed **553 tests** on Python
  3.14.8 with Playwright 1.65.2 / Chromium. Playwright 1.48.0 / Python 3.13.17
  loopback checks passed separately. Ruff, compileall, helper sync, CLI docs
  (**10 / 95 / 58**), and `git diff --check` passed. The prior 555+68 figure is
  retained only as a historical checkpoint; this exact checkout's final run
  reported 553 tests. No live external target was contacted.
- Rate-limit imports now include same-origin-filtered OpenAPI records and
  api-discovery's URL-keyed GraphQL map. Duplicate rotating XFF evidence is
  fixed. Race, path-mutation, IP-header, and GraphQL responses without
  application-level proof remain INFO candidates. Active probes remain enabled.
- Cache timing is finite and bounded (timeout <= 30 seconds, delay <= 5
  seconds). Active cache probes add a bounded set of five inert query-key
  candidates, skip existing names and sensitive-looking query keys, and retain
  same-nonce replay only under the existing staging-only flag. Query values
  are omitted from reports. The local fixture models an unkeyed `utm_content`
  cache entry; broader parser differences remain manual.
- Coupon stacking now requires at least two entries in an explicit applied
  coupon/discount collection before emitting an INFO candidate. All five
  active payload cases still run; totals and persistence still require a
  controlled business-state read-back. API response redaction remains
  pattern-based and cannot catch every unknown secret embedded in arbitrary
  JSON strings.
- Business-logic race probes keep all three active payload cases and ten-way
  concurrent bursts. Optional same-origin state read-back compares each burst
  with one sequential mutation control using an operator-selected numeric JSON
  Pointer; the run-wide `--race-request-budget` includes payloads, controls,
  and reads (840 maximum by default). The sequential control is an additional
  write, so use a disposable object and a genuinely read-only GET route. Without
  comparable state, multiple 2xx responses remain INFO candidates. The thread
  pool is not HTTP/2 single-packet synchronization.

- Previous authz code pass: `585ffa2b38aba78625e83a4eec2af2e1de3637b0`
  (`Sanitize authz evidence and handle deep JSON`). See the shared redaction
  follow-up below; its pattern-based limitation still applies.

- Previous GraphQL code pass: `81733eee577420a8b3efebfb3117b691393a2f85`
  (`Harden GraphQL probe evidence and inputs`), on `main`. GraphQL depth,
  fragment-cycle, introspection-naming, and nested-field authorization
  responses that lack impact/ownership proof are now explicitly unverified
  candidates; fast transport failures are inconclusive. Schema-derived
  GraphQL names are validated, optional candidate IDs are JSON-quoted and
  bounded, and `--delay` is finite and limited to 0–60 seconds. The existing
  bounded depth ladder and selected nested-field/CSRF probes remain active;
  the pre-existing explicit cookie/canary and mutation-write gates are
  unchanged. Added 12 focused regressions: API-breaker matrix **59 tests**;
  full suite **533 tests + 38 subtests**. Ruff, compileall, shared-helper sync,
  CLI docs (**10 / 95 / 58**), and `git diff --check` passed. All API requests
  in the new tests are mocked; no live targets were contacted. Real GraphQL
  HTTP integration remains unverified.

- Verification at the GraphQL code state: **533 tests + 38 subtests**;
  the GraphQL regressions were all offline/mocked. See the dated GraphQL
  addendum below; the new local authz HTTP fixture is a separate follow-up.

- Previous JWT expiry fix: `0f58b5e8a4fa6a2531bd459215f37e85c544fc7b`
  (`Handle malformed JWT expiry values`), pushed to `origin/main` on
  2026-11-16. Malformed, non-finite, boolean, non-numeric, and out-of-range
  exp claims now produce an informational finding instead of crashing.
- Verification at that JWT-expiry code state: **521 tests + 30 subtests**;
  Ruff, compileall, shared-helper sync, CLI docs (**10 / 95 / 58**), and
  `git diff --check` passed. No live targets were contacted.

- Previous JWT/authentication follow-up: `68dd243dc5276d1d41762a6e2c059261da7c182c`
  (`Harden API auth analyzer evidence`), pushed to `origin/main` on 2026-11-16.
  JWT/API-key 2xx responses now require an invalid-token or unauthenticated
  control rejection before they are confirmed; otherwise they are INFO
  candidates. No-auth data remains a candidate pending sensitivity review.
  JWT header/payload and nested privilege-claim values redact common secrets
  and personal data. JWT decoding rejects malformed base64url and non-object
  header/payload JSON. Active probes remain enabled.
- Verification at the 68dd243 code state: **520 tests + 25 subtests**; Ruff, compileall,
  shared-helper sync, CLI docs (**10 / 95 / 58**), and `git diff --check`
  passed. No live targets were contacted.

- Previous API authorization follow-up: `511a522909c15d0687743683916217a1e892af40`
  (`Improve API authorization test evidence`), pushed to `origin/main` on
  2026-11-16. The active BOLA initial read substitutes a bounded seed for
  OpenAPI path placeholders. Status-only BOLA/BFLA responses are unverified
  candidates; exact-object BOLA GET responses remain confirmed findings.
  Existing active GET probes and explicitly enabled write/method-override
  probes still run.
- Verification at the 511a522 code state: **509 tests + 21 subtests**;
  Ruff, compileall, shared-helper sync, CLI docs (**10 / 95 / 58**), and
  `git diff --check` passed. All target-facing requests were mocked.

- Previous API-breaker URL fix: `9efbba5e7cbb7c6b816459f4dbca298fa40e6a79`
  (`Fix BOLA object URL construction`),
  pushed to `origin/main` on 2026-11-16. It wires the existing ID-endpoint
  classifier into BOLA checks, preserves direct object URLs and query strings,
  substitutes placeholders, encodes IDs, recognizes UUID-style IDs, and
  rejects unusable response IDs. Four regression tests were added.
- Verification at the 9efbba5 code state: **504 tests + 21 subtests**;
  Ruff, compileall, shared-helper sync, CLI docs (**10 / 95 / 58**), and
  `git diff --check` passed. Ruff is available through `python3 -m ruff`;
  the standalone command is not on this PowerShell PATH. No live targets
  were contacted.

- The bootstrap/preflight pass started from clean `main` at
  `3aa2f62090bce3f9e966cdd4361b58067d981d2b`. The API-breaker continuation
  started from clean `main`/`origin/main` at
  `a95bab9c9334023a82dde223190e38ca1059f82f`. Both pickup points were checked
  before edits; the focused PATH_INFO work directly preceded the bootstrap base.
- Full lineage since the audit baseline `73162b06b8458155cdf4113b810da3be6d8e6039`
  (chronological; all were present on `origin/main` at pickup):
  - `caed91e` — broad audit and hardening batch (details in `AUDIT.md`).
  - `6695fcf` — added isolated Playwright browser runtime auditor.
  - `da46b1d` — integrated deep LFI + ImageTragick work onto the audited base.
  - `0f2ce3c` — added this handover and the dated audit addendum.
  - `fb1a102`, `f870a85` — fixed browser WebSocket URL redaction and
    `postMessage` observation; hardened form-POST authorization, request
    budgets, and cookie-domain filtering.
  - `d9f7513` — added `INVENTORY.md`; fixed the stale hooks path in
    `requirements.txt`.
  - `0008e0e`, `2445562` — deepened recon coverage and fixed CVE version-range,
    cache-busted source-map, and `None`-body handling bugs.
  - `90116f8` — cloud-pivot-finder matrix and S3 region-hint crash fix.
  - `085df31` — attack-path-architect matrix and tech-merge `NameError` fix.
  - `87c1403` — AI/LLM test matrix across five testers.
  - `802be7b` — fixed chain category derivation that silently suppressed
    multi-word vulnerability chains; added vuln-chain matrix.
  - `92354a7` — exploit-development payload-generator matrix.
  - `d68009c` — legacy web tester matrix and race-PoC thread-count fix; the
    later focused PATH_INFO review recorded in `3aa2f62` added two regressions,
    bringing that matrix to 60.
  - `61aae43` — fragment img fallback, form-probe fallback, and configurable
    SPA settle behavior for the browser auditor.
- `3aa2f62` — refreshed this handover/inventory and added two PATH_INFO
  regressions for status `0` and propagation of unexpected request exceptions.
- `db2c900c1238fa12980056d4c9ad4555001f4043` — installed and verified
  required tooling in bootstrap; added managed strict/narrow preflight,
  regression tests, and the dated audit/handover updates.
- `a95bab9c9334023a82dde223190e38ca1059f82f` — recorded the bootstrap commit
  in the living handover before this audit pass.
- `ac332fcbd6be29e3aedda3b39c3b181ce15ceccf` — scoped API imports to the
  trusted origin, wired same-origin JavaScript discovery, corrected
  business-logic candidate confidence, and required an explicit cookie
  plus canary ID for active GraphQL CSRF submissions.
- `461d52d6951460a46107c79e65adb23573088ab6` — recorded the API-breaker
  continuation and its 26-test / 500-test verification checkpoint.
- `9efbba5e7cbb7c6b816459f4dbca298fa40e6a79` — fixed BOLA object URL
  construction, including direct numeric/UUID endpoints, collection query
  preservation, placeholder substitution, and unsafe ID filtering.
- `511a522909c15d0687743683916217a1e892af40` — fixed literal OpenAPI path
  placeholders in initial BOLA reads and changed status-only BOLA/BFLA
  responses into unverified candidates while preserving active probes.
- `68dd243dc5276d1d41762a6e2c059261da7c182c` — added JWT/API-key invalid-token
  controls and candidate confidence, strict JWT decoding, recursive claim
  redaction, bounded delay inputs, and focused auth-analyzer regressions.
- `0f58b5e8a4fa6a2531bd459215f37e85c544fc7b` — made JWT expiry analysis
  resilient to huge, non-finite, boolean, and non-numeric exp claim values.
- `81733eee577420a8b3efebfb3117b691393a2f85` — hardened GraphQL name and
  candidate-input handling; downgraded unverified depth/authz/fragment
  acceptance signals to candidates without disabling their active probes;
  added 12 regressions.
- `90d4fadda5ca21bfa5575f261ed32199986bc18c` — stopped sharing User A's
  session cookie with User B in BOLA probes, added separate `--cookie-b`,
  bounded authz CLI delay, and added a local HTTP BOLA/BFLA integration test.
- `585ffa2b38aba78625e83a4eec2af2e1de3637b0` — redacted common sensitive
  JSON fields and inline secrets from authz response previews, omitted
  non-JSON bodies, and made object-ID extraction iterative for deep JSON.
- `5d6e6b36947adfb6144eb98004227297daf805d6` — moved response preview
  sanitizing into `response_safety.py` and applied it across auth, authz,
  business-logic, and mass-assignment outputs.
- Verification at the `61aae43` code state: **441 tests + 21 subtests** passed;
  Ruff, compileall, CLI docs (`10/94/58`), and shared-helper sync passed. The
  browser feature has a real local Chromium fixture run. The focused PATH_INFO
  review recorded in `3aa2f62` added two regressions and reran the suite:
  **443 passed +
  21 subtests**. Ruff and compileall are clean; CLI docs now report
  **10 skill docs / 95 command references / 58 CLIs**; shared helpers are in
  sync. Chromium and the test/lint stack were installed and verified in this
  Windows environment. These are local-fixture/offline checks, not live-target
  testing. The `3aa2f62` checkpoint raised the suite to **443 tests + 21
  subtests**. Bootstrap changes and their new verification are recorded in
  this 2026-11-16 addendum; `git log -1` is the source of truth for the current
  branch tip.
- **Verification at the bootstrap continuation code state:** full suite **474
  tests + 21 subtests passed**; Ruff, compileall, CLI docs (**10 skill docs / 95
  command references / 58 CLIs**), shared-helper sync, and `git diff --check`
  passed. The real `--strict` preflight passed on Windows, including a live
  local Chromium headless launch. This host already had the managed dependencies,
  so no OS package installation ran; installer and PATH-change cases are tested
  with mocks. No live targets were contacted.
- **API-breaker deepening pass (2026-11-16):** added 26 focused regressions and
  fixed imported-endpoint scope gaps in `schema_builder.py`, `rate_limiter.py`,
  and `logic_tester.py`; each now requires the operator's explicit trusted
  `--api-base` and skips off-origin imported URLs before sending credentials or
  probes. `api_discovery.py` now invokes its previously-unwired JavaScript
  endpoint analyzer, limited to 20 same-origin script files, and validates its
  target origin and worker count. The rate CLI validates delay and caps
  `--count` at 1000 (default remains 120). `logic_tester.py` no longer repeats
  category probes before its full `--endpoint` sequence. Its active
  POST/PUT/PATCH probes remain enabled when selected; status/echo/race signals
  are informational candidates until read-back confirms persisted impact.
  GraphQL CSRF mutations now require both a session `--cookie` and an explicit
  `--csrf-test-id`; the hardcoded fallback to ID `1` is removed, and GET/form
  acceptance is only a candidate pending browser and state verification.
  Full suite: **500 tests + 21 subtests passed**; Ruff, compileall, helper sync,
  CLI docs (**10 / 95 / 58**), and `git diff --check` passed. New target-facing
  tests use mocks; no live API targets were contacted.
- **BOLA URL follow-up (2026-11-16, code commit
  `9efbba5e7cbb7c6b816459f4dbca298fa40e6a79`):** corrected the
  object URL used during active BOLA checks. Direct object endpoints (including
  UUID IDs) stay intact, collection endpoints receive one encoded ID in the
  path, query parameters survive, and placeholder paths are substituted.
  Extracted response IDs reject null, boolean, container, oversized, and
  control-character values. The focused API-breaker matrix is now **30 tests**.
  The complete suite passed **504 tests + 21 subtests**; Ruff, compileall,
  helper sync, CLI docs (**10 / 95 / 58**), and `git diff --check` passed on
  Windows/Python 3.14.8. Ruff was run as `python3 -m ruff` because its standalone
  executable is not on this PowerShell PATH. All target-facing regressions are
  mocked; no live target was contacted.
- **Authorization evidence follow-up (2026-11-16, code commit
  511a522909c15d0687743683916217a1e892af40):** OpenAPI-style object
  placeholders are replaced with the first bounded seed ID before the User A
  read, rather than being sent literally. BOLA status-only and static-ID hits
  are candidates; a cross-user/anonymous BOLA GET is confirmed only when a
  200 response contains the exact tested ID. BFLA and method-override 2xx
  responses are candidates pending proof of privileged data/action. Existing
  active GET behavior is unchanged; explicitly opted-in POST/PUT/PATCH/DELETE
  and method-override probes still execute. Added five regressions.
  The API-breaker test file now has **35 tests**; the full suite passed
  **509 tests + 21 subtests**, Ruff, compileall, helper sync, CLI docs
  (**10 / 95 / 58**), and git diff --check. All target requests were mocked.
- **JWT/auth analyzer follow-up (2026-11-16, code commit
  68dd243dc5276d1d41762a6e2c059261da7c182c):** JWT and API-key acceptance
  now uses a malformed-token/unauthenticated baseline; a 2xx becomes a
  confirmed auth finding only when the baseline is rejected with 401/403.
  Public or control-ambiguous endpoints produce INFO candidates. No-auth data
  remains a candidate until sensitivity and intended access are established.
  JWT header, payload, and nested privilege values redact common credential,
  key-material, and personal-data keys in JSON output. The decoder rejects
  invalid base64url segments and non-object JSON. CLI delay is bounded to
  0–60 seconds and the timing sleep to 1–10 seconds. Active probes still run.
  Added 11 regressions; the API-breaker test file now has **46 tests**. The
  full suite passed **520 tests + 25 subtests**, Ruff, compileall, helper sync,
  CLI docs (**10 / 95 / 58**), and git diff --check. No live targets were
  contacted.
- **JWT expiry boundary follow-up (2026-11-16, code commit
  0f58b5e8a4fa6a2531bd459215f37e85c544fc7b):** direct conversion of arbitrary
  exp numbers to datetime raised OverflowError for large but valid JSON
  integers. The analyzer now reports malformed/non-finite/non-numeric or
  unrepresentable expiry values as INFO and continues. Added one regression
  with five invalid-value subcases. API-breaker matrix: **47 tests**; full
  suite: **521 tests + 30 subtests**. Ruff, compileall, helper sync, CLI docs
  (10 / 95 / 58), and git diff --check passed; all target requests were mocked.
- **GraphQL evidence/input follow-up (2026-11-16, code commit
  `81733eee577420a8b3efebfb3117b691393a2f85`):** fixed overconfident
  classification of timeout/5xx/depth-cost timing, fragment-cycle acceptance,
  introspection-name acceptance, and nested-field response differences. These
  signals are now INFO candidates pending isolated impact, object-ownership,
  or read-back evidence; quick transport failures and non-200/non-GraphQL
  responses are inconclusive. Validated schema-derived names before query
  interpolation; JSON-quoted caller IDs; bounded the optional ID list to 50
  values of 128 characters and CLI delay to finite 0–60 seconds; preserved
  active payload submission and the existing gates for CSRF/mutation writes.
  Added 12 regressions covering negative controls, injection-safe quoting,
  input bounds, candidate classifications/report mappings, and continued
  active GET/form/opt-in write behavior. API-breaker matrix: **59 tests**;
  full suite: **533 tests + 38 subtests**. Ruff, compileall, helper sync, CLI
  docs (**10 / 95 / 58**), and diff check passed. All new target-facing tests
  were mocked. No live target or real GraphQL HTTP integration was used.
- **BOLA/BFLA local-integration and session-isolation follow-up (2026-11-16,
  code commit `90d4fadda5ca21bfa5575f261ed32199986bc18c`):** found that the
  single `--cookie` was copied into both User A and User B headers while
  testing with separate bearer tokens. User B could therefore be authenticated
  as User A and produce misleading cross-user evidence. Added `--cookie-b`;
  User B receives only that cookie when supplied, and never inherits User A's
  cookie. Shared non-cookie headers still apply to both users. Bounded
  `authz_tester.py --delay` to finite 0–60 seconds. A real loopback HTTP fixture
  now exercises the collection read as User A, exact-object GET as User B,
  denied anonymous read, regular-user `/admin` GET candidate, and verifies that
  default authorization testing sends only GETs. The selected mutating probes
  remain active under the existing explicit `--allow-mutation-write` gate.
  API-breaker matrix: **63 tests**; full suite: **537 tests + 47 subtests**.
  Focused authz tests passed **79 tests + 31 subtests**; Ruff, compileall,
  helper sync, CLI docs (**10 / 95 / 58**), and diff check passed. Network
  integration used only the loopback fixture. No live API was contacted.
- **Authz evidence-output follow-up (2026-11-16, code commit
  `585ffa2b38aba78625e83a4eec2af2e1de3637b0`):** authorization findings
  previously stored raw 200-character response bodies, which could place
  credential or personal-data values in JSON reports. JSON previews now redact
  common password/token/key/cookie/contact fields plus inline email/JWT/bearer
  and key-value secrets; non-JSON/HTML response bodies are replaced with an
  omission marker and length. Object IDs remain available for correlation.
  `extract_object_ids()` now walks nested arrays/objects iteratively and safely
  handles non-text and deeply nested JSON. Added regressions for nested secret
  redaction, non-JSON omission, deep IDs, and invalid bodies. API-breaker matrix:
  **65 tests**; full suite: **539 tests + 47 subtests**. Focused authz tests:
  **81 tests + 31 subtests**. Ruff, compileall, helper sync, CLI docs
  (**10 / 95 / 58**), and diff check passed. No live external target was
  contacted. Similar raw `response_preview` fields in `auth_analyzer.py`,
  `logic_tester.py`, and `mass_assignment.py` remain to be audited.
- **API-breaker shared response-redaction follow-up (2026-11-16, code commit
  `5d6e6b36947adfb6144eb98004227297daf805d6`):** extracted the authz sanitizer
  into `scripts/response_safety.py` and applied it to all response preview
  emitters in `authz_tester.py`, `auth_analyzer.py`, `logic_tester.py`, and
  `mass_assignment.py`. Existing auth, business-logic, and mass-assignment
  tests now assert that preview output strips representative PII/credentials.
  A source scan found no remaining raw `response_preview: body[:…]` in the
  API-breaker scripts. The sanitizer is key/pattern-based; an unknown
  application-specific secret embedded in arbitrary JSON text may still
  escape detection, while HTML/non-JSON body snippets are omitted. Full suite:
  **539 tests + 47 subtests**; Ruff, compileall, helper sync, CLI docs
  (**10 / 95 / 58**), and diff check passed. No live targets contacted.
- The browser auditor has now had a **real Playwright/Chromium integration run**
  against a local fixture (passive, active query, active fragment via both
  `innerHTML` and `document.write`, and form submission all exercised). Two bugs
  were found and fixed (see below). `tests/test_browser_security_auditor.py`
  adds pure-function coverage plus a Chromium-gated live test that skips cleanly
  when the browser is absent.

## Established per-skill workflow

For each skill deepening pass:
1. Inventory its scripts, skill guide, current tests, dependencies, and scope
   controls; compare documented CLI usage with the actual commands.
2. Read the implementation closely and identify concrete bug risks and
   testable pure units. Separate a real bug from missing coverage or a
   documented heuristic.
3. Fix confirmed bugs. Where network code is entangled, introduce a narrow
   injectable seam so regression tests can mock requests without weakening the
   real active-testing behavior.
4. Add a per-skill regression matrix, including boundaries and negative cases.
   Keep tests offline or on loopback fixtures unless browser integration is
   specifically required and locally isolated.
5. Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/bootstrap.py" --strict` before a
   full engagement, or use `--require-tool` / `--require-python` for a narrow
   task. If a newly installed executable needs a refreshed PATH, stop, restart
   the parent PowerShell/terminal or desktop host and Claude Code, then rerun
   preflight. Install and verify test tools before dependent checks. Run the
   full pytest suite, Ruff, compileall, and relevant
   CLI/helper/manifest checks. Do not describe skipped or partial validation
   as complete.
6. Update `HANDOVER.md`, `INVENTORY.md`, and dated `AUDIT.md` addenda with what
   was inspected, what changed, verification, and remaining uncertainty.
7. Commit one logical chunk with the configured author identity, push to
   `origin main`, verify the remote SHA and final tree, and report the full
   commit SHA. Never rewrite pushed history.

## Depth of review so far (self-reported by the audit author, not yet
independently re-verified line by line)

**Deepest automated coverage:** cache-audit helpers, static DOM analysis,
crawler discovery, redirect scope, selected imported-API data handling, XSS
finding-confidence, PoC-generation safety.

**Bootstrap/preflight deepened 2026-11-16:** setup markers are now revalidated
against the active interpreter and package versions; failed Python installs
retry on later runs; Playwright Chromium is installed and its executable is
checked; missing allowlisted system tools are installed through existing
noninteractive package managers; Go installs are verified and Windows user
PATH is persisted. `--strict` gates the complete managed stack, while
`--require-tool` and `--require-python` gate narrower tasks. See the dated
addendum for exact tests and validation boundaries. Actual OS package-manager
installation was not exercised in this already-provisioned Windows environment.

**Areas deepened since the prior handover (coverage is regression depth, not a
claim that every behavior is exhaustively validated):**
- `cloud-pivot-finder` — DEEPENED 2026-11-16: all 7 scripts now have a 38-test
  matrix (`tests/test_cloud_pivot_finder.py`). `takeover_scanner` was refactored
  to expose a pure `classify_takeover` (network injected) so the fingerprint
  state machine is testable, and tests lock the documented false-positive fixes
  (CloudFront/GCS/Firebase/Fastly/Zendesk negative fingerprints rule a service
  out; ELB `nxdomain_vulnerable: False` stays inert; S3 `-an` account-regional
  names are excluded; edge-case platforms are flagged not confirmed). One real
  bug fixed: `bucket_enum.check_s3_bucket` crashed with `AttributeError` when a
  response body contained an empty/unterminated `<Region>` tag (substring
  present but regex no-match → `None.group(1)`); now matches first. Also covered:
  `generate_bucket_names`, the cross-cloud `_CRED_PATTERNS` regex, the
  reference-only `check_bucket` claimable gate, `cloud_detector._extract_hosts_from_json`,
  `serverless_finder.identify_serverless_type`/`check_error_signatures`,
  `metadata_paths` SSRF-vector/recon-extraction/`build_pivot_path` (incl.
  ECScape-note-only-for-AWS), `cicd_finder.load_hosts`/`probe_host_path`, and
  `cloud_report`'s remediation prioritization + section summaries.
- `attack-path-architect` — DEEPENED 2026-11-16: all 5 scripts now have a
  28-test matrix (`tests/test_attack_path_architect.py`). One real bug fixed:
  `classify_assets` raised `NameError` when a `tech_fingerprint` host absent
  from the port-scan map carried a `details` key (the tech-merge `else` branch
  referenced a `details` bound only in the `if` branch) — now reads `details`
  locally. Covered: `mitre_mapper` lookup (flat/sub-technique/unknown) +
  `map_techniques` multi-tactic grouping + SIEM/Navigator generation;
  `generate_attack_tree` `_ttp_lookup` (Enterprise/ATLAS/Unknown), `generate_paths`
  scoring (condition match, risk/WAF feasibility adjustment, stealth, WEB_APP
  fallback for HTTP-serving non-web assets, sort order), and
  `generate_chain_opportunities` (XSS+shared-cookie, SSRF+storage, dangling
  CNAME); `classify_assets` subdomain/port classification, `calculate_risk_score`
  clamping, `determine_exposure`; `map_trust.build_trust_graph`
  (source/target edge + fully-connected hosts); and `engagement_planner`'s
  authorization-defaults-false gate + markdown render.
- `recon-dominator` — FULLY DEEPENED 2026-11-16: every script now has
  regression coverage (59-test matrix in `tests/test_recon_dominator.py`). This
  bootstrap pass also added a regression for the optional Amass-not-installed
  path so it no longer recommends the stale v4 Go install command.
  `cve_lookup` version-range matching and `active_recon`'s Sitting-Ducks SOA
  delegation verdict were covered first, with two real `cve_lookup` bugs fixed
  (prose "before/prior to/< X" treated as inclusive -> false positive on the
  fixed version; trailing-period version strings). Second pass added coverage
  for the cve_lookup-feeding parsers and fixed two more bugs:
  - `js_recon.find_sourcemap_url` fallback produced `app.js?v=1.map` for
    cache-busted script URLs (always 404s, silently skips source-map
    recovery) -- now strips query/fragment before appending `.map`.
  - `tech_fingerprint.extract_versioned_components` crashed on a `None` body
    -- now guarded.
  Covered units: `extract_versioned_components` (WP ?ver= plugin/theme/core
  logic incl. the 2-agreeing-matches core rule), js_recon pure functions
  (`maybe_url`, `extract_endpoints`, `extract_api_calls`, `normalize_template`,
  `find_sourcemap_url`, `get_next_build_id`, `find_referenced_chunks`,
  `extract_script_urls`), `port_scanner.parse_service_version` (SSH/FTP/SMTP/
  HTTP-Server/X-Powered-By + OS hints) and `detect_waf`, wayback
  `categorize_urls`/`identify_removed_content`, `google_dorker.generate_dorks`,
  and `generate_report`'s markdown assembly + backtick-fence injection guard.
- `03-exploit-development` — DEEPENED 2026-11-16: the skill is a single script
  (`scripts/payload_generator.py`; the earlier "only the model-artifact scanner
  was hardened" note was stale — that scanner lives in 16-ai-llm-security, not
  here). Added a 14-test matrix (`tests/test_exploit_development.py`). No new bug
  found — the two documented syntax fixes (the Perl reverse shell's extra
  closing brace; the PowerShell `{{`/`}}` literal-brace handling) were already in
  place and are now locked by regression tests (brace-balance assertions + the
  base64 `-enc` UTF-16LE round-trip). Also covers the advertised==implemented
  payload-type invariant, per-language filtering, lhost/lport interpolation,
  PowerShell-only-on-windows gating, the windows/linux cmd_exec split, and the
  static web-shell/XSS/SQLi payload sets. The `--demo` self-test is now exercised
  by pytest (`_run_demo` returns 0).
- `16-ai-llm-security` — DEEPENED 2026-11-16: all 5 tester scripts now have an
  87-test matrix (`tests/test_ai_llm_security.py`). The scripts each ship a
  `--demo` self-test but pytest never ran them, so their pure detection logic
  had no standing regression coverage; this pass read all five adversarially and
  locked the logic-bearing units. No crash bug was found (unlike the three
  prior skills) — the scripts are well-built and demo-backed; coverage was the
  gap, not correctness. Covered: prompt_injection_tester `judge` precedence
  (canary > refusal > weak-leak > partial), list-indexing `dotted_get`,
  deterministic `mutate_payload`, `run_best_of_n` stop-at-first-SUCCESS /
  error-recorded-not-propagated / full-budget, SUCCESS-only `export_findings`
  (indirect-channel HIGH vs direct MEDIUM); unbounded_consumption_tester every
  `check_*` via a monkeypatched module-global `_post` (oversized accept/reject/
  timeout, logprobs key-substring recursion, max_tokens accept/reject, rate-limit
  header present/absent) + exposed-only `export_findings`; model_supply_chain
  `scan_pickle_bytes` GLOBAL/REDUCE detection on a real `__reduce__` pickle (note:
  `os.system` pickles as `nt.system` on Windows — both in DANGEROUS_MODULES),
  `_verdict_from_findings` escalation, `.npy` routing (object-dtype `|O` delegates
  to the pickle scanner, plain `<f8` skipped, non-npy flagged), GGUF Jinja-gadget
  detection INCLUDING the benign-template guard (a present-but-benign chat_template
  must report a finding yet NOT the substring "gadget pattern", or every GGUF with
  any template would misclassify as DANGEROUS), the `_gguf_skip_value` oversized-
  array ValueError guard, and DANGEROUS-only `export_findings`; mcp_security_tester
  full-schema-poisoning `scan_tool_schema` (caps-directive + credential-path flagged,
  lowercase "important:" benign, nested param description scanned), word-boundary
  `detect_tool_shadowing` (override-language + other-tool-name vs bare benign mention),
  `diff_against_baseline` changed/new/removed/unchanged, exact-alias
  `check_cve_fingerprint` (version-matched / patched / unversioned-name-only /
  `@scope/` normalization / unknown→[]), `check_token_passthrough` via a
  monkeypatched `send_jsonrpc` (accepted→exposed, 401→safe, error→inconclusive),
  and confirmed-only `export_findings`; rag_security_tester list-indexing
  `dotted_get`, strict float-embedding shape (`[0.1]*300` matches, int arrays and
  short arrays don't) + nested `_find_embedding_arrays`, hidden-unicode + citation-
  drift checks, `_vtuple`/`_match_branch_patch`/`check_cve_fingerprint`
  (milvus branch-patch + anythingllm exact-version), word-boundary
  `_classify_confirmation` (cannot/yesterday don't false-match), two-tenant canary
  leakage + param-swap-inconclusive, membership-inference member/decoy routing,
  and positive-verdict-only `export_findings`.
- `vuln-chain-composer` — DEEPENED 2026-11-16: all 7 scripts now have a 63-test
  matrix (`tests/test_vuln_chain_composer.py`). One real, significant bug found
  and fixed: `import_findings.normalize_finding` derived `category` as
  `vuln_type.split("_")[0]`, so the pipeline's own multi-word types normalized to
  "reflected"/"error"/"subdomain"/"open"/"public"/"attack" — none of which equal
  the "xss"/"sqli"/"takeover"/"redirect"/"bucket"/"attack_path" keys that
  `correlate.py`'s named `CHAIN_TEMPLATES` and `build_chains.py`'s
  `EXPLOIT_TECHNIQUES` both match on. Result: 6 of the ~12 named chain templates
  (and every multi-word type's specific exploit technique) silently never fired —
  verified end-to-end that two `reflected_xss` findings on sibling subdomains
  produced ZERO chains. Fixed with a canonical `_derive_category` keyword map
  (most-specific first: two-token `attack_path` before single keywords; `ssrf`
  before `xxe` so `xxe_ssrf` lands on its SSRF-primitive category), falling back
  to the original split[0] for unmapped types; single-word categories (ssrf/idor/
  blockedcve/info) are unchanged, and the `id` field (which uses `type`) is
  untouched, so existing importer tests still pass. The TODO lines in
  `generate_chain_poc` are inside the *generated* PoC scaffold (intentional
  operator-fills-in design), not a bug. Covered: `_derive_category` (every broken
  multi-word case + single-word unchanged + xxe_ssrf precedence + fallback),
  `normalize_finding` (severity upper-casing, domain extraction, chainable_as for
  sqli/xss, the unvalidated-xss-candidate → empty-chainable gate, ssrf-allowlist/
  cvehypothesis/idor `requires` tagging, cross-cutting WAF-blob requirement),
  `load_findings_from_file` (basic list, subdomain_takeover_scan shape, malformed-
  entry skipping, filename type inference); correlate's evidence helpers
  (`get_parent_domain`, `_significant_tokens`, `_credential_evidence_present` real-
  credential-vs-username, `_cloud_metadata_evidence_present`,
  `_auth_system_evidence_present`, `_agent_enables_precondition` reachable+overlap,
  `_redirect_unlocks_ssrf` named-host, `_org_membership`/`_waf_bypass`/
  `_scope_violation`), `find_chains` (the XSS template now firing post-fix, and the
  confirmed/unconfirmed gate: an unconfirmed Info-Disclosure category match stays
  at the primary severity, NOT amplified — the documented CVSS-10.0-on-a-username-
  disclosure false positive), `discover_generic_chains` (capability overlap +
  exclude_pairs dedup); calculate_impact CVSS v3.1 against known vectors (9.8/10.0/
  0.0/6.1), `build_vector`, and the confidence-gated amplification (confirmed →
  rule override CRITICAL, unconfirmed → heuristic, IDOR → PR:L); build_chains
  `get_technique` (known/default/fallback) and `build_detailed_chain` (phase
  ordering, feasibility bounds, user-interaction detection); generate_chain_poc
  shell-safe `generate_curl_command` + `generate_python_poc` AST-compilability
  even with hostile chain metadata; and generate_report `get_remediation`/
  `get_vrt`/ascii diagram/HackerOne + Bugcrowd (P1/VRT) formatters.
- `web-protocol-auditor` — manual methodology skill (SKILL.md + research notes
  only, no scripts); nothing to regression-test beyond the docs themselves.
- Legacy web active testers (webapp-exploit-hunter: LFI/upload/auth/race/SQLi/
  SSRF/SSTI/XSS/WAF-bypass) — DEEPENED 2026-11-16: added a 58-test matrix
  (`tests/test_webapp_legacy_testers.py`) covering every previously-uncovered
  tester offline (each network touch goes through a monkeypatched module-global
  `http_request`, never a real socket). One real bug found and fixed:
  `race_tester.main()` clamped the test burst to `max(2, min(threads, 50))` but
  the PoC-generation loop reassigned `threads = args.threads`, so a `--threads
  500` run tested with 50 while its xargs PoC and report meta claimed 500 (and
  `--threads 1` tested 2, PoC said 1) — the reproduction never matched the
  tested concurrency. Fixed by extracting pure `_clamp_threads()` used for both
  the burst and the PoC/meta. Covered: race `analyze_results` (multi-success,
  unique-body inconsistency even when `expect_single_success` is False,
  all-success-no-rejection, status distribution, SCENARIOS integrity) +
  `send_parallel_requests` ordering + the clamp bounds; idor `detect_id_type`/
  `generate_test_ids` (numeric incl. base64/hex encodings, UUID last-segment,
  slug)/`replace_id_in_url` (query + `path:` marker) + horizontal IDOR
  detection (different-200-body flagged, error-page body not) — note the
  documented aggressive heuristic that ANY encoding-shaped test ID returning
  200 flags regardless of body; ssrf `is_ssrf_param` + `test_ssrf` (metadata
  AccessKeyId → CRITICAL, localhost, clean → none); ssti reflection gate,
  polyglot, Jinja2 fingerprint via `49`, engine-error confirmation, and a
  clean-negative polyglot (engine names like "erb" hide inside ordinary words —
  "verbatim" false-positives the substring check, so clean bodies must be
  chosen carefully); waf `_looks_blocked` (status/body/transport-error) +
  `_looks_passed_and_reconstructed` + parameter-pollution differential
  (blocked-baseline-required discipline); lfi `is_lfi_param`,
  `_extract_referenced_path`, `parse_proc_net_tcp` (0100007F:0539 →
  127.0.0.1:1337, port-0 skip, dedupe), `_inject_param` (note urlencode
  escapes the `/` in traversal payloads), `test_lfi` passwd-read → CRITICAL;
  upload `build_multipart_body`, `extract_upload_path` (JSON + Location),
  `check_execution` (executed / accessible-not-executed / 404 → None), the
  stdlib FastCGI record/name-value encoding (8-byte alignment, 4-byte length
  form), and `detect_php_handler_stack` (nginx guess + PATH_INFO-permissive
  behavioral probe); xss `detect_reflection_context` (attribute/script/body —
  a quote before the canary classifies as attribute first) + candidate shape
  (unvalidated/INFO/low-confidence, encoded reflection not flagged); and the
  auth `decode_jwt_part` / sqli `detect_sql_errors` pure helpers (MySQL's
  pattern needs "MySQL" after "SQL syntax" — the Generic table catches the
  bare phrase first). auth_tester/sqli_tester network paths and
  generate_poc/vuln_report remain covered only by their earlier targeted tests.
- **Adaptive WAF-evasion retry for sqli_tester/xss_tester (2026-11-16):**
  capability add, not a bug fix. Generalizes `16-ai-llm-security`'s
  `prompt_injection_tester.run_best_of_n`/`mutate_payload` pattern (mutate,
  retry, stop at first success) into the two web injection testers that most
  obviously benefit from it: previously, a payload that got caught by a WAF
  simply produced no finding for that parameter, with no distinction between
  "genuinely not vulnerable" and "vulnerable but filtered." Both testers now
  escalate automatically, but ONLY when a response actually looks
  filtered/blocked (new `_looks_blocked`, duplicated locally in each script
  rather than added to the byte-synced `_common.py` — see each script's own
  docstring note); a parameter that produces no signal at all is left alone
  after one attempt, exactly as before, so this adds capability without
  adding noise.
  - `sqli_tester.py`: `test_error_based` retries a blocked payload with up to
    `--max-mutations` (default 2, 0 disables) syntax-preserving WAF-evasion
    mutations — `_mutate_case` (keyword case-randomization, e.g. `UNION` ->
    `UniON`), `_mutate_inline_comment` (keyword-splitting/MySQL versioned
    comments, e.g. `UNION` -> `/*!50000UNION*/`), `_mutate_whitespace`
    (space-to-inline-comment substitution) — the same technique family as
    sqlmap's `randomcase`/`space2comment` tampers. Every mutation attempt
    derives fresh from the ORIGINAL payload (never compounds), matching
    `mutate_payload`'s own convention. A confirmed finding via evasion is
    marked `waf_evasion_used: true` with a full `attempts` trail (attempt
    number, payload variant, status, blocked flag) so nothing is hidden.
  - `xss_tester.py`: `test_xss_payloads` now auto-escalates to the existing
    `waf_bypass` payload category when context-specific payloads are all
    filtered/blocked and none are confirmed — previously this category only
    ran when the operator passed `--waf-bypass` by hand. The flag still
    works as an explicit unconditional override. An auto-escalated finding
    is marked `auto_escalated: true`.
  - Added 22 tests to `tests/test_webapp_legacy_testers.py` (webapp legacy
    matrix: 60 -> 82): block-detection true/false/transport-error cases for
    both scripts, all three SQLi mutation primitives (including the
    keyword-preserving and no-keyword-noop cases), the fresh-from-original
    mutation convention, and — the core behavior under test — a blocked
    baseline whose mutation confirms a real finding, a clean parameter that
    triggers exactly one request (no wasted escalation), `--max-mutations 0`
    reproducing the old single-attempt behavior exactly, the mutation budget
    terminating cleanly and moving to the next payload, XSS auto-escalation
    firing/not-firing correctly, and `--waf-bypass`'s explicit-override
    behavior staying intact.
  - Full suite verified: **588 tests + 73 subtests passed** (up from 566 + 73
    before this change); Ruff and compileall clean on the changed files.
    All new target-facing tests are mocked; no live target was contacted.
- **New capability: multi-step workflow (sequence) testing (2026-11-16, new
  script `workflow_tester.py`).** Every tester in this skill, before this,
  probed exactly one endpoint/parameter at a time — nothing built a
  sequence out of what the crawler already recorded, so a whole bug class
  (steps reachable out of order: skipping payment in checkout, skipping
  email verification, reaching a completion page without the prior steps)
  was structurally invisible to the pipeline. The new script discovers
  candidate multi-step business flows from `crawler.py`'s own output using
  two independent, purely-offline signals:
  - `build_form_chain_graph`/`find_linear_chains`: a form found on page A
    whose action targets page B (`forms[i]["found_on"]` -> `forms[i]["url"]`)
    is a real "A leads to B" edge; the graph walker follows only truly
    linear (unbranching, 2+ step) paths and stops cleanly at a branch point
    or a cycle.
  - `group_endpoints_by_step_prefix`: URLs sharing a path prefix recognized
    as a workflow (checkout/signup/onboarding/register/wizard/setup/verify/
    activate/enroll/apply/invite), ordered by an explicit step number first
    (`step2` before `step3`), then a start/mid/review/confirm keyword rank,
    crawl-discovery order as the final tiebreak. A real ordering bug was
    caught and fixed during development: the first version made an
    explicit step number the PRIMARY sort key, so a numberless `start`
    sorted AFTER a numbered `step2` — keyword rank must dominate, with the
    number only breaking ties within the same rank.
  - `test_step_skip` sends exactly ONE GET per step after the first,
    directly at that step's URL — never a form submission, never
    progressing or completing the flow itself (this tool needs no write
    gate; it's read-only by construction). `classify_step_access` treats a
    redirect to an earlier step/login, a 401/403, or a recognized "complete
    the prior step"/session-expired phrase as the workflow's own
    enforcement working (not a finding); an ordinary 200 is reported ONLY
    as an unverified CANDIDATE (INFO/low confidence, `validated: false`) —
    the same confirmed-vs-candidate discipline the api-breaker deepening
    pass established for BOLA/BFLA/JWT (a bare 200 is a lead, never proof
    the page lacked real state validation).
  - New `tests/test_workflow_tester.py`: 34 tests covering the step-rank
    heuristic (including the caught ordering bug), path-prefix grouping
    (single-match-isn't-a-workflow, non-workflow paths ignored, distinct
    prefixes not merged), the form-chain graph (self-loops/missing fields
    ignored, branch points stop the chain, cycles terminate instead of
    hanging), `discover_workflows`'s dedup when both signals land on the
    identical sequence, every `classify_step_access` boundary, and
    `test_step_skip` never probing step 0 and never sending anything but
    GET. Documented in `skills/webapp-exploit-hunter/SKILL.md` as step 4k.
    CLI-docs: 10 skill docs / 97 command references / 59 CLIs (up from
    95/58). No live target was contacted; this is a purely offline/mocked
    addition like every other script in this skill's test matrix.
- **Proof-of-impact as the default: baseline-exclusion fixes for
  ssrf_tester.py and ssti_tester.py (2026-11-16).** Real, pre-existing
  false-positive bugs, found while generalizing the "a bare pattern match
  isn't proof until something distinguishes it from the baseline" rule
  the api-breaker deepening pass established for BOLA/BFLA/JWT (and that
  `sqli_tester.py`'s `test_error_based` already used for its own
  `baseline_error_patterns` exclusion):
  - `ssrf_tester.py`: `SSRF_SUCCESS_PATTERNS["localhost"]` includes a bare
    `r"<html"`, and `"internal_file"` includes bare `r"PATH="`/
    `r"HOSTNAME="` — all three match virtually every ordinary, non-
    vulnerable HTML response. The pattern-match detection path never
    checked the UNMODIFIED baseline response for the same pattern, so a
    target with a normal HTML page got "SSRF HIGH/CRITICAL" on nearly
    every tested parameter regardless of whether anything actually
    happened. New `detect_ssrf_indicators(body)` returns every pattern
    hit (not just the first); `test_ssrf` now computes a
    `baseline_signatures` set once and only counts a `(category,
    pattern)` pair as evidence when it's absent from that set. Confirmed
    findings are marked `confirmed_against_baseline: true`.
  - `ssti_tester.py`: `fingerprint_engine` never fetched a baseline at
    all — if an engine's expected output (`MATH_MARKER = "49"` for
    Jinja2's `{{7*7}}`) happened to already appear on the unmodified page
    for an unrelated reason (a price, an age, a street number), every
    request was confirmed as CRITICAL SSTI regardless of execution. The
    module's own `MATH_MARKER` docstring already named this exact risk
    ("reduce false positives") without anything checking for it. New
    `_baseline_response()` fetches one baseline per call (GET re-fetches
    the exact crawled URL unmodified; POST has no preserved original
    value here, so an inert placeholder is submitted instead) and both
    the expected-output and engine-error-message checks now require
    absence from that baseline.
  - Added 5 tests to `tests/test_webapp_legacy_testers.py` (82 -> 87): the
    ordinary-HTML-baseline false positive for SSRF now returns `[]`, a
    genuine new-relative-to-baseline leak still confirms,
    `detect_ssrf_indicators` returning every category's hit; for SSTI, a
    page returning the SAME engine error for every request (including
    baseline) no longer confirms, MATH_MARKER already present on the
    baseline page no longer confirms, and the existing
    `test_engine_error_message_also_confirms` was corrected to give a
    clean baseline (it previously returned the identical error for every
    call including the baseline fetch, which the fix now correctly
    rejects — the old test's premise was itself accidentally verifying
    the bug, not the feature). No live target contacted.
- **N-role authorization matrix for authz_tester.py (2026-11-17).** New
  capability, not a bug fix. `--token`/`--token-b` can only ever test two
  identities; real RBAC bugs often only show up between a *specific* pair
  of roles in a larger hierarchy, and the single-token BFLA check has no
  way to tell "the admin legitimately reaching `/admin`" apart from "a
  low-priv user escalating to `/admin`" since it doesn't know whether its
  one token IS the admin. New repeatable `--role NAME:TOKEN` (declared in
  ascending privilege order, lowest first; an empty TOKEN declares an
  explicit anonymous role at that position) plus pure `parse_role`/
  `build_role_matrix` helpers and two new testers:
  - `test_bola_matrix`: generalizes the original's "User A's objects,
    tried as User B" to however many named roles are supplied — for every
    role that can read an object, every OTHER role in the matrix is
    cross-tested against those same object IDs. A lower-ranked role
    reading a higher-ranked role's object (a genuine privilege-escalation
    direction) is marked `critical`; the reverse direction is still a real
    BOLA bug but a less surprising one, marked `high`. Deliberately scopes
    to the original's Phase 1+2 (the real cross-identity crossing); Phase
    3's hardcoded-resource-path probing (which never established
    ownership either) is not generalized here — left for a follow-up.
  - `test_bfla_matrix`: probes every role against every admin-pattern
    path, but — unlike the single-token original — the HIGHEST-ranked
    (last-declared) role succeeding is treated as expected and not
    reported; only a lower-ranked role succeeding is a candidate, with
    severity scaling by rank gap (rank 0, e.g. an explicit anonymous
    entry, succeeding is the worst case).
  - `test_bola`/`test_bfla` and `--token`/`--token-b` are completely
    unchanged — the matrix path only activates when `--role` is actually
    used (mutually exclusive with `--token`/`--token-b`; needs >= 2 roles).
  - Added 18 tests to `tests/test_api_breaker.py` (82 -> 100): `parse_role`
    boundary cases, `build_role_matrix` rank/cookie-isolation, the BOLA
    cross-role severity-by-direction case and the no-leak/too-few-roles
    cases, the BFLA top-rank-never-flagged case and the severity-scales-
    with-rank-gap case across 4 roles, and CLI dispatch/validation
    (mutual exclusivity, minimum-role-count, `--role` output correctly
    populating `meta.roles` vs. the unchanged empty-list 2-role mode).
    Full `test_api_breaker.py`: 100 passed + 29 subtests. Ruff, compileall,
    and CLI-docs (10/98/59, up from 97/59) pass. No live target contacted.

## Browser auditor (`webapp-exploit-hunter/scripts/browser_security_auditor.py`)
The four browser bullets in the closeout checklist were resolved on 2026-11-16:

- **Request policy / mutating GETs:** every routed same-origin GET/HEAD request
  now checks the state-changing path patterns, not just crawler links. Such
  requests are blocked unless they are the exact canary-bearing, in-scope
  document navigation from an explicitly requested `--submit-forms` probe.
  Local Chromium coverage proves an unsolicited `/account/logout` GET is
  blocked and an authorized GET form with its marker is submitted. Other active
  query/fragment probes still run.
- **Form grant scope:** a one-shot grant matches the method, exact allowed
  origin, path, action query (exact for POST; retained action parameters for
  GET), top-level document navigation, and unique marker in the submitted
  query/body. Same-path XHR/fetch cannot consume it. Unit tests cover wrong
  method/path/query/body; a loopback Chromium fixture submits both GET and POST.
- **WebSocket compatibility:** root `requirements.txt` sets the supported floor
  at Playwright 1.48.0. Official Python API docs mark
  `BrowserContext.route_web_socket` and `WebSocketRoute.close` as introduced in
  1.48. A real loopback fixture passed on Playwright 1.48.0 / Python 3.13.17
  with its declared `greenlet==3.1.1`, and the repository suite exercises the
  current Playwright 1.65.2 install. The first minimum-version probe exposed a
  sync-API hang when calling `WebSocketRoute.close()` inside the route callback.
  The final policy avoids that nested call: routing creates a local mock, never
  calls `connect_to_server`, and the init script closes the page-side mock after
  it opens. Integration asserts the close event and zero upstream handshakes.
- **Storage-state scope / PSL:** localStorage is filtered by exact canonical
  origin. Cookie domains must exactly equal an explicitly allowed hostname;
  parent cookies are accepted only when the parent host itself is explicitly
  allowed. A cookie `url` must have an allowed origin and match any supplied
  domain. The code no longer approximates a public-suffix list. Regressions
  cover `.co.uk`, explicit parent scope, out-of-scope cookie URLs, mismatches,
  and malformed cookie/origin arrays.

The earlier SPA timing item is resolved by the best-effort network-idle wait
and `--settle-ms` described below.

### Previously documented limitations outside this closeout

- URL paths, page titles, cookie names, and storage key names are retained in
  some report fields; query/fragment strings and values/bodies are omitted.
- `max-pages` counts crawled documents, not temporary probe/form pages. The
  form-submission metric counts attempts, not verified network writes.
- Form indices are re-read after navigation but can still be affected by pages
  that reorder their controls dynamically.

These are pre-existing bounds outside the exact browser checklist; they were
not expanded into new review tasks in this pass.

## Active-testing doctrine — intentional gates (keep, document, invoke; don't drop)
The injection scanners (SQLi/SSRF/SSTI/LFI/upload/race/WAF/reflected-XSS) still
send active requests. Intentional write-probe gates:
- `api-breaker/scripts/authz_tester.py` — BOLA/BFLA default GET; mutating methods
  and method-override need `--allow-mutation-write`.
- `api-breaker/scripts/mass_assignment.py` — POST/PUT/PATCH need
  `--allow-mutation-write`; imported write endpoints need an explicit trusted
  `--api-base`; imported cross-origin endpoints are skipped.
- `api-breaker/scripts/schema_builder.py` — GraphQL mutation-BOLA writes need
  `--allow-mutation-write` plus a target ID; ordinary schema/GraphQL query
  probes remain active. GraphQL CSRF GET/form mutation probes require `--cookie`
  and `--csrf-test-id`; they can change data and are candidates until browser
  cookie policy and state changes are verified. Imported endpoints require
  explicit `--api-base` and are origin-scoped.
- `api-breaker/scripts/logic_tester.py` — business-logic POST/PUT/PATCH payloads
  and concurrent race probes remain active without a separate write flag when
  selected. Imported endpoints require explicit `--api-base` and are scoped;
  candidate responses need persistence/read-back confirmation.
- `api-breaker/scripts/rate_limiter.py` — burst, path/method, and GraphQL
  batching probes remain active. Explicit `--api-base` scopes imports;
  `--count` is bounded from 1 to 1000.
- `browser_security_auditor.py` — `--active` (URL probes), `--submit-forms`.
- `web-cache-auditor` — `--probe-unkeyed`, staging replay adds `--confirm-cache-replay`.
- Generated web PoC replays the supplied finding payload/method (no invented
  fallback probe set).

The explicit API mutation gates are the clearest friction with "don't be
passive": authorized workflows must document and pass them, not silently skip
write testing. `logic_tester.py` remains the separate active business-logic
path without a write flag; its selected targets must still be authorized and
its unverified candidates require read-back before being reported as findings.

Bootstrap preflight checks dependency readiness only. It does not replace
authorization/scope checks and does not change any active payload, API write,
browser `--active`, or `--submit-forms` behavior.

## Browser auditor — verified by integration run (2026-11-16)
- **Working:** missing-header/cookie-flag/sensitive-storage findings; off-origin
  request blocking + counting; WebSocket interception (no upstream connect);
  active query DOM-XSS (svg+img); active fragment DOM-XSS (svg fired via both
  `innerHTML` and `document.write` in the tested Chromium); form submission with
  marker execution; `/logout`-style links skipped.
- **Fixed in `fb1a102` commit:** (1) `redact_url` now reports `ws://`/`wss://`
  socket URLs instead of `[invalid-url]`; (2) the wildcard-postMessage hook now
  uses `Object.defineProperty(window, 'postMessage', …)` — the previous
  `Window.prototype.postMessage` reassignment silently no-ops in Chromium, so
  that finding never fired.
- **Hardened (2026-11-16, second browser pass):** (1) the form-POST one-shot
  grant is now bound to a `document` navigation — a racing same-path xhr/fetch
  POST can no longer consume it (verified: real POST form submit is a
  `document` request); (2) the request budget now counts only requests actually
  let through, so an off-origin-heavy page can't exhaust it with blocked
  requests, and WebSockets are counted (`websockets_seen`) and the recorded
  socket list is bounded; (3) cookie suffix-match now rejects bare single-label
  (TLD-like) parent domains while still allowing a registrable multi-label
  parent (not a full public-suffix check; routing still enforces exact origin).
- **Hardened (2026-11-16, third browser pass — img-variant + SPA settle):**
  (1) fragment probes now ship in BOTH execution variants (svg-onload AND
  img-onerror) instead of svg-only — svg-onload via innerHTML is engine/version-
  dependent, img-onerror on `data:,` is the cheap cross-engine fallback; the
  query probes already paired them. Verified live: the Chromium-gated
  integration test gained a `/frag` fixture (decoded `document.write` sink,
  linked from home so the crawler reaches it) and asserts a fragment-source
  dom_xss finding end-to-end. (2) Form probes now try svg first and fall back
  to the img variant only when svg did not execute (a success on either is the
  same finding, so no budget is wasted double-submitting after a confirmation);
  budget check runs per submission. (3) `_navigate()` adds a best-effort
  `networkidle` wait (capped at 4× settle, silently skipped when it never fires
  on polling/websocket pages) plus a new `--settle-ms` flag (50-5000, default
  250 — behavior unchanged by default) so operators can wait longer for
  async-rendered SPA DOM/forms. SKILL.md documents the variants and the flag.

## Closeout checklist (all six items complete)

1. **API response-preview redaction — closed 2026-11-16.** Reviewed every
   `response_preview` emitter in `auth_analyzer.py` (1), `logic_tester.py` (5),
   and `mass_assignment.py` (2). All call the shared `safe_response_preview`
   helper already used by `authz_tester.py`; no raw emitter or new bug was
   found. Regression fixtures include email, API-key, bearer, and password
   values and assert those values are absent from emitted previews.
2. **Rate-limit bypass/batching — closed 2026-11-16.** Reviewed active burst,
   forwarded-header/path mutations, and GraphQL batching. Found and fixed a
   validation-order bug: invalid worker/count values now fail before even the
   sequential baseline request. Added a three-case regression asserting zero
   network calls for invalid input. Selected active probes and their defaults
   are preserved.
3. **Business-state race read-back — closed 2026-11-16.** Candidate evidence
   stays distinct from confirmed state impact. Integer JSON-pointer values
   retain exact precision; 202 responses do not qualify as a completed
   synchronous control; state reads request cache bypass and suspected cache
   hits/stale data suppress comparative claims. Regressions cover large
   integers, 202 controls, cache metadata, and no-cache headers. All three
   active payload cases and ten-request bursts are retained. The optional
   read-back still requires an operator-selected disposable object and a truly
   read-only route.
4. **API report input shapes — closed 2026-11-16.** The report loader handles
   one finding object, aggregate `findings` objects, and arrays; it warns and
   skips malformed roots, invalid containers, non-object entries, unreadable
   files, and corrupt JSON. Report rendering normalizes malformed type,
   severity, URL, method, and path values instead of crashing. Regression
   tests cover each supported shape and malformed inputs.
5. **Bootstrap / Amass — resolved and closed 2026-11-16.** `amass` is not in
   `GO_TOOLS`. The manual-tool note records that v5 dropped enum's one-shot
   `-o`/`-json` output, the documented `subs` readback command changed between
   v5.x releases, and an April 2026 v5.1.1/`develop` report says `-brute`/`-w`
   are accepted but unused by the engine (with no acknowledged fix). Revisit
   only when the installed `amass --help` and `amass enum --help`, visible
   wordlist guesses on an owned-domain fixture, and a reliable structured
   output path have all been verified. Bootstrap's install-and-verify behavior
   for tools it already manages was not changed. No repository-wide
   package-manager or pinning project is part of this closeout.
6. **Browser auditor — closed 2026-11-16.** The four listed risks are resolved:
   all routed in-scope GET/HEAD requests check state-changing path patterns;
   form grants bind method, origin, path/query, document navigation, and a
   unique submitted marker; WebSocket mocks have no upstream connection and
   are closed page-side with coverage on Playwright 1.48.0 and 1.65.2; storage
   cookies/localStorage are filtered by explicit origin/host without a PSL
   suffix approximation. Loopback Chromium tests exercise unsolicited GET
   blocking and canary-bearing GET/POST form submissions; unit cases cover
   invalid grant and storage inputs. No new browser checklist item was added.

## Standing constraints (don't re-introduce)
- Preserve the active-testing doctrine: for explicitly authorized, in-scope
  assessments, run the selected bounded payload probes and form submissions
  documented by the skill. Do not silently turn active testing into passive
  observation. Keep explicit gates for destructive or state-changing actions
  where they are documented, and do not add a new gate that disables the
  requested probe by default.
- Bootstrap checks every tool it currently manages on each run, automatically
  installs missing managed tools, and verifies availability before work starts.
  Strict or narrow preflight stops dependent work when any required tool is
  still unavailable. Missing-tool installer, verification, and PATH-refresh
  behavior is covered with regression mocks; the Windows PowerShell interpreter
  command is `python3`. Amass stays outside managed tools under item 5.
- HTTPS verified by default; `CATUS_INSECURE_TLS=1` is the only opt-out.
- Cross-origin redirects (incl. HTTP→HTTPS) are blocked by design — pass the
  final authorized origin when canonicalization crosses origins.
- Claude permission prompts preserved by default; `--dangerously-skip-permissions`
  stays an explicit operator choice.
- Author identity for commits: `FelixCatus <18648889+Felix1Catus@users.noreply.github.com>`.

Windows details to preserve: use `python3` for the interpreter command in
PowerShell; keep `hooks/hooks.json` LF-only; and reference the actual
`hooks/hooks.json` path in plugin metadata and bootstrap checks.

## Final closeout entry — 2026-11-16

The six-item closeout checklist above was re-read top to bottom after the
changes. Every item is marked closed, and the section contains no indefinite
status wording. The scope stayed on those six items; other skills recorded as
deepened or doc-only were not reopened.

- Code, regression, and audit documentation commit
  `6f8c4af3646043294682520d9ca551560a01f928` was pushed to `origin/main` after
  the prior local API-race commits `7f26773c848cf6ebcedc7adf046b79fb17d386fe`
  and `f5bff3d96aa53ac32693fdcca3983107bf01c459`.
- Verification: 553 full-suite tests passed; the focused API-breaker matrix
  passed 82 tests + 29 subtests; two Playwright 1.48.0 integration checks
  passed; Ruff, compileall, shared-helper sync, CLI-docs (10 / 95 / 58), and
  `git diff --check` passed. The default Playwright 1.65.2 browser fixtures
  also passed inside the full suite.
- **Explicit deferrals:** Amass is excluded from managed installation because
  its v5 CLI/output surface and wordlist behavior require checks against the
  actually installed version (item 5); no live external-target testing was
  performed because this repository closeout supplied no named authorized
  target. These are documented bounds, not active checklist work.
- The final metadata commit and its `origin/main` verification are recorded by
  the GitHub `main` tip reported in the session closeout.

## 2026-11-17 — Improvement #5: shared target knowledge v1 (Codex)

Surveyed the established workflow, mailbox ownership, fingerprint output,
SQLi baseline/mutation flow, importer normalization, and standalone skill
loading. Claude's #4 files (`authz_tester.py`, `tests/test_api_breaker.py`)
were not edited. Tasks #6–#8 were not started.

- New cross-cutting `scripts/target_knowledge.py`: stdlib SQLite, explicit
  engagement namespace, exact canonical HTTP(S) origins, resource/context
  keys, source/confidence/timestamps/TTL, query CLI, concurrent transactions,
  and explicit errors for incompatible/corrupt databases. No global default
  database or per-skill vendored state module.
- Exactly three CLI integrations: recon `tech_fingerprint.py` publishes
  observed stack/versions/WAF; webapp `sqli_tester.py` reuses recent clean
  error-based payload outcomes for identical baseline/request/auth contexts,
  records access-denial/rate-limit signals, and exposes recon context;
  composer `import_findings.py` enriches findings with current observations
  without changing severity, confidence, or chain capabilities.
- Failed-payload reuse has a 15-minute TTL and always takes a fresh baseline.
  No auth denial, HTTP 429, transport/server failure, or WAF block counts as
  a clean negative. `--knowledge-refresh` bypasses reuse and invalidates an
  obsolete failure after a changed result. Request headers/query values,
  baseline bodies, original values and payloads are hashed rather than stored.
  Public metadata/path information is still engagement-sensitive; the store
  is local trusted state, not an authorization boundary or encrypted vault.
- `scripts/TARGET_KNOWLEDGE.md` and the three skill guides document opt-in
  flags, query examples, standalone behavior, privacy, TTL, and deferrals.
  New `tests/test_target_knowledge.py`: **30 tests + 29 subtests**, offline,
  including concurrent processes, namespace/origin/role/expiry boundaries,
  refresh-positive invalidation, secret exclusion, and all three integrations.
- Validation: full pytest **667 passed + 102 subtests passed**; Ruff, full compileall,
  common-sync, CLI-doc checker (**10 skill docs / 101 references / 59 CLIs**),
  and final diff whitespace checks passed. No live targets were tested.

Deferred in v1: cloud/API automatic integrations, other SQLi modes and other
testers, detailed Retry-After/window modeling, event history/purge UI, and
tasks #6–#8. Subsequent addenda below record follow-up integrations and tasks.
Technology fingerprints and HTTP status signals remain observations;
no-new-error is not proof of non-vulnerability.

## 2026-11-17 — Shared target knowledge v2 integrations (Codex)

Extended the v1 store with `cloud_provider` and `api_inventory` kinds plus
scoped `KnowledgeStore.forget()` for explicit refreshes. `cloud_detector.py`
optionally reuses positive provider observations for one hour; it stores
provider/service labels, not resolved IPs, and marks reused hosts with IP
unknown. `api_discovery.py` optionally reuses sanitized positive endpoint
inventory for 15 minutes, scoped by engagement, exact origin/base path, and a
digest of request headers. A hit skips only common-path and same-origin JS
discovery; GraphQL/OpenAPI/method/legacy checks still execute. Empty results
are never cached. Both integrations are disabled unless DB and engagement are
explicitly supplied; refresh deletes only the selected observation and runs
fresh discovery.

`tests/test_shared_knowledge_pipeline.py` adds helper, engagement/context/TTL,
refresh, sanitization, and CLI reuse/refresh coverage. API cache entries omit
endpoint URLs, query values, response bodies, and raw headers; cloud entries
omit IP addresses. Deliberately deferred: other cloud/API stages, reuse of API
inventory by vulnerability-specific tests, automatic auth-role inference,
shared state for remaining scripts, event history/purge UI, and remote
knowledge synchronization. Focused tests passed **41 tests + 29 subtests**;
full pytest passed **816 tests + 125 subtests**. Ruff, compileall,
`check_common_sync.py`, `check_skill_cli_docs.py` (**10 docs / 109 references /
60 CLIs**), and final diff checks pass. No live targets were tested.

## 2026-11-17 — Unattended Claude/Codex supervisor v1

Implemented `tools/agent-supervisor/supervisor.py`, its disabled example
configuration and README, and `tests/test_agent_supervisor.py`. Updated the
mailbox README to distinguish shared runtime state from historical Markdown
inboxes. Claude's independent design review is recorded at `fa479ef`.

The stdlib controller uses one transactional SQLite queue/event stream under
the Git common directory, so linked worktrees see the same tasks and ownership.
Specs require explicit operator approval; file-set claims, fencing tokens,
leases, dependencies, stop/recovery, checkpoints and append-only sequenced events
are durable. No stale-lease automatic reassignment occurs. Quarantined claims
require operator-confirmed process cleanup before retry/cancel. Historical
mailboxes are not overwritten; the runtime transcript is a generated view.

One author task executes at a time in v1, using the opposite model for review.
Authors edit isolated worktrees outside `.git`; reviewers use independent local
clones with their own Git metadata. The controller bounds worker/check/Git
runtime, records explicit permission settings, commits as FelixCatus, validates
claimed files before and after commit, checks committed whitespace, and sends
the complete bounded binary-capable diff for exact-base/exact-candidate review.
A separate integration worktree validates before a non-force push. Changed
remote main invalidates integration; ambiguous/already-applied pushes block a
blind retry. POSIX groups and Windows kill-on-close jobs provide lifecycle
cleanup. JSON stdout is separate from stderr. No global bypass flags are used.

Validation: **39 dedicated tests + 20 subtests** cover atomic/concurrent claims,
quarantine, stale ownership, dependencies, strict reviews, CLI permissions,
process timeout/stop/descendant cleanup, stderr separation, local Git remotes,
repair, hook-injected/out-of-scope files, whitespace, changed main and push
acknowledgement reconciliation. Final full pytest: **724 passed + 122 subtests passed**. Ruff,
compileall, common-sync and CLI-doc checks (**10/102/59**) passed.

Real CLI smoke tests passed in both directions using a disposable local Git
remote: Codex author -> Claude reviewer, then Claude author -> Codex reviewer.
The reverse test exposed `.git`-nested worktree edit restrictions and linked
Git metadata visibility; these were fixed with outside-metadata worktrees and
independent reviewer clones, without bypassing permissions. Claude's first code
review rejected `ce9be40` with concrete findings; fixes are in `f7206db`.
Independent Claude CLI review approved implementation `ceab93c7421c0423f9af847d49da69ac5ff0cf01` with no remaining findings.

The committed example remains disabled. The real project queue is empty; no
background service or task #6–#8 was started. Runtime task approval is explicit.
This is local trusted-repository lifecycle coordination, not a hostile-code
sandbox, an encrypted log store, or a promise of a Codex USD spending cap.
Parallel author execution, automatic orphan PID killing, cloud synchronization,
and hidden-session recovery are not implemented; see the README's limits.

## 2026-11-17 — Shared-goal live session visibility

User chose one Codex desktop terminal view for both providers. Added
`tools/agent-supervisor/live_view.py` plus `watch`, `sessions` and bounded
read-only `demo` commands. Claude workers now use named persistent JSONL
sessions; the backend accepts both historical JSON and streamed result
envelopes without weakening author/reviewer failure or SHA validation.
The view groups native Codex/Claude session IDs, roles, heartbeat state,
messages/tools and task progress under the same goal. Native resume commands
are emitted only for UUIDs. Heartbeat marker writes are atomic; stale markers
are shown as unknown. Structured-only reviewer results show completed status.

A real read-only simultaneous demonstration passed for both providers on goal
`shared-session-visibility`, without modifying the checkout. The app API opened
the terminal panel but exposes no terminal-input method; user was given the
one-time `python3 tools/agent-supervisor/supervisor.py watch` paste. No Windows
terminal UI input automation was used. Watch never launches tasks; Ctrl+C
closes only the view. Demo obeys the stop switch and bounded model runtime.

Validation: **735 full-suite tests + 122 subtests passed** before final cosmetic
review fixes; **13 view tests pass** on the fixes. Final focused rerun: **52 passed + 20 subtests passed**.
Ruff, compileall, common-sync, CLI-doc checker (**10/102/59**) and diff checks
pass. Independent Claude review identified/fixed the structured-result status
and atomic-marker display issues. Independent Claude CLI review approved `f152ba0554a9c72a8892e9f8cf5a73f428a83abf` with no remaining findings.

Prepared private, unqueued task drafts under Git-common-dir/agent-coordination/
drafts: #6 author Claude/reviewer Codex; #7 author Codex/reviewer Claude,
depending on #6; #8 author Claude/reviewer Codex, depending on #6 and #7.
V1 still uses one author at a time. None of #6–#8 started in this checkpoint.


## 2026-11-17 addendum — Improvement #7: guarded executable chain v1

Added `skills/vuln-chain-composer/scripts/execute_chain.py` for one supported
chain only: confirmed `redirect_into_allowlist` -> SSRF. `build_chains.py`
emits a plan only when both distinct finding IDs, endpoint URLs, and parameter
names are present; correlation now preserves those fields. `generate_chain_poc.py`
creates a network-free Python preview, comments curl commands out of its shell
preview, and exports the plan JSON. Active execution requires `--execute`,
explicit source origins and destination origin, a destination URL, and a
response marker. It sends at most two GETs, disables automatic redirect
following and ambient proxies, checks Location scope before step two, stops
on failure, and emits response status/hash and finding provenance without
bodies or query values.

Regression coverage in `tests/test_vuln_chain_composer.py` now totals 73 tests,
including localhost success, dry-run zero traffic, redirect-out-of-scope,
non-redirect stop-on-failure, preflight scope rejection, and malformed or
unconfirmed plan rejection. No external target was contacted. Deliberately
deferred: arbitrary chain types, mutations, non-GET actions, browser/user
interaction, imported-payload execution, auth workflows, dynamic cross-host
state, and chain-specific remediation execution. Validation: **790 tests + 122
subtests passed**; Ruff, compileall, common-sync, CLI-docs (**10/104/60**), and
final diff checks pass. Only localhost fixture HTTP requests were sent.


## 2026-11-17 addendum — Improvement #8: evidence-linked business context

Added `scripts/context_severity.py`, a pure rubric helper that scores explicit
asset business context without inspecting vulnerability types or changing
CVSS. Context can travel on an imported finding's `business_context` object or
be supplied to `calculate_impact.py --business-context` as a versioned exact-
host asset profile. `correlate.py` preserves attached context on chain finding
snapshots; `calculate_impact.py` reports it separately as contextual severity;
`generate_report.py` renders the technical rating and contextual tier in
separate fields. The schema requires service name/purpose, classified business
criticality, data sensitivity and affected scope, evidence for those
classifications, and chain-specific `impact_evidence`. Reports retain source
and evidence and state that operator context is not independently verified.

The deterministic rubric uses only the highest documented consequence factor
(criticality, sensitivity, or affected scope), with a stated rationale. Exact
host matching prevents context bleed across sibling subdomains. A contextual
tier is assigned only for a confirmed chain; otherwise a clearly labeled
potential tier is retained. The existing technical severity, CVSS score,
vector, and severity mapping remain unchanged. Regression matrix:
`tests/test_contextual_severity.py` plus `tests/test_vuln_chain_composer.py`.
Coverage includes public-blog versus tenant-payment context, profile/schema
boundaries, exact-host isolation, artifact-to-chain propagation, CLI use,
reporting, and unconfirmed gating. Focused tests: **88 passed + 3 subtests**;
full pytest: **805 passed + 125 subtests passed**. Ruff, compileall, common-sync, CLI-docs (**10/105/60**), and final diff checks pass.

Deliberately out of scope: automatic crawling/classification of application
purpose, external model/API calls, unsupported context inference from URLs or
vulnerability types, changing CVSS or the static technical baseline, and
cross-engagement context sharing.

## 2026-11-17 — Shared target knowledge auth/rate and offline transfer

Expanded `scripts/target_knowledge.py` with role-labeled auth outcome records,
bounded rate-limit observations (status counts, numeric allowlisted rate
headers, and normalized Retry-After), and strict offline JSON bundle export /
import. Bundle import requires the same explicit engagement and exact origin,
validates each kind against allowlists and TTL ceilings, rejects expired or
malformed data, preserves provenance and expiry, and will not replace newer
local observations with older bundle rows. Bundles are local and unsigned;
transfer them only through trusted storage.

`api-breaker/authz_tester.py` publishes N-role matrix response observations
with credential headers hashed as context. `rate_limiter.py` publishes
normalized per-endpoint observations; every requested fresh rate-limit test
still runs. `webapp-exploit-hunter/idor_tester.py` displays fresh matching
auth/rate context without skipping probes. Existing finding-import enrichment
carries matching facts without changing severity or evidence confidence. No
credential or response-body persistence was added.

New `tests/test_target_knowledge_v2.py` covers bundle boundaries, role/context
separation, secret exclusion, TTL/origin/engagement checks, stale conflict
handling, N-role/rate publication, and IDOR context reuse. Network sync,
encryption, and import from untrusted bundles remain out of scope; offline
transfer is not an authenticated sync protocol. Validation: full pytest
**827 passed + 128 subtests**; Ruff, compileall, common-sync, CLI docs
(**10 docs / 111 references / 60 CLIs**), and final diff checks pass. No live
targets were tested.

## 2026-11-17 addendum — guided stateful business scenarios

Added `business_scenario.py` and opt-in `workflow_tester.py --scenario`
support for operator-authored business assertions. Scenario plans are the
default and issue no requests. Execution requires `--execute`; scenarios
containing writes additionally require `--allow-mutation-write`, fixture and
cleanup declarations, a baseline assertion, a bounded request count, and
same-origin action URLs. Each case receives fresh setup and cleanup; baseline
failure skips misuse cases while still attempting cleanup. A 429 or any
`Retry-After` header halts follow-up probes. Reports contain response statuses
and assertion pass/fail flags, not response values, and are expressly not
validated findings. Dynamic-ID capture, automatic action reordering,
cross-skill persistence, rule inference, and generalized rollback remain
follow-up work. Focused coverage: `tests/test_business_scenario.py` and the
existing workflow tests. Full validation is recorded in the audit addendum.

## 2026-11-18 addendum — dynamic values in guided scenarios

Extended scenario v1 with JSON-pointer capture of short string/integer values
from successful 2xx responses and `${name}` substitution in later same-lane
action paths, headers, JSON bodies, and cleanup. Variables are isolated between
baseline and misuse cases, held only in memory, and omitted from output; paths
URL-encode substitutions and control characters/oversized or structured
captures are rejected. Missing captures stop dependent actions and prevent
misuse cases from running when baseline setup is incomplete. HTTP error bodies
cannot supply captures or satisfy assertions. Regression coverage is in
`tests/test_business_scenario.py`; full validation is recorded in the audit
addendum.

## 2026-11-17 addendum — GET form submit controls in SQLi/XSS targets

Crawler-derived SQLi/XSS test targets now preserve named submit-button values
for GET forms, generating separate variants when a form has multiple named
submit buttons. Pentest-Ground DVWA's SQLi handlers require `Submit=Submit`;
the former target builder discarded that control and could return the form
page instead of invoking the handler. New `scripts/_form_controls.py` keeps
the URL query intact while adding the selected control. POST bodies and their
other controls are deliberately unchanged/out of scope. The isolated
regression matrix is `tests/test_get_form_submit_controls.py`. Validation and
the authorized DVWA reproducer results are recorded in the audit addendum.


## 2026-11-18 addendum — form-context coverage and evidence thresholds

The full DVWA follow-up found three more confirmed challenge modules
(command injection via actual POST form, CSRF password change via GET, and
open redirect) and confirmed stored XSS in an isolated same-origin browser
check. The first unauthenticated crawl had not exposed the authenticated
challenge menu. POST test targets now retain safe sibling controls, hidden
tokens, and distinct selected submit actions; password/file values are not
replayed as sibling form data. XSS POST probing checks the subsequent GET and
labels persistence only as a candidate. SSTI arithmetic probes now use unique
wrappers so reflected expressions cannot be mistaken for evaluation. SSRF
body-size deltas and IDOR status/body differences are candidates unless
fetch/ownership evidence exists. Focused regression results are recorded in
AUDIT.md. Remaining authenticated DVWA modules require a dedicated coverage
matrix and per-module validators; not yet claimed as tested.


## 2026-11-18 addendum — command-injection proof tester

Added `skills/webapp-exploit-hunter/scripts/command_injection_tester.py`.
It selects command-shaped parameters from crawler results, preserves POST form
context, and sends bounded `printf` marker probes only. It confirms execution
only when a formatted output marker absent from the submitted payload appears
in the response. Authenticated Pentest-Ground DVWA run confirmed the `/exec/`
POST `ip` command injection with `validated: true`. Five offline regression
cases cover payload construction, reflection rejection, form control
preservation, marker validation, and confirmation. Current full suite and
standard validation results are recorded in AUDIT.md. No API-breaker authz
files were changed.


Validation for the 2026-11-18 follow-up: full pytest **857 passed + 128
subtests**; full Ruff, compileall (`skills`, `scripts`, `tests`, `tools`),
common-sync, CLI docs (**10/114/61**), and diff checks passed. The command
injection CLI also confirmed the DVWA `/exec/` POST path with a harmless marker.


## 2026-11-18 addendum — upload handler invocation and proof

The prior DVWA upload result was not a valid negative: its multipart request
omitted the `Upload=Upload` submit control and used `file` instead of the
form's `uploaded` field. It received HTTP 200 without calling the handler. The
tester now keeps safe hidden/submit values, parses the relative upload path in
DVWA's success response, and follows only a same-origin path. Its unique PHP
marker unlinks only itself after execution. One live authorized request
confirmed execution and subsequent 404 cleanup. The generic lesson is to
replay the actual successful form controls and validate the effect at the
resource the response identifies; a status code is not a test result.
Focused upload regressions passed; final full validation passes **878 tests +
128 subtests**, with Ruff, compileall, common-sync, CLI docs (**10 / 116 / 63**),
and diff checks clean. See AUDIT.md for source links and reproduction detail.


## 2026-11-18 addendum — JavaScript and CSP challenge verifiers

Added `javascript_challenge_tester.py` for the DVWA client-computed phrase
token exercise and `csp_form_tester.py` for script-URL forms guarded by CSP.
The former computes only the documented level-specific token and sends one
request pair; its INFO finding is explicitly scoped to a training challenge.
The latter uses Chromium to submit a mock script URL from the target's
allowlist, locally fulfills the script response, and blocks all other external
requests. The live target confirmed the JavaScript challenge and CSP form
script execution with no third-party request. Dedicated regression tests are
`tests/test_dvwa_javascript_challenge.py` and `tests/test_csp_form_tester.py`.
Coverage is 14/15 deployed menu modules; CAPTCHA is the only unusable entry
because the lab is missing reCAPTCHA keys. Full validation passes **878 tests
+ 128 subtests**; Ruff, compileall, common-sync, CLI docs (**10 / 116 / 63**),
and diff checks are clean.
