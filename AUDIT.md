# Static code audit — 2026-11-15

Target: `Felix1Catus/CatusMythos-Lounge`, `main` at `73162b06b8458155cdf4113b810da3be6d8e6039`.

## Changes made

- Claude lounge sessions now preserve Claude Code's normal permission prompts by default. The explicit `--dangerously-skip-permissions` option remains available for operators who choose it. The `go.sh` Claude launch path no longer bypasses permissions by default.
- The AI/LLM HTTP helpers now return a clear missing-`requests` error instead of attempting to access `requests.exceptions` when the optional package is absent. The prompt-injection sender raises a concise dependency error that its existing caller reports.
- Corrected the bootstrap docstring: it intentionally installs optional Python dependencies and user-scoped Go tools on first plugin startup; system-level packages remain report-only.
- Network probes and generated PoCs now verify HTTPS certificates by default. `CATUS_INSECURE_TLS=1` is an explicit opt-in for authorized targets with self-signed certificates. The TLS certificate-sharing probe remains unverified because it sends no application data and must inspect invalid certificates.
- The model artifact scanner caps per-file and archive-member reads at 64 MiB, limits archive entries, streams pickle opcodes instead of materializing them, and marks truncated scans `review` rather than `safe`.
- PoC generators now quote untrusted values in generated Python and shell, terminate curl option parsing before untrusted URLs, constrain user-controlled concurrency counts, and avoid forwarding raw shell commands from findings. The shared web request helper's documentation now matches its certificate-verification behavior.
- Shell scripts now retain LF line endings in Windows checkouts. The lounge tests validate the checked-in hooks and cover the non-Linux polling fallback without relying on installed files in a user home directory.

## Web-testing expansion — 2026-11-15

- Added `web-cache-auditor` from PortSwigger research on cache poisoning, cache deception, and cache/origin URL normalization. It separates reflection from cache replay, uses inert canaries and fresh cache-busters, caps response reads, omits bodies and query values from reports, and requires an explicit flag for staging-only replay confirmation.
- Added eight stdlib regression tests covering URL validation/redaction, cache evidence, bounded reads, redirect isolation, and findings import into `vuln-chain-composer`. Updated the plugin catalog and swarm operator's surface-selection logic to use the new skill only when cacheable routes exist.
- Added a passive DOM XSS source-to-sink reviewer for inline scripts, event-handler attributes, and same-origin JavaScript. External hosts require an explicit flag, cross-origin redirects are blocked, URL query values are redacted, and downloads are bounded. Research notes point to PortSwigger and OWASP validation guidance.
- Corrected the web app skill's claim that its response-only XSS tester analyzed DOM XSS and stored XSS. Reflected payloads now remain low-confidence `INFO` candidates until browser validation; the findings importer does not make candidate XSS chain-enabling.
- Verified Python's `urllib` redirect implementation preserves caller-supplied headers. Added a credential-free HTTP(S), exact-origin redirect opener to the five network skill helper copies and routed their direct fetchers through it. AI/LLM POST probes now disable redirect following, and generated web PoCs embed the same redirect guard.
- Extended `check_common_sync.py` to detect drift in the vendored redirect helpers. Loopback regression tests prove cross-origin redirects (including a same-host different-port redirect) are stopped before the second request, same-origin redirects work, and credentialed input URLs are rejected.
- Fixed the helper-sync gate so a missing `_common.py` is a failing condition instead of a warning followed by exit code 0.
- Checked every `python scripts/...` example across all skill manuals against the real CLI `--help` output. Fixed nine stale flags across API authorization/mass-assignment/logic/report commands, chain-composer stages, and upload testing. Added `scripts/check_skill_cli_docs.py` so missing scripts and unsupported options are checked offline.
- Implemented the crawler's documented robots/sitemap discovery: literal robots routes and XML sitemap/index entries are parsed under bounds (10 documents, three index levels, 1,000 routes, 128 KiB per response). DTD/entity declarations, cross-domain entries, and entries on a different scheme or effective port are rejected. Updated the web-app guide to match actual authentication probes and available rate controls.

## Repo-wide and Windows accessibility pass — 2026-11-15

- Replaced deprecated naive UTC timestamp calls throughout the Python tools with timezone-aware UTC timestamps, keeping the existing ISO-8601 `Z` output format. Added a repo Ruff configuration targeting Python 3.8 and removed unused imports and dead local assignments found by the lint sweep.
- Fixed the SessionStart bootstrap hook to invoke `python3`, matching the executable available in the Windows PowerShell environment. Updated skill and contributor command examples and optional-dependency help text to use `python3`; documented the existing bootstrap behavior. It installs optional Python dependencies and user-scoped Go recon tools when available, and reports missing system packages without invoking a privileged package manager.
- Hardened imported API scan handling: authentication probes require an explicit trusted `--api-base`, imported cross-origin endpoints are skipped before credentials are sent, and mutating authorization/mass-assignment probes require explicit flags. API-key query values are encoded. Mass-assignment response echoes remain informational candidates until a persisted state change is verified.
- Corrected SQL error-based injection checks to ignore database error strings already present in the baseline response. The findings importer now honors recognized metadata types and skips malformed JSON roots, metadata, finding entries, and specialized result sections instead of aborting the import.
- Added the manual `web-protocol-auditor` skill for scoped HTTP desynchronization and WebSocket assessment, with primary-source research notes and explicit human review for high-risk live confirmation.
- Added regressions for bootstrap command selection, hostile imported API metadata, mutation gating, API key scope/encoding, false-positive suppression, candidate chainability, and malformed findings input.

## Remaining considerations

### Low — Claude permission bypass remains available as an explicit option

`lounge/seat_launcher.sh --dangerously-skip-permissions` intentionally bypasses confirmation prompts. Use it only in a disposable, tightly scoped environment; the default launcher now retains the permission prompts.

### Low — HTTP clients stop at origin-changing redirects

The redirect policy deliberately blocks changes in scheme, hostname, or port, including HTTP-to-HTTPS redirects. Supply the final authorized URL to the tool when a target uses a canonical-origin redirect.

## Review and verification limits

Reviewed repository metadata, plugin manifests and hook wiring, bootstrap behavior, lounge launch/state handling, AI/LLM HTTP paths, model-artifact scanning, PoC generation, and cross-repository Python helper consistency. Searched Python and shell sources for process execution, dynamic evaluation, unsafe deserialization, TLS verification overrides, filesystem deletion, and network calls.

Python 3.14.8 checks passed for the current worktree: Ruff, repository compileall, CLI documentation validation (10 skill docs / 91 command references / 57 distinct CLIs), shared-helper consistency, all 3 repository JSON files, all 9 offline demos, all 21 Bash syntax checks, and 47 unit tests. `python3` resolves in the target PowerShell environment. `git diff --check` passed (Git emitted only line-ending normalization warnings). PoC generators were exercised with hostile input values; generated Python compiled and generated shell commands parsed safely. DOM, redirect, cache, and crawler discovery behavior was tested only against loopback fixtures; no live targets were contacted. Passing offline checks do not establish absence of all bugs.

---

## Addendum — 2026-11-16

The header revision `73162b0` above is the **base** that was audited; it remains
as historical provenance. The current `main` head is
`da46b1ddc15110feaf220bdd3cccf5d1e4b4e234`. This addendum records work done after
the 2026-11-15 audit; the checks and counts in the sections above describe the
`caed91e` state and were **not** all re-run for the commits below.

### Browser runtime auditor (`6695fcf`)
- Added `skills/webapp-exploit-hunter/scripts/browser_security_auditor.py`: an
  isolated Playwright-backed auditor with passive observation, opt-in `--active`
  query/fragment execution canaries, and explicit `--submit-forms` submissions.
  Origin controls, request/page/submission budgets, blocked service workers,
  WebSocket interception without upstream connect, storage-state origin
  filtering, and redaction of many sensitive values.
- Verified at add time: Python compile, Ruff, CLI `--help`, CLI-docs, JSON
  parse, `git diff --check`. The CLI-docs check then reported **10 skill docs /
  94 command references / 58 distinct CLIs** (vs 10 / 91 / 57 pre-browser).
- **Not** covered by the 47-test suite, and **no real Playwright/Chromium run has
  been performed yet.** Known-weak areas (request policy, form-POST grant
  binding, WebSocket handling/redaction, storage-state cookie suffix-match,
  budget counting, SPA settle timing) are enumerated in `HANDOVER.md`.

### Deep LFI + ImageTragick integration (`da46b1d`)
- 3-way merge of local payload-depth work onto the audited base:
  `lfi_tester.py` (two-step JSON-reference following, generic read primitive,
  `/proc/net/tcp` internal-port discovery, apache PID → `/proc/<pid>/environ`
  secret chain, `--skip-lfi-chains` gate), `upload_tester.py` (ImageTragick
  CVE-2016-3714/15/16/17/18 with OOB `--callback-url` confirmation and
  `--allow-destructive-poc` canary-only gating), `import_findings.py`
  (ImageTragick `*_attempted` → `rce_potential`/`precondition_dependent`),
  `SKILL.md` (ImageTragick layer).
- At the one overlap, kept the audit's `shlex`-quoted, no-`-k` `poc_curl`; fixed
  a Python-3.12-only nested f-string to be `py38`-safe (the Ruff target).
- Re-verified on `da46b1d`: **47 unit tests + 21 subtests pass; Ruff clean** on
  the merged scripts. The browser auditor remains unexercised by a real browser.

### Coverage caveat
The audit did not deeply review every skill to the same depth. `HANDOVER.md`
lists which skills got the deepest automated coverage and which remain
lightly verified. Do not read this record as implying uniform review or a
bug-free repository.

---

## Follow-up addendum — 2026-11-16

The `da46b1d` head and pre-browser verification above are historical snapshots.
The subsequent `main` history includes browser-auditor hardening and local
Chromium integration, a structural skill inventory, regression matrices across
the previously shallow skills, and fixes to recon, cloud, attack-path, chain,
and race-PoC behavior. The verified code head before this documentation/test
follow-up was `61aae43f2d1051f75e125132a654d780c3b22bf3` (`origin/main` matched
it at pickup). See `HANDOVER.md` for the full commit lineage and per-skill
findings; see `INVENTORY.md` for the refreshed coverage map.

At that code head, the complete suite passed **441 tests + 21 subtests** and
the browser auditor was exercised with Playwright/Chromium against a local
fixture (passive observations, off-origin/WebSocket controls, active query and
fragment DOM execution, and form submission). Two additional upload PATH_INFO
regressions were added in the follow-up: status `0` is non-permissive and
unexpected request-layer exceptions are not silently swallowed. The refreshed
complete suite then passed **443 tests + 21 subtests**. Ruff, compileall, CLI
documentation validation (**10 skill docs / 95 command references / 58 CLIs**),
shared-helper synchronization, and `git diff --check` passed in the same
Windows environment with Python 3.14.8, pytest 9.1.1, Ruff 0.17.5, and Playwright
1.65.1 with Chromium installed. No live targets were contacted.

These checks improve coverage but do not establish that the repository is
bug-free or that every skill has exhaustive end-to-end coverage. The remaining
gaps and browser policy limitations are maintained in `HANDOVER.md` and
`INVENTORY.md`.

---

## Follow-up addendum — dependency bootstrap and preflight (2026-11-16)

Starting point was the clean, verified `main` tip `3aa2f62090bce3f9e966cdd4361b58067d981d2b`.
This pass addresses the handover's open bootstrap/preflight item. The previous
bootstrap trusted successful package markers without checking the active
interpreter, cached failures indefinitely, reported missing system tools rather
than installing them, and left Playwright's browser/manual OS dependencies to
the operator. Its hook timeout was also too short for its worst-case sequence.

### Changes

- Bootstrap revalidates Python imports and package version constraints in the
  interpreter it is running under. It retries previous failures so transient
  network/proxy problems do not freeze a skill in a permanently unavailable
  state. Requirements hashing normalizes CRLF/LF; unreadable/malformed marker
  data no longer aborts the non-strict startup path.
- SessionStart now attempts missing Python dependencies, Playwright Chromium,
  Go, the managed Go recon CLIs, and allowlisted system commands through
  package managers already present on the host: WinGet/Chocolatey, Homebrew,
  apt/dnf/yum/pacman. Each attempt is logged, uses noninteractive flags, and is
  bounded by a 540-second total install budget inside the official 600-second
  command-hook maximum. It does not fetch and execute a package-manager
  bootstrap script.
- Playwright Chromium is installed through its own Python CLI. Strict browser
  preflight verifies an actual headless launch; on Linux, a missing-library
  error triggers Playwright's `install-deps chromium` through noninteractive
  `sudo -n` (or directly when already root), followed by a retry.
- `--strict` now exits nonzero until the complete *managed* stack is usable.
  Narrow `--require-tool` and `--require-python` modes install and verify only
  the selected task dependencies. The swarm operator and browser/AI skill docs
  now direct agents to preflight before dependent work. On Windows, newly
  installed tools outside the parent session's PATH cause preflight failure;
  the Go bin is persisted to the user PATH and the agent must restart its
  terminal/host and re-run preflight.
- The active-testing behavior and scope gates were not reduced or changed.
  Preflight is not a target authorization mechanism. API mutation flags,
  browser `--active` / `--submit-forms`, injection probes, and cache replay
  controls remain as they were.
- `amass` was deliberately left outside managed installs: the current wrapper
  uses `amass enum -passive` v4-style arguments and parses JSON from stdout,
  while the upstream project now documents a v5 installation path. Whether
  the current CLI preserves those exact flags/output semantics remains
  unverified; check it with a fixture before bootstrap manages the install.

### Verification and limits

- Added offline bootstrap tests for line-ending-stable requirements hashes,
  version-aware markers, retry after cached failure, installer command building
  on Windows and Linux, narrow and strict preflight gates, Chromium binary and
  OS-library setup, Go executable visibility, stale PATH handling, and LF-only
  SessionStart metadata. `tests/test_bootstrap.py` contributes 30 tests; the
  existing hook test also checks its Python command, timeout, and LF bytes.
- Final verification on this code state: **474 tests + 21 subtests passed**;
  Ruff, compileall, helper sync, CLI docs (**10 / 95 / 58**), and
  `git diff --check` passed. `python3 scripts/bootstrap.py --strict` passed on
  Windows, including a real local Chromium launch. The host already had every
  managed tool, so no OS package installation ran.
- The strict preflight was run on this Windows host. `requests`, Playwright,
  Chromium, Go, Nmap, dig, WHOIS, Perl, and the four managed Go CLIs were already
  available; a real local Chromium headless launch passed. No package-manager
  installation was triggered on this host. Package-manager installs and Linux
  library installation were tested with mocks only; clean-host Windows/macOS/
  Linux installation remains unverified.
- Python package constraints and Go `@latest` references remain intentionally
  unpinned in this pass. Supply-chain pinning and platform installer testing
  remain follow-up work. No live targets were contacted.

Primary implementation references: [Claude Code command-hook limits](https://code.claude.com/docs/en/hooks-guide),
[WinGet install options](https://learn.microsoft.com/en-us/windows/package-manager/winget/install),
[Playwright Python browser installation](https://playwright.dev/python/docs/browsers), and
[OWASP Amass current install docs](https://github.com/owasp-amass/docs/blob/master/docs/index.md).

---

## Follow-up addendum — API-breaker scope and evidence (2026-11-16)

Starting point was clean `main` at
`a95bab9c9334023a82dde223190e38ca1059f82f`, after the bootstrap continuation.
This pass prioritizes the API-breaker coverage gap called out in `HANDOVER.md`
and `INVENTORY.md`. The complete skill remains partially audited.

### Findings and changes

- `schema_builder.py`, `rate_limiter.py`, and `logic_tester.py` could trust
  imported endpoint URLs or metadata without binding them to the operator's
  intended origin. These CLIs now require an explicit credential-free
  `--api-base`; imported URLs are resolved and filtered through the shared
  same-origin check before any authenticated probes run. `schema_builder.py`
  requires that explicit base when `--input` is used.
- `api_discovery.py` defined a JavaScript endpoint extractor but never invoked
  it. It now parses script tags from the target page, analyzes at most 20
  same-origin scripts, skips external scripts and API URLs, and probes the
  extracted same-origin paths. Its target URL and worker count are validated.
- `rate_limiter.py` now rejects non-finite/negative delays and request counts
  outside 1–1000; the default remains 120. This keeps explicit rate tests
  configurable while avoiding accidental zero-work false reports and
  unbounded count values.
- `logic_tester.py` had labeled response status, field presence, or concurrent
  2xx counts as confirmed price/quantity/coupon/negative-amount/race/privilege
  vulnerabilities without verifying the manipulated value or a persisted
  state change. Exact injected-value echoes are now low-confidence candidates;
  other accepted/race signals are also informational candidates pending
  read-back. `api_report.py` preserves API6/API5 mapping while explaining that
  candidate impact is unverified. The active POST/PUT/PATCH payloads and race
  probes remain enabled when selected; no new write flag was introduced.
- `schema_builder.py` previously submitted GraphQL CSRF mutations against a
  guessed object ID (`1`) even without an ambient session cookie, and treated a
  successful response as confirmed CSRF impact. It now submits those GET/form
  mutations only when both `--cookie` and an operator-approved
  `--csrf-test-id` are present. The requests remain active when selected, but
  successful responses are informational candidates pending browser cookie
  policy and persisted-state verification.
- A specific `logic_tester.py --endpoint` run previously reached some payload
  routines once through category classification and again through the
  all-tests path. The category pass is now skipped for this explicit mode, so
  each selected probe routine runs once.

### Verification and remaining limits

- Added `tests/test_api_breaker.py` with 26 focused regressions for same-origin
  JavaScript analysis, active discovery integration, imported endpoint scoping,
  explicit target bases, bounded rate counts, no duplicate single-endpoint
  submissions, evidence confidence, candidate report mapping, and guarded
  GraphQL CSRF mutation submission.
- Full suite passed **500 tests + 21 subtests**. Ruff, compileall, helper sync,
  CLI docs (**10 skill docs / 95 command references / 58 CLIs**), and
  `git diff --check` passed on Windows. New API-target interactions were mocked;
  no live API target was contacted.
- At this 500-test checkpoint, `api-breaker` remained shallow in JWT case matrices, GraphQL depth/authz/CSRF
  integration, BOLA/BFLA workflows, rate-limit bypass/batching, business-state
  read-back, and broad report input shapes. Keep these in the active worklist;
  26 focused tests do not establish broad coverage or absence of defects.

Business-logic evidence rules follow the business-specific harm model in
[OWASP API6:2023](https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).
For object-level authorization methodology see
[OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

---

## Follow-up addendum — BOLA object URL construction (2026-11-16)

After the API-breaker scope/evidence pass, review found that
`authz_tester.py` defined `find_id_endpoints()` but did not use it. BOLA checks
therefore appended discovered IDs to all endpoint URLs, producing malformed
paths such as `/users/42/42` for direct object endpoints; appending after a
query string also corrupted the URL. The follow-up now distinguishes
collection and object endpoints, substitutes path placeholders, preserves
queries, percent-encodes IDs, and keeps the final URL on the configured API
origin. It recognizes UUID-style IDs and rejects unusable values extracted
from response JSON.

Four regression tests cover placeholder/collection URL construction,
query preservation, and direct numeric and UUID object endpoints. The
API-breaker test file now has **30 tests**. Full verification passed:
**504 tests + 21 subtests**, Ruff, compileall, shared-helper sync, CLI docs
(**10 skill docs / 95 command references / 58 CLIs**), and `git diff --check`.
The host is Windows with Python 3.14.8; Ruff passed through
`python3 -m ruff` because `ruff` is not on the shell PATH. Requests are mocked
in these regressions; no live target was contacted. The code fix is commit
`9efbba5e7cbb7c6b816459f4dbca298fa40e6a79` on `main`.

---

## Follow-up addendum — BOLA/BFLA path probing and evidence (2026-11-16)

A further API-breaker review found that BOLA's initial read sent OpenAPI-style
path placeholders literally, so parameterized endpoints commonly returned
errors before cross-user checks could run. The initial read now substitutes
a bounded seed ID while preserving the URL origin and query string.

The authorization testers also treated any successful HTTP status on a
candidate object/admin path as a confirmed BOLA/BFLA issue. Such responses
can be ordinary public endpoints, empty acknowledgements, or unrelated
content. BOLA status-only and static-ID responses now remain INFO candidates;
a BOLA GET is confirmed only when the response identifies the exact tested
object. BFLA and method-override responses remain candidates until privileged
data or action is demonstrated. Explicitly selected active requests still run;
write verbs and method-override probes retain the existing
--allow-mutation-write gate.

Five regression tests cover template substitution, status-only BOLA
candidates, exact-object BOLA confirmation, BFLA candidate classification and
report mapping, and continued active write/method-override probes. The
API-breaker matrix now has **35 tests**. Full verification passed **509 tests
+ 21 subtests**, Ruff, compileall, shared-helper sync, CLI docs (**10 / 95 /
58**), and git diff --check. All target requests were mocked. The code
change is commit 511a522909c15d0687743683916217a1e892af40 on main.

---

## Follow-up addendum — JWT/auth analyzer evidence and output safety (2026-11-16)

Review of auth_analyzer.py found that JWT forgery, key-confusion, kid
injection, weak-secret, and API-key-position checks treated a 200/201 response
as proof even when the endpoint also accepted an invalid token. No-auth scans
also elevated a sufficiently large response without establishing that the
endpoint's data was sensitive. The probes remain active, but JWT/API-key
success is confirmed only when the malformed-token or unauthenticated control
is rejected with 401/403; ambiguous/public endpoints yield INFO candidates.
No-auth data stays a candidate until its sensitivity and intended access are
established.

The report previously copied decoded JWT header and payload values directly
into JSON. A recursive redactor now masks common credential, key-material,
and personal-data claim keys, including nested privilege claims. JWT decoding
also rejects malformed base64url segments and non-object header/payload JSON,
preventing a malformed three-part token from reaching code that assumes
dictionary claims. CLI inter-request delay is restricted to 0-60 seconds; the
time-injection sleep is restricted to 1-10 seconds.

Eleven regressions cover malformed token shapes, recursive redaction,
invalid-token differential controls, public-endpoint candidates, API-key
position confirmation, no-auth candidate confidence, crit-header acceptance
with differing 2xx codes, and delay bounds. The API-breaker test file has
**46 tests**. Full verification passed **520 tests + 25 subtests**, Ruff,
compileall, shared-helper sync, CLI docs (**10 skill docs / 95 command
references / 58 CLIs**), and git diff --check. All network calls in the new
tests are mocked; no live targets were contacted. The code change is commit
68dd243dc5276d1d41762a6e2c059261da7c182c on main.

Remaining auth-analyzer limits include the lack of end-to-end HTTP integration
for all attack variants, sensitivity/ownership confirmation that needs a
target-specific human read-back, and independent validation of the RS/PS
relabel hypothesis. The stdlib-only decision continues to defer true-key JWKS
verification and embedded-JWK signing.

---

## Follow-up addendum — JWT expiry claim bounds (2026-11-16)

A direct reproduction showed analyze_jwt_claims() crashed with OverflowError
when a syntactically valid JWT payload contained a very large numeric exp.
Non-finite floats, booleans (which Python treats as integers), and non-numeric
exp values also lacked safe classification. These values now produce an
informational jwt_invalid_expiry finding and analysis continues; ordinary
numeric expiry behavior is unchanged.

One regression covers huge integers, infinity, NaN, booleans, and string
values. The API-breaker matrix now has **47 tests**. Full verification passed
**521 tests + 30 subtests**, Ruff, compileall, shared-helper sync, CLI docs
(**10 skill docs / 95 command references / 58 CLIs**), and git diff --check.
The code fix is commit 0f58b5e8a4fa6a2531bd459215f37e85c544fc7b on main.

---

## Follow-up addendum — GraphQL evidence and input handling (2026-11-16)

Review of `schema_builder.py` found several GraphQL acceptance signals that
overstated evidence: a status-0 transport failure could be classified as DoS;
a 5xx, latency-growth heuristic, or timeout was presented as confirmed impact;
and status/body checks for naming-bypass and fragment-cycle probes could treat
unrelated responses as acceptance. Nested-field differences also did not
establish that the tested object belonged to another user or that the fields
were intended to be hidden. These checks no longer label unverified signals
as confirmed vulnerabilities. Timeout/5xx and latency signals remain INFO
candidates; acceptance-based checks require a clean GraphQL success response.
Fast transport failures and non-200/non-GraphQL acceptance-probe responses are
inconclusive. The active
depth ladder, fragment-cycle, introspection-naming, nested-field, CSRF, and
explicitly opted-in mutation-write requests remain in place; existing cookie,
canary, and mutation-write gates are unchanged.

Schema-derived field/type names are validated before query interpolation.
Caller-supplied nested-field IDs are JSON-quoted and bounded (at most 50 IDs,
128 characters each); CLI delay is finite and limited to 0–60 seconds. The
GraphQL skill guide now describes candidate confidence and keeps the active
testing workflow explicit. `api_report.py` maps GraphQL BOLA and resource
control candidates to the relevant OWASP API categories.

Added 12 focused regressions for the transport/server/timeout distinctions,
non-success bypass responses, nested-field controls and candidate evidence,
JSON quoting of a hostile ID, invalid names, parser bounds, fragment-cycle
candidate handling, report mappings, and preservation of active CSRF GET/form
requests and selected opt-in write requests. The API-breaker test file now has
**59 tests**; the full suite passed **533 tests + 38 subtests**. Ruff,
compileall, shared-helper sync, CLI docs (**10 skill docs / 95 command
references / 58 CLIs**), and `git diff --check` passed on Windows/Python 3.14.8.
All target-facing regressions are mocked; no live target was contacted. A real
GraphQL HTTP integration run is still needed, as are the broader API-breaker
items in `HANDOVER.md` (BOLA/BFLA, rate-limit/batching, business-state
read-back, report-shape coverage, and JWT RS/PS relabel review).

Code and regression changes are commit
`81733eee577420a8b3efebfb3117b691393a2f85` on `main`; verification and this
record are being carried forward as separate documentation commits.

---

## Follow-up addendum — BOLA sessions and authz evidence output (2026-11-16)

The BOLA cross-user request builder copied the one optional `--cookie` header
to both User A and User B while also sending distinct bearer tokens. This
could authenticate User B's request as User A and invalidate the cross-user
comparison. `--cookie` now belongs to User A; the new `--cookie-b` belongs to
User B, and User A's cookie is omitted from User B when the second cookie is
not supplied. Shared non-cookie headers still apply to both. The authz CLI
also now rejects non-finite, negative, and over-60-second delays before any
target request.

Authorization findings previously included raw 200-character response
snippets. The authz tool now redacts common credential, key, cookie, and PII
fields from JSON, redacts inline email/JWT/bearer/key-value patterns, and
omits non-JSON bodies while retaining their length. Object-ID extraction uses
an iterative walk and handles deep JSON without Python recursion failure.

A local `ThreadingHTTPServer` fixture exercises actual HTTP requests for the
User A collection read, User B exact-object read, anonymous denial, regular
user `/admin` GET candidate, and default GET-only behavior. Other regressions
cover cookie isolation with and without `--cookie-b`, CLI delay rejection,
preview redaction, and deep JSON. The API-breaker test file has **65 tests**;
full verification passed **539 tests + 47 subtests**, Ruff, compileall,
shared-helper sync, CLI docs (**10 skill docs / 95 command references / 58
CLIs**), and `git diff --check`. Focused authz coverage passed **81 tests + 31
subtests**. Integration contacted only the loopback fixture; no live external
API was contacted.

Code changes are commits `90d4fadda5ca21bfa5575f261ed32199986bc18c` and
`585ffa2b38aba78625e83a4eec2af2e1de3637b0` on `main`. Similar raw preview
fields in `auth_analyzer.py`, `logic_tester.py`, and `mass_assignment.py` are
not yet reviewed and remain open.

---

## Follow-up addendum — shared API response-preview sanitizing (2026-11-16)

The prior authz-preview change was generalized into the skill-local
`skills/api-breaker/scripts/response_safety.py` helper and applied to every
`response_preview` emitter in `authz_tester.py`, `auth_analyzer.py`,
`logic_tester.py`, and `mass_assignment.py`. Structured JSON redacts common
credential, key, cookie, and personal-data field names; common inline email,
JWT, bearer, and credential-assignment patterns are also masked. Non-JSON
response bodies are omitted from findings, while the authz preview retains a
body-length marker. Object ID extraction in authz stays iterative.

Regressions now exercise output redaction through the no-auth, business-logic,
and mass-assignment finding paths in addition to the authz sanitizer itself.
`rg` confirmed there are no remaining raw `response_preview: body[:…]` slices
in API-breaker scripts. Full suite: **539 tests + 47 subtests**; focused
authz/API tests: **81 tests + 31 subtests**. Ruff, compileall, helper sync,
CLI docs (**10 skill docs / 95 command references / 58 CLIs**), and
`git diff --check` passed. All requests were mocked or directed to a local
loopback fixture; no external targets were contacted.

Redaction is pattern-based, not a guarantee that all proprietary values or
unknown secrets embedded in arbitrary JSON strings are removed. The relevant
code is commit `5d6e6b36947adfb6144eb98004227297daf805d6` on `main`.

---

## Follow-up addendum — rate-limit probe evidence and imported targets (2026-11-16)

`rate_limiter.py` now includes same-origin-filtered OpenAPI endpoint records
and GraphQL endpoints from both the URL-keyed `api_discovery.py` result map
and `schema_builder.py`'s `graphql_schema.endpoint_url`. Direct request counts,
concurrency, delays, and GraphQL baseline attempts are bounded. The report
generator maps new candidate types to OWASP API categories and candidate-aware
remediations.

The scanner remains active for authorized in-scope testing. Sequential and
concurrent bursts, forwarded-IP header mutations, path/method variants, and
GraphQL batch/alias payloads still run when selected. Findings now stay INFO
candidates where response counts, status/body-length matches, or accepted
requests do not establish an application-level bypass or persisted business
impact. GraphQL differential probes use clean, side-effect-free `__typename`
responses, cap the baseline at 60 requests and batch/alias operations at 110,
and do not claim those safe probes establish impact on login, OTP, or other
sensitive resolvers.

Added focused regressions for URL-keyed GraphQL and OpenAPI import handling,
clean GraphQL batch/alias response validation, direct probe-budget bounds, and
candidate report mappings. The API-breaker test file now has **69 tests + 26
subtests**. Full verification passed **543 tests + 47 subtests**, Ruff,
compileall, shared-helper sync, CLI docs (**10 skill docs / 95 command
references / 58 CLIs**), and `git diff --check`. Target behavior was mocked;
no external API was contacted at this point in the audit. The follow-up below
adds local loopback HTTP fixtures; no live authorized API integration exists.
A `429` differential, matching response shape, or successful `__typename`
result remains candidate evidence rather than proof of business impact.

Code, focused regressions, skill documentation, and research-note updates are
commit `a75e337cd2cb1a025cec5d7abc35f401ce646c74`
(`Harden API rate-limit probe evidence`) on `main`.

---

## Follow-up addendum — loopback evidence, query cache keys, and coupon signals (2026-11-16)

Two local HTTP fixtures now exercise the rate-limiter's actual request path:
one returns a per-client 429 baseline and permits rotating `X-Forwarded-For`
values; the other accepts a clean unbatched GraphQL request, throttles the
next one, then returns exact clean results for the array and alias probes.
The first fixture exposed duplicate findings from two configured
`X-Forwarded-For` entries that were overwritten by the same generated-IP
sequence. The redundant sequence is now run once, retaining the active
rotation probe. Both findings remain INFO candidates, and no external target
was contacted.

`web-cache-auditor` now rejects non-finite and over-limit timing values,
including direct `request_get()` timeout calls: request timeout is bounded to
30 seconds and delay to 5 seconds. Its active `--probe-unkeyed` mode also tests
five inert query-key candidates (`utm_content`, `utm_source`, `gclid`,
`fbclid`, `_`) on eligible URLs. It skips names already present and suppresses
query probing when sensitive-looking keys are present. A staging-only replay
uses the same nonce with the candidate parameter removed. A local cache fixture
verifies a replayed canary becomes an INFO lead, with the query value omitted
from the report. The candidate seed set is intentionally limited; duplicate
parameter precedence, semicolon parsing, and broader cache/origin normalization
remain manual checks. These probes follow PortSwigger's discussion of
[cache parameter cloaking](https://portswigger.net/research/web-cache-entanglement)
and [unkeyed query strings](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query).

`logic_tester.py` no longer treats a generic `success` message or an echo of
the submitted `coupons` array as coupon-stacking evidence. It emits an INFO
candidate only when a 2xx JSON response has at least two entries in an explicit
applied-coupon/discount collection. All five active coupon payload cases still
run; response evidence still does not prove a changed total or persisted state.

The API-breaker suite now has **72 tests + 26 subtests**; cache auditor has
**12 tests + 23 subtests**. Full suite: **550 tests + 68 subtests**. Ruff,
compileall, shared-helper sync, CLI docs (**10 skill docs / 95 command
references / 58 CLIs**), and `git diff --check` passed. All integration traffic
was loopback-only; no live external API was contacted.

Code, skill/research docs, and local regression fixtures are commits
`c484a2834893ea7fd7af645bb9a91bd7816ad052` (`Improve API rate and coupon
evidence`) and `b8abc54830bbdab2ce712b6260a021395caaf46f`
(`Probe query cache-key behavior safely`) on `main`.

---

## Follow-up addendum — state-aware business-logic race probes (2026-11-16)

`logic_tester.py` retains all three active race payload cases and ten-request
concurrent bursts. A new run-wide `--race-request-budget` bounds race payloads,
sequential controls, and read-back requests to 840 by default. Optional
`--race-state-url` plus an RFC 6901 `--race-state-json-pointer` must remain on
the trusted API origin. For each case with a numeric pre-state, the tester
sends one sequential control mutation, reads the selected counter again, sends
the concurrent burst, and reads it again. Multiple 2xx responses alone remain
candidate evidence; when the state reads are comparable, a candidate is emitted
only if the selected counter changed more during the burst than during the
one-request control. Raw counter values are not written to findings. The
state-aware option adds one extra mutation per payload and requires a
disposable test object plus a genuinely read-only read-back route; HTTP GET is
not assumed harmless. Active probes remain enabled by default.

Loopback fixtures verify that repeated 2xx responses with idempotent state
changes are suppressed and that excess numeric counter changes are reported as
INFO candidates. Scope checks reject an off-origin read-back URL before any
request. Research notes now link PortSwigger's state-machine/race methodology
and OWASP WSTG payment-functionality guidance. The stdlib thread pool does not
provide HTTP/2 single-packet synchronization, and the fixed generic payloads
still require target-specific business rules and state semantics for useful
results; no live target was contacted.

The API-breaker suite now has **77 tests + 26 subtests**; the full suite passed
**555 tests + 68 subtests**. Ruff, compileall, shared-helper sync, CLI docs
(**10 skill docs / 95 command references / 58 CLIs**), and `git diff --check`
passed. All network integration remained loopback-only.

Code, regression fixtures, skill guidance, and primary-source research notes
are commit `7f26773c848cf6ebcedc7adf046b79fb17d386fe`
(`Add state-aware API race checks`) on `main`.

## Scoped closeout addendum — 2026-11-16

This addendum closes the six-item checklist in `HANDOVER.md`. It is scoped to
those named items and does not reopen other skills or propose a wider reorg.

1. **API response previews:** rechecked all eight emitters in
   `auth_analyzer.py`, `logic_tester.py`, and `mass_assignment.py`. Each uses
   `safe_response_preview`; no raw emitter or additional fix was needed. The
   mass-assignment regression now verifies redaction of a password, email,
   API-key field, and inline Bearer value.
2. **Rate limiting:** reviewed active concurrent bursts, forwarded-header/path
   mutations, and GraphQL batching. Fixed the ordering bug that sent sequential
   baseline traffic before validating race count/workers. Invalid inputs now
   fail before all network requests; three subcases prove that invariant.
   Payload depth and active behavior were preserved.
3. **Business-state races:** retained exact integer values from JSON Pointer
   reads, excluded HTTP 202 from synchronous state controls, sent explicit
   no-cache read headers, and suppressed comparative state claims when Age or
   cache-hit/stale metadata makes reads suspect. Regressions cover large
   integers, 202, cache metadata, and cache-bypass headers. The three active
   payload cases and ten-request bursts were not removed or gated.
4. **Report inputs:** the loader accepts single finding objects, aggregate
   `findings` arrays, and top-level arrays. It warns and skips malformed roots,
   invalid containers, non-object entries, unreadable files, and corrupt JSON.
   Report rendering normalizes malformed fields before mappings, impact, and
   curl generation.
5. **Bootstrap / Amass:** documented the supplied Amass v5 CLI/output drift
   and wordlist-engine report in `MANUAL_OPTIONAL_TOOLS`, README, tools setup,
   and inventory. `amass` is still excluded from `GO_TOOLS`. The bootstrap's
   install/verify behavior for its managed stack is unchanged; strict/narrow
   preflight still stops dependent tasks when a required tool is unavailable.
6. **Browser auditor:** routed in-scope GET/HEAD mutation paths now use the
   state-changing-path policy; one-shot form grants bind method, origin,
   path/query, document navigation, and a unique marker; WebSocket handling uses
   local mocks with no upstream connection and closes the page-side mock; and
   storage-state filtering requires exact allowed origins/hosts instead of a
   public-suffix approximation. Playwright 1.48.0 and 1.65.2 loopback runs
   cover WebSocket isolation and canary-bearing GET/POST form submission.

The code and regression coverage also exposed one closeout lint defect: a
repeated WebSocket counter key in the browser page report. The duplicate was
removed; the retained counter uses the normalized page value.

The code and regression closeout is commit
`6f8c4af3646043294682520d9ca551560a01f928` (`Close scoped audit checklist and verify
regressions`) on `main`; the local API-race commits `7f26773` and `f5bff3d` were
also included in the push.

### Final verification

- `python3 -m unittest discover -s tests`: **553 tests passed** in 111.068 s.
  The full run exercised loopback/browser fixtures and mocked target requests;
  no live external target was contacted.
- Focused API-breaker suite: **82 tests + 29 subtests passed**.
- Playwright 1.48.0 / Python 3.13.17 loopback checks: **2 browser integration
  tests passed**. The full suite ran with Playwright 1.65.2 on Python 3.14.8.
- `python3 -m ruff check .`, `python3 -m compileall -q .`,
  `python3 scripts/check_common_sync.py`,
  `python3 scripts/check_skill_cli_docs.py` (**10 skill docs / 95 command
  references / 58 CLIs**), and `git diff --check` all passed. Git emitted only
  expected PowerShell line-ending normalization warnings for three files.
- Earlier `555 tests + 68 subtests` entries in this report and handover are
  historical checkpoint records. The current exact checkout's final full-suite
  command reports 553 top-level tests; use this result for the closeout.

No repository-wide restructure, live target assessment, or broad tool-version
pinning was part of this closeout. The Amass unblock evidence remains the
installed `amass --help` and `amass enum --help`, visible wordlist guesses on an
owned-domain fixture, and a reliable structured-output path.

## 2026-11-17 — Shared target-knowledge v1 (#5), Codex

Scope: new stdlib shared SQLite infrastructure plus exactly three integration
points (recon fingerprint publication, error-based SQLi observation reuse,
composer importer enrichment). Read mailbox and established per-skill workflow
before editing; Claude's authorization tester and API-breaker test matrix were
left untouched. No tasks #6–#8, live target traffic, dependency changes, or
per-skill shared-helper changes.

Evidence: **30 new tests + 29 subtests** exercise pure origin/context functions,
engagement/origin/path/role separation, expiry boundaries, refresh invalidation,
negative/error cases, incompatible/corrupt stores, concurrent connections and
processes, absence of raw secrets in the database, query CLI, and the three
integrations. full pytest **667 passed + 102 subtests passed**. Ruff, `compileall -q .`,
common-sync, CLI docs (**10 skill docs / 101 command references / 59 CLIs**),
and final diff checks passed. Hashes are not encryption; the generic API
assumes trusted operators and private engagement files. Advertised stack
versions and auth/rate/WAF signals do not establish exploitability. Failed
payload reuse is narrowly error-based and expires after 15 minutes.

Follow-up limits are documented in `scripts/TARGET_KNOWLEDGE.md`: cloud/API
wiring, remaining testers, rate-limit timing models, history/purge UI, and
other improvement-list tasks remain out of scope.

## 2026-11-17 — Unattended supervisor implementation and review

Surveyed mailbox ownership, established workflow, lounge identifiers/claims/
leases/events, and installed Codex/Claude CLI interfaces. Kept implementation
separate from lounge's HTTP-cell protocol and #5's target-knowledge store.
Claude's design review `fa479ef` informed atomic file claims, fencing,
quarantine, worktree identity, exact-SHA review and recovery behavior.

The first independent Claude code review rejected `ce9be40`; corrected full-diff
visibility (including binary data), successful-parent POSIX cleanup, stderr/JSON
separation, typed ownership/process errors, noninteractive/deadline-aware Git,
ambiguous-push handling, committed whitespace checks and protected transcript
paths. The real reverse CLI smoke exposed additional Git-metadata path issues,
fixed by separating worker worktrees and independent reviewer clones.

Evidence: **39 supervisor regression tests + 20 subtests**, including local
non-network Git integration and process lifecycle cases. Both real CLI
handoff directions passed with a disposable local remote; fixture code was not
pushed to GitHub. Final full pytest: **724 passed + 122 subtests passed**. Ruff, full compileall,
common-sync, CLI docs (**10/102/59**) and final diff checks passed.
Independent Claude CLI review approved implementation `ceab93c7421c0423f9af847d49da69ac5ff0cf01` with no remaining findings.

Shipped defaults remain disabled and the project queue is empty. No tasks
#6–#8, live target assessment, global permission bypass, API-key provisioning,
or recurring background service activation occurred. Runtime data is private
under Git metadata; worktrees are separate. Lifecycle coordination assumes
trusted repositories and is not hostile-code isolation or a strict Codex cost
cap. All residual limits are documented in tools/agent-supervisor/README.md.

## 2026-11-17 — Shared-goal live view validation

Added named persistent CLI session streaming, same-goal compact live terminal
view, goal progress/heartbeat/session UUIDs and guarded native resume commands.
Historical single-result Claude JSON still parses; streamed structured reviews
retain exact candidate/base binding. Watch does not mutate task state; demo is
explicit, read-only, bounded, checks unchanged checkout and obeys stop control.
No UI automation typed terminal commands or changed app/security settings.

Validation: real Codex+Claude simultaneous read-only demo passed on the shared
visibility goal. **13 view tests pass**. Baseline full suite **735 tests +122
subtests** passed; Final focused rerun: **52 passed + 20 subtests passed**. Ruff, compileall, helper sync,
CLI docs (**10/102/59**) and diff checks pass. Claude review caught two cosmetic
issues (structured-only result status; marker rewrite flicker), both fixed.
Independent Claude CLI review approved `f152ba0554a9c72a8892e9f8cf5a73f428a83abf` with no remaining findings.

Task #6–#8 division exists only as private draft specifications, not approved
queue entries or running jobs. Current project queue remains empty. App tools
open/read the terminal but cannot input the watch command; the user has the
one-time paste instruction. No cross-provider native chat UI is claimed.

## 2026-11-17 — Supervised improvement #6: automatic bounded WAF escalation

New `skills/webapp-exploit-hunter/scripts/_waf_escalation.py`. Closes the gap
the earlier 2026-11-16 adaptive-WAF-evasion pass left open: that pass added
same-payload mutation retries inside sqli_tester.py/xss_tester.py, but left
the separate `waf_bypass_tester.py` differential-technique CLI entirely
manual, requiring an operator to notice a block and run it by hand against
the same target/parameter.

`classify_block(status, body, headers)` distinguishes rate limiting
(429, `Retry-After`, "too many requests"/"throttle"/"quota exceeded" body
phrasing) from attack filtering (403/406, or a WAF/CDN block-page body
signature), with rate limiting taking precedence when a response matches
both. Only `attack_filter` is escalation-worthy. `run_bounded_escalation()`
runs a fixed, hardcoded, two-sub-test sequence (parameter pollution, then a
single-step inspection-size-limit probe) against waf_bypass_tester.py's own
functions, capped by an explicit `budget` it never exceeds — it drops the
second sub-test rather than truncating the first when budget is tight.
`EscalationTracker` records (url, param) pairs already escalated so a run
never re-escalates the same pair. The call graph is one-directional
(`sqli_tester.py`/`xss_tester.py` -> `_waf_escalation.py` ->
`waf_bypass_tester.py`; the latter is never imported back), guarded by a
static source-scan regression against future recursion. Escalated findings
are waf_bypass_tester's own differential findings (so still real, not
fabricated here), tagged `origin: "auto_waf_escalation"` and explicitly
noted as WAF-bypass evidence rather than SQLi/XSS confirmation — the
pre-existing confirmed-vs-candidate discipline is preserved, not loosened.

Both testers' escalation is OFF by default at the function level
(`waf_escalation_budget=0`); only their CLIs enable it by default via
`--waf-escalation-budget` (default 4, 0 disables), so every pre-existing
direct/library caller and test is unaffected. Existing adaptive-mutation
behavior (sqli's keyword-case/inline-comment/whitespace mutation retries,
xss's in-category `waf_bypass` auto-escalation) is unchanged.

Review follow-ups: response headers now reach `classify_block()`, preventing
403 responses with `Retry-After` from being treated as attack filtering.
Both callers forward auth headers into the differential tests; those tests
are limited to GET query parameters, so POST/body probes do not switch
methods implicitly. `tests/test_waf_auto_escalation.py` now has **43 tests**;
combined with the **87** tests in `test_webapp_legacy_testers.py`, the
focused set passes **130 tests**. A loopback HTTP fixture exercises the real
lazy-loaded WAF tester for both differential probes and verifies the four
request cap. Final validation: **780 tests + 122 subtests passed**; Ruff,
compileall, common-helper sync, and CLI-doc checks (**10/102/59**) pass. The
only real HTTP traffic is to the localhost fixture; no external targets were
contacted. No commit or push was made.


## 2026-11-17 addendum — Improvement #7 executable chain v1

Surveyed the chain builder, correlation output, and PoC generator. Confirmed
the generated Python scaffold executed a generic request for every phase
despite TODO reproduction steps, while the shell sequence ran curl directly.
Replaced those generated scripts with a non-networking Python preview and
commented shell command preview. Added a standalone plan and a bounded
executor for only the confirmed redirect-into-allowlist -> SSRF case.

Evidence: localhost tests exercise two-step success, default dry-run with zero
requests, redirect Location escape blocking before the second request, failed
first-step stop, explicit endpoint scope, and invalid/unconfirmed plans.
Focused matrix: **73 passed**; full pytest: **790 passed + 122 subtests passed**.
Ruff, compileall, common-sync, CLI-doc checks (**10/104/60**), and final diff
checks pass. Only loopback HTTP fixture traffic was used. Design limit: this
executor validates that a redirect and downstream fetch can occur; it does
not execute arbitrary generated chain steps or imported payloads.


## 2026-11-17 addendum — Improvement #8 contextual business severity

Surveyed static severity assignment in `import_findings.py`, technical CVSS
and chain amplification in `calculate_impact.py`, report rendering, and the
correlation snapshots. No existing finding field provided a consistent
business-asset context. Added a narrowly versioned optional asset profile and
preserved an explicit per-finding `business_context` object through correlation.

`scripts/context_severity.py` validates exact-host context, service purpose,
business criticality, data sensitivity, affected scope, context evidence, and
chain-specific impact evidence. It computes a separate contextual tier from
the highest documented consequence factor. Technical severity/CVSS remain
unchanged. Only confirmed chains receive an assigned contextual tier; an
unconfirmed match is potential-only. Reports expose context evidence and note
that supplied context has not been independently verified.

Focused regression set: **88 passed + 3 subtests**. It covers the same finding
under public-blog and tenant-payment contexts, source evidence, artifact
propagation, no-match, unconfirmed gating, malformed profiles, exact-host
isolation, CLI profile loading, and report output. Ruff, compileall,
common-sync, CLI-doc checks (**10/105/60**), and diff check passed. Full pytest: **805 passed + 125 subtests passed**; Ruff, compileall, common-sync, CLI-docs
(**10/105/60**), and final diff checks pass. No external target probes or hosted
model/API calls.

## 2026-11-17 addendum — shared target-knowledge v2 integrations

Added opt-in, engagement-scoped cache integrations for cloud-provider
detection and API endpoint discovery. Cloud entries are positive-only,
provider/service metadata with a one-hour TTL and no resolved IP. API entries
are positive-only sanitized path metadata with a 15-minute TTL and an auth
header digest; reused paths are rebuilt under the caller-supplied base URL.
Both integrations support scoped refresh, and API discovery continues its
GraphQL/OpenAPI/method/legacy checks on cache hits. See
`scripts/TARGET_KNOWLEDGE.md` for exact behavior and deferred reuse surfaces.

Evidence at this checkpoint: `tests/test_shared_knowledge_pipeline.py` plus
`tests/test_target_knowledge.py` passed 41 tests + 29 subtests; full pytest
passed 816 tests + 125 subtests. Ruff, compileall, helper-sync, CLI docs
(10/109/60), and `git diff --check` passed. No live target was tested.

## 2026-11-17 addendum — shared knowledge auth/rate and offline transfer

Implemented structured, expiring auth and rate-limit observations. The N-role
API authorization matrix and API rate-limit tester publish observations;
IDOR consumes only fresh exact-resource facts matching its auth-header digest
for report context and still executes the selected probes. Finding import
remains advisory and does not alter severity/confidence. Offline bundles are
versioned, origin/engagement-bound, size/row/TTL-bounded, allowlist-sanitized,
and preserve original expiry/provenance. Stale imports cannot replace newer
records. Bundles are unsigned and unencrypted and should move only through
trusted storage. No network sync service/client was added and no live target
was contacted. Focused regression matrix: **228 passed + 61 subtests**; full
pytest: **827 passed + 128 subtests**. Ruff, compileall, common-sync, CLI docs
(10/111/60), and final diff checks pass.

## 2026-11-17 addendum — guided stateful business scenarios

Implemented an opt-in operator-defined scenario mode in the workflow tester.
Plan mode is no-network; execution requires explicit `--execute`, and writes
also require `--allow-mutation-write`. Preflight validates same-origin paths,
fixture/cleanup declarations, baseline assertions, and bounded request count.
Baseline failure skips misuse cases but still runs cleanup; 429/Retry-After
stops later traffic. Assertion outcomes omit response values and remain
unverified observations. The focused test suite uses a local stateful HTTP
fixture plus offline boundary tests. No external target was contacted.
Remaining scope: automatic semantic inference, dynamic ID capture, persisted
scenario state, and rollback outside explicitly declared cleanup actions.
Validation: full pytest **836 passed + 128 subtests**; Ruff passed;
compileall passed; common-sync passed (six pipeline skills / five scoped
network helpers); CLI docs passed (10 docs / 113 command references / 60
CLIs); `git diff --check` passed. Targeted scenario/workflow matrix: **43
passed**. No external targets were contacted.

## 2026-11-18 addendum — dynamic scenario values

Added explicit JSON-pointer captures from 2xx JSON responses and bounded,
in-memory `${name}` substitution in later action paths, headers, JSON bodies,
and per-run cleanup. Captures are scalar strings/integers up to 2,048
characters with control characters rejected; output includes only capture
names and availability. Baseline and each misuse case have separate variable
maps. Unknown/missing captures stop dependent actions; non-2xx responses
cannot satisfy assertions or provide captures. Focused matrix: 50 passed.
Full repository validation: **843 pytest tests + 128 subtests passed**;
Ruff, compileall, helper-sync, CLI docs (10 docs / 113 references / 60 CLIs),
and `git diff --check` passed. Focused scenario/workflow matrix: **50 passed**.
No live targets were contacted.

## 2026-11-17 addendum — GET form submit-control preservation

An authorized scan of Pentest-Ground's expressly scan-permitted DVWA at
`https://pentest-ground.com:4280` exposed a false-negative condition: the
crawler recorded named GET submit controls, but the SQLi/XSS target builders
dropped them. The lab's SQLi routes require `Submit=Submit`. Preserving it in
the query results in two error-based SQLi findings for the `id` parameter
(one on each SQLi page); direct baseline-vs-single-quote controls show no SQL
error signature for `id=1` and a new generic SQL-syntax signature for `id=1'`.
The lab's reflected-XSS `name` parameter also produced a candidate, and an
isolated browser query probe confirmed controlled JavaScript execution. These
scan results are written outside the repository. The implementation adds
pure form target building for named GET submit controls in
SQLi/XSS and a focused regression matrix. No destructive paths, auth brute
force, or other Pentest-Ground services were tested. Full repository
validation: **846 pytest tests + 128 subtests passed**; Ruff, compileall,
common-sync, CLI docs (10 docs / 113 references / 60 CLIs), and `git diff
--check` passed. Focused form-control and legacy tester matrix: **90 passed**.


## 2026-11-18 addendum — DVWA coverage and false-positive follow-up

Target was limited to the scan-permitted DVWA app at
`https://pentest-ground.com:4280/`. Authenticated crawling with the lab's
published `admin/password` training credentials surfaced the challenge menu
that the original unauthenticated crawl missed. Confirmed modules now include
error-based SQLi, blind SQLi, file inclusion, reflected XSS, stored XSS,
command injection (harmless echo marker through the actual POST form), CSRF
(password changed to its existing value via GET; no token present), and an
off-origin open redirect. Runtime confirmation for stored/reflected XSS used
harmless JavaScript markers; the stored guestbook canary was left for the
lab's documented periodic reset. No other Pentest-Ground port/app was touched.

This follow-up exposed scanner gaps: POST probes omitted sibling controls and
selected submit values; unauthenticated crawling hid authenticated challenge
routes; SSTI detection accepted reflected expressions; SSRF treated response
size changes as proof; and IDOR promoted changed responses without establishing
resource ownership. POST form context is now preserved for SQLi/XSS target
construction. SSTI uses unique evaluation wrappers. SSRF deltas and generic
IDOR response differences are INFO candidates unless fetch/ownership evidence
is present. Regression coverage lives in `tests/test_get_form_submit_controls.py`
and `tests/test_webapp_legacy_testers.py`.

The inventory baseline is 18 current upstream DVWA challenge menu entries;
7 are confirmed so far (about 39%). This is an observed-module coverage rate,
not a claim that every challenge or hidden bug has been exhaustively tested.
Still requiring concrete module-specific checks: brute-force rate controls,
insecure CAPTCHA, weak session IDs, DOM XSS, CSP bypass, JavaScript attacks,
authorization bypass under a non-admin principal, cryptography, and API. The
stored-XSS browser auditor's built-in generic text canary did not itself
confirm execution; a dedicated safe execution marker did. Direct race testing
was not meaningful without a single-use transaction fixture. Full repository
validation is pending after the current code changes.


## 2026-11-18 follow-up — command injection and module coverage

Expanded the same authorized DVWA assessment after correcting POST form
context. Added `command_injection_tester.py`; it used a harmless `printf`
output transform and confirmed the `/vulnerabilities/exec/` POST `ip`
parameter. Authenticated browser checks additionally confirmed DOM XSS at
`/vulnerabilities/xss_d/`, stored XSS at `/vulnerabilities/xss_s/`, and
previously confirmed reflected XSS; the stored-XSS browser auditor itself
needs a payload that actually executes, because a plain text canary is not
proof. Four sequential `dvwaSession` values confirmed the Weak Session IDs
challenge. Confirmed module count is now 11/15 (about 73%), adding DOM XSS,
stored XSS, command injection, CSRF, open redirect, and weak session IDs to
the original SQLi, blind SQLi, LFI, and reflected XSS results.

Implemented evidence and form coverage changes: POST target construction now
keeps sibling controls, hidden tokens and the selected named submit action;
password/file values are omitted. XSS checks follow POST with same-origin GET
and distinguish stored candidates. SSTI uses unique arithmetic wrappers,
preventing reflection from satisfying evaluation evidence. SSRF response-size
deltas and IDOR status/body differences are unverified candidates absent
independent fetch/ownership evidence. Tests added to
`tests/test_get_form_submit_controls.py`,
`tests/test_webapp_legacy_testers.py`, and
`tests/test_command_injection_tester.py`.

The remaining active modules in this deployment are upload execution, CSP
bypass, and JavaScript attacks. The CAPTCHA route is present but inoperative
because the reCAPTCHA key is missing. API, Cryptography, and Authorization
Bypass were not exposed in this instance menu. A direct race challenge is not
present in the deployed menu. Additional module-specific validation remains
follow-up work, so 11/15 is not an assertion of exhaustive bug discovery.


Validation for the 2026-11-18 follow-up: full pytest **857 passed + 128
subtests**; full-repository Ruff clean; compileall clean for `skills`, `scripts`,
`tests`, and `tools`; shared-helper sync passed; CLI docs checked **10 skill
docs / 114 command references / 61 CLIs**; `git diff --check` passed. The
command-injection checker has five dedicated offline regression tests, and
SQLi/XSS POST form context has regression coverage. No API-breaker authz files
were changed.


## 2026-11-18 addendum — DVWA upload request-shape correction

Reviewing the official DVWA source and the previous upload JSON uncovered a
false-negative: the uploader sent a file part without the form's named
`Upload=Upload` action, so DVWA returned its page without invoking the upload
handler. The old 37 “accepted” alerts were HTTP 200s, not proof of upload, and
the claimed zero-RCE result was invalid. The previous pass also failed to parse
DVWA's relative success path, preventing the execution check from reaching the
uploaded file.

`upload_tester.py` now preserves safe hidden and submit controls, discovers the
file input name, parses DVWA's prose/anchor upload paths, resolves paths on the
same origin only, and uses a per-run PHP marker that deletes only its own file
after execution. The authorized one-file reproduction submitted the actual
`uploaded` field with `MAX_FILE_SIZE` and `Upload`, received its relative path,
executed a unique harmless marker at that path, and then confirmed HTTP 404 on
the same path after self-cleanup. This confirms DVWA's upload-to-PHP execution
challenge. Confirmed deployment coverage is now 12/15 menu modules (80%).
CAPTCHA remains disabled for missing reCAPTCHA keys; CSP bypass and the
JavaScript challenge still need explicit module-level execution checks.

Focused validation after the upload change: `tests/test_webapp_legacy_testers.py`
passed **99 tests**. The final full suite passes **878 tests + 128 subtests**;
full Ruff, compileall, common-sync, CLI docs (**10 / 116 / 63**), and
`git diff --check` pass.

Primary learning sources reviewed: [official DVWA README and setup notes](https://github.com/digininja/DVWA/blob/master/README.md), [DVWA upload handler](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/upload/source/low.php), [DVWA upload form](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/upload/index.php), [DVWA's level-by-level walkthrough](https://github.com/Akinloye3264/dvwa_walkthrough), and its [local-lab reproduction checklist](https://github.com/Akinloye3264/dvwa_walkthrough#reproducing-an-exercise).


## 2026-11-18 addendum — JavaScript and CSP challenge reproduction

The next two DVWA modules are now reproduced with safe proofs. The JavaScript
challenge verifier computes the documented `low`, `medium`, or `high` token
from the public client-side transform and sends one GET/POST pair. The live
`low` challenge returned its success message. This is a purpose-built training
exercise result, reported as INFO rather than a general authentication flaw.

The CSP form verifier reads an explicit host from the response's `script-src`
(or `default-src`) directive, submits it to the `include` form, and uses an
isolated Chromium route to mock the allowlisted host response. All other
off-origin browser traffic is aborted. On this instance the harmless marker
executed from the mocked `pastebin.com` source and **zero external requests
were sent**. This confirms the DVWA lesson without accessing the third-party
host.

`javascript_challenge_tester.py` and `csp_form_tester.py` provide reusable
single-check CLIs; focused offline coverage is in
`tests/test_dvwa_javascript_challenge.py` and `tests/test_csp_form_tester.py`.
Together with the corrected upload proof, confirmed challenge coverage is now
14/15 menu entries (about 93%). The only untestable entry is CAPTCHA, whose
page reports missing reCAPTCHA keys. API, Cryptography, and Authorization
Bypass are absent from the deployed menu and not in the denominator.

Sources reviewed: official [DVWA README](https://github.com/digininja/DVWA/blob/master/README.md),
[JavaScript challenge handler](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/javascript/index.php),
[low-level JavaScript transform](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/javascript/source/low.php),
[CSP challenge source](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/csp/source/low.php),
and the [public level-by-level walkthrough](https://github.com/Akinloye3264/dvwa_walkthrough).

Final validation for this follow-up passes **878 pytest tests + 128 subtests**;
Ruff, compileall, common-sync, CLI docs (**10 / 116 / 63**), and
`git diff --check` pass.

## 2026-11-18 addendum — assessment campaign foundations (#1–#6)

**Architecture changes.** Added an offline campaign planner and explicit JSON
contracts in `scripts/assessment_campaign.py`, `scripts/role_matrix.py`, and
`scripts/finding_evidence.py`. Campaign inputs require exact credential-free
HTTP(S) origins, explicit targets/roles, ordered dependencies, bounded declared
request totals, and an explicit mutation/cleanup declaration for workflow
steps. The planner accepts registered tool identifiers only; it does not run
arbitrary commands or launch general scanner CLIs. Its `run-workflow` adapter
executes only the existing operator-authored business-scenario runner after an
exact-origin confirmation and request-budget preflight.

**Shared state and evidence.** Target knowledge schema v2 keeps the latest
observation as the query view and adds a bounded local history of up to 20,000
events per engagement; schema-v1 rows are copied as migration snapshots.
History covers writes, imports, and explicit deletion. Portable bundles still
contain current observations only. A common finding review reports lifecycle
state and proof completeness without promoting results; report and importer
outputs preserve the original `validated` / chainability claims. Role/object
matrices require explicit authorization policy, and a 2xx/status-only
cross-role response remains a candidate until identity, owner control, object
identity, and unauthorized data are independently evidenced.

**Coverage and context.** Coverage output separates executed test coverage from
precision/recall. Those metrics are omitted unless the manifest has provenance-
backed expected labels; blocked, candidate, conflicting, and untested cases do
not become negatives. Campaign business-context input is validated against
scoped hostnames and stays compatible with the existing contextual severity
path.

**Boundary / remaining uncertainty.** Planning and reporting are offline;
`run-workflow` is the only active adapter. Its optional SQLite ledger persists
step state, prevents completed-step replay, and enforces a transactional
aggregate cap across calls using that adapter. It does not cap independent,
heterogeneous scanner CLIs. Existing per-tool limits are not equivalent to a
whole-pipeline cap. Automatic hypothesis generation,
dynamic business-context inference, and full benchmark labels across DVWA
levels and another vulnerable application remain follow-up work. These files
make no live-target claims.

**Validation.** Final exact-code full pytest: **933 passed + 143 subtests**.
Campaign ledger regression tests: **37 passed + 7 subtests**. Full
Ruff, compileall (`skills scripts tests tools`), common-sync, CLI-doc checker
(**10 skill docs / 116 references / 63 CLIs**), and `git diff --check` pass.
Tests use synthetic/offline data and existing local fixtures; this work made no
live target requests.
