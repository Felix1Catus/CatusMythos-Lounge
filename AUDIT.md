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
- `api-breaker` remains shallow in JWT case matrices, GraphQL depth/authz/CSRF
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
