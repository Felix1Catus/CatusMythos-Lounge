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
