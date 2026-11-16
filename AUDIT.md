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
