# Handover and open items

Living status note for the ongoing CatusMythos-Lounge improvement work. Keep it
current; it records what has and has **not** been deeply reviewed so later work
doesn't mistake uneven coverage for uniform coverage.

## Current state

- `main` head: `da46b1ddc15110feaf220bdd3cccf5d1e4b4e234` (pushed to `origin/main`).
- Lineage since the audit baseline `73162b0`:
  - `caed91e` — audit/hardening batch (see `AUDIT.md`).
  - `6695fcf` — isolated browser runtime security auditor.
  - `da46b1d` — integrated the local deep-payload LFI + ImageTragick work onto
    the audited base (3-way merge of a local branch; see commit body).
- Verification last run on `da46b1d`: 47 unit tests + 21 subtests pass; Ruff
  clean. A real Playwright/Chromium run of the browser auditor is **still
  pending** (Chromium binary now installed locally via
  `python3 -m playwright install chromium`).

## Depth of review so far (self-reported by the audit author, not yet
independently re-verified line by line)

**Deepest automated coverage:** cache-audit helpers, static DOM analysis,
crawler discovery, redirect scope, selected imported-API data handling, XSS
finding-confidence, PoC-generation safety.

**Shallowest / highest bug-risk — prioritize these:**
- `cloud-pivot-finder`, `attack-path-architect` — mostly repo-wide lint/timestamp
  and shared-helper coverage; little domain-specific end-to-end testing.
- `recon-dominator` — crawler + redirect got focused tests, but recon/OSINT/CVE/
  port-scan/report workflows were not comprehensively exercised.
- `03-exploit-development` — only the model-artifact scanner was hardened.
- `16-ai-llm-security` — HTTP/dependency/redirect paths reviewed, but
  prompt-injection, MCP, RAG, and consumption tests were not adversarially tested.
- `vuln-chain-composer` — import + generated-PoC safety improved; correlation,
  impact scoring, and arbitrary chain generation remain lightly verified. May
  still emit TODO placeholder steps for some chain shapes.
- `web-protocol-auditor` — manual methodology skill, no automated protocol tests.
- Legacy web active testers (LFI/upload/auth/race/SQLi/SSRF/SSTI) — targeted
  fixes only, no full per-script test matrix.

## Browser auditor (`webapp-exploit-hunter/scripts/browser_security_auditor.py`)
Known-weak / unverified areas to review and add regression tests for:
- **Request policy:** allows all same-origin GET/HEAD, blocks off-origin, allows
  one in-scope POST (by method/origin/path) while a form submit is pending.
  An in-scope GET can still mutate state (incl. a GET form action); the
  skip-list only filters crawled links.
- **Form POST authorization:** the pending-submit grant is not bound to the exact
  query string, form identity, resource type, or body. A same-origin POST to the
  same path during the window could consume the grant before the form's own
  request. Snapshot/reload can reorder controls, so stored indices need
  revalidation.
- **WebSockets:** `route_web_socket` closes sockets rather than forwarding; not
  counted against the HTTP budget; `redact_url()` only accepts HTTP(S) so
  `ws://`/`wss://` report URLs become `[invalid-url]`.
- **Storage state:** localStorage origins filtered by exact canonical origin, but
  cookie domains allowed on suffix-match (permits parent-domain cookies), and
  cookie `url` fields pass through without their own origin check.
- **Redaction:** query/fragment stripped and bodies/values omitted, but URL
  paths, page titles, cookie names, and storage key names are retained and could
  themselves carry sensitive data.
- **Budgets:** HTTP cap counts blocked requests too; WebSockets uncounted;
  `max-pages` counts crawled docs, not probe/form pages (active mode can spawn up
  to 10 extra pages per crawled page); form-submission count counts attempts,
  not confirmed network writes.
- **SPA timing:** fixed 250 ms settle may miss async-populated forms/DOM.

## Active-testing doctrine — intentional gates (keep, document, invoke; don't drop)
The injection scanners (SQLi/SSRF/SSTI/LFI/upload/race/WAF/reflected-XSS) still
send active requests. Intentional write-probe gates:
- `api-breaker/scripts/authz_tester.py` — BOLA/BFLA default GET; mutating methods
  and method-override need `--allow-mutation-write`.
- `api-breaker/scripts/mass_assignment.py` — POST/PUT/PATCH need
  `--allow-mutation-write`; imported write endpoints need an explicit trusted
  `--api-base`; imported cross-origin endpoints are skipped.
- `browser_security_auditor.py` — `--active` (URL probes), `--submit-forms`.
- `web-cache-auditor` — `--probe-unkeyed`, staging replay adds `--confirm-cache-replay`.
- Generated web PoC replays the supplied finding payload/method (no invented
  fallback probe set).

The two API write gates are the clearest friction with "don't be passive":
authorized workflows must document and pass the flags, not silently skip write
testing.

## Open items
1. Integration-test the browser auditor against a local fixture (passive, active
   query/fragment, and form-submit paths); fix issues; add regression tests for
   the behaviors listed above. Re-examine the `upload_tester.py` PATH_INFO probe
   whose broad exception catch was removed (unexpected exceptions now propagate).
2. Build a full skill-by-skill inventory (intended use, CLIs, I/O, deps, tests,
   scope controls, overlaps, gaps). None exists yet.
3. Revisit bootstrap + task preflight against "install required tools directly
   when feasible; don't run dependent checks with an incomplete stack." Current
   bootstrap installs Python deps + user-scoped Go tools, but only *reports*
   missing system tools (`nmap`, `dig`, `whois`, `perl`) and does not install
   Chromium. Preserve Windows fixes: `python3`, LF line endings, `hooks/hooks.json`.
4. Consolidate the five copied `_common.py` helpers? A sync check exists instead
   of consolidation. Map imports/CLI examples/plugin refs/tests before moving.
5. Deepen the shallow skills above with primary-source research → test steps,
   edge-case matrices, evidence/confidence rules, regression coverage.

## Standing constraints (don't re-introduce)
- HTTPS verified by default; `CATUS_INSECURE_TLS=1` is the only opt-out.
- Cross-origin redirects (incl. HTTP→HTTPS) are blocked by design — pass the
  final authorized origin when canonicalization crosses origins.
- Claude permission prompts preserved by default; `--dangerously-skip-permissions`
  stays an explicit operator choice.
- Author identity for commits: `FelixCatus <18648889+Felix1Catus@users.noreply.github.com>`.
