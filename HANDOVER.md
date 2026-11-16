# Handover and open items

Living status note for the ongoing CatusMythos-Lounge improvement work. Keep it
current; it records what has and has **not** been deeply reviewed so later work
doesn't mistake uneven coverage for uniform coverage.

## Current state

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

## Browser auditor (`webapp-exploit-hunter/scripts/browser_security_auditor.py`)
Known-weak / unverified areas to review and add regression tests for:
- **Request policy:** allows all same-origin GET/HEAD, blocks off-origin, and
  permits an in-scope POST only for a pending form's document navigation. An
  in-scope GET can still mutate state (including a GET form action); the
  state-changing path skip-list only filters crawled links. The PATH_INFO
  fingerprint below is also a coarse status heuristic, not a vulnerability
  finding.
- **Form POST authorization:** the pending-submit grant is not bound to the exact
  query string, form identity, or body. Document-navigation binding prevents a
  racing fetch/XHR from consuming it, but the grant remains broader than one
  exact action URL. Snapshot/reload can reorder controls, so stored indices
  still merit revalidation.
- **WebSockets:** connections are intercepted and closed without upstream
  connection or frame forwarding, and are counted separately from HTTP
  requests. `ws://`/`wss://` URLs are now redacted/reported correctly. The
  behavior is integration-tested in Chromium but should be checked against
  other supported Playwright versions.
- **Storage state:** localStorage origins are filtered by exact canonical origin,
  but cookie domains allow multi-label parent-domain suffix matches. Single-label
  parent domains are rejected, but this is not a public-suffix-list check;
  cookie `url` fields pass through without their own origin validation.
- **Redaction:** query/fragment stripped and bodies/values omitted, but URL
  paths, page titles, cookie names, and storage key names are retained and could
  themselves carry sensitive data.
- **Budgets:** the HTTP cap counts requests allowed through; WebSockets are
  counted separately and the stored socket list is bounded. `max-pages` counts
  crawled documents, not temporary probe/form pages (active mode can create up
  to 10 extra pages per crawled page). Form-submission count records attempts,
  not confirmed network writes.
- **SPA timing:** RESOLVED 2026-11-16 — see "third browser pass" below
  (networkidle best-effort wait + `--settle-ms`).

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

## Open items
1. **PATH_INFO review — completed 2026-11-16.** The shared
   `http_request_timed` helper catches ordinary request/network exceptions and
   returns status `0`; the detector explicitly classifies `0` and `404` as
   non-permissive. The broad catch that was removed would have hidden
   unexpected programming errors, so it should stay removed. Added regressions
   for status `0` and unexpected exception propagation; no code bug was found.
   Residual caveat: any other status (including 401/403/5xx) is a permissive
   *heuristic* that only enables deeper tests; it is not itself reported as
   RCE. Revisit the status policy if fixtures show excessive unnecessary
   uploads.
2. **Inventory structure — coverage refreshed; structural map still needs
   review if skills, CLIs, dependencies, or plugin references move.** Inventory
   now includes bootstrap behavior and the 26 focused API-breaker regressions.
3. **Bootstrap + task preflight — implemented; deeper OS-specific install
   validation remains open.** Missing Python dependencies, Chromium, Go, Go
   recon tools, and allowlisted system tools are actively installed through
   available managers. Strict/narrow preflights stop dependent work if any
   required tool is still unavailable. Revisit package-manager behavior on
   clean Windows/macOS/Linux images. `amass` is deliberately excluded from
   managed installs until its v5 CLI and JSON-output behavior are verified
   against this repo's v4-style wrapper. Python requirement ranges and Go
   `@latest` references are still unpinned; research reproducible, verifiable
   pinning before tightening them.
   Preserve Windows fixes: `python3`, LF `hooks/hooks.json`, actual
   `hooks/hooks.json` path.
4. Consolidate the copied `_common.py` helpers? A sync check exists instead
   of consolidation. Map imports/CLI examples/plugin refs/tests before moving.
5. Continue skill deepening where meaningful gaps remain. `api-breaker` is still
   only partially audited: prioritize JWT edge-case tests, GraphQL depth/authz/
   CSRF behavior, BOLA/BFLA integration, rate-limit bypass/batching, business-
   state read-back, and report input shapes. Also continue the remaining browser
   scope/state/redaction edge cases and live-protocol methodology. Ground changes
   in primary-source research, bounded active probes, explicit evidence/confidence
   rules, and regression coverage. The matrices above do not prove complete
   coverage or absence of bugs.

## Standing constraints (don't re-introduce)
- HTTPS verified by default; `CATUS_INSECURE_TLS=1` is the only opt-out.
- Cross-origin redirects (incl. HTTP→HTTPS) are blocked by design — pass the
  final authorized origin when canonicalization crosses origins.
- Claude permission prompts preserved by default; `--dangerously-skip-permissions`
  stays an explicit operator choice.
- Author identity for commits: `FelixCatus <18648889+Felix1Catus@users.noreply.github.com>`.
