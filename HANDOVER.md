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
- Verification: 105 unit tests + 21 subtests pass; Ruff clean; compileall ok;
  CLI-docs 10/94/58; shared helpers in sync.
- The browser auditor has now had a **real Playwright/Chromium integration run**
  against a local fixture (passive, active query, active fragment via both
  `innerHTML` and `document.write`, and form submission all exercised). Two bugs
  were found and fixed (see below). `tests/test_browser_security_auditor.py`
  adds pure-function coverage plus a Chromium-gated live test that skips cleanly
  when the browser is absent.

## Depth of review so far (self-reported by the audit author, not yet
independently re-verified line by line)

**Deepest automated coverage:** cache-audit helpers, static DOM analysis,
crawler discovery, redirect scope, selected imported-API data handling, XSS
finding-confidence, PoC-generation safety.

**Shallowest / highest bug-risk — prioritize these:**
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
  regression coverage (58-test matrix in `tests/test_recon_dominator.py`).
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
- `03-exploit-development` — only the model-artifact scanner was hardened.
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

## Browser auditor — verified by integration run (2026-11-16)
- **Working:** missing-header/cookie-flag/sensitive-storage findings; off-origin
  request blocking + counting; WebSocket interception (no upstream connect);
  active query DOM-XSS (svg+img); active fragment DOM-XSS (svg fired via both
  `innerHTML` and `document.write` in the tested Chromium); form submission with
  marker execution; `/logout`-style links skipped.
- **Fixed in `b-fix` commit:** (1) `redact_url` now reports `ws://`/`wss://`
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
- **Still open:** the 250 ms settle can miss async SPA state; fragment/form
  probes use the svg variant only (worked in the tested Chromium, but the img
  variant is a cheap cross-version robustness add since svg-onload-via-innerHTML
  is engine-dependent).

## Open items
1. Optional browser-auditor robustness: add the img-variant to fragment/form
   probes (cross-engine), and consider a networkidle/longer settle for SPAs.
   Re-examine the `upload_tester.py` PATH_INFO probe whose broad exception catch
   was removed (unexpected exceptions now propagate).
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
