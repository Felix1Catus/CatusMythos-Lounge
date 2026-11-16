# Skill inventory

Structural inventory of every skill: intended use, CLIs and their purpose,
dependencies, test coverage, scope controls, integrations, overlaps, and the
clearest coverage gaps. This is a map for prioritizing deeper per-skill review;
it is not itself a line-by-line doc-vs-code audit (that happens per skill).
Inventory structure originated at `f870a85`. Coverage status refreshed
2026-11-16 against the verified `3aa2f62` bootstrap baseline, the API-breaker
continuation from `a95bab9`, the BOLA URL fix at `9efbba5`, and the BOLA/BFLA
evidence follow-up at `511a522`, and JWT/auth hardening at `68dd243`. Check
`git log -1` for the exact current tip.

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
| Broad script-level regression matrices | `recon-dominator` (59), `cloud-pivot-finder` (38), `attack-path-architect` (28), `16-ai-llm-security` (87), `03-exploit-development` (14), `vuln-chain-composer` (63), legacy `webapp-exploit-hunter` testers (60) |
| Focused or partial coverage | `api-breaker` (46 focused scope/discovery/business-logic/GraphQL-CSRF/BOLA/BFLA/auth-analyzer regressions); `webapp-exploit-hunter` browser/crawler/DOM and selected CLI paths; `web-cache-auditor` (8 tests for its script) |
| Plugin infrastructure | `tests/test_bootstrap.py` (30): parsing, install command construction, retry/cache validation, browser setup, PATH readiness, and nonzero preflight gates |
| No scripts (manual methodology) | `web-protocol-auditor` |

The full suite most recently passed **520 tests plus 25 subtests**. It includes
local-fixture browser integration with Playwright/Chromium, bootstrap
regressions, and the new API-breaker matrix. The strict bootstrap preflight also
passed on the current Windows host. Coverage is uneven:
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
  and allowlisted DNS/WHOIS/Nmap/Perl commands. `amass` is deliberately not
  managed yet because the current wrapper uses a v4-style invocation and
  parses JSON from stdout; verify the current v5 CLI/output behavior before
  enabling it automatically.
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
  DOM XSS (static + browser), plus browser runtime auditor.
- **CLIs (15):** `crawler`, `auth_tester`, `sqli_tester`, `xss_tester`,
  `dom_xss_auditor`, `ssrf_tester`, `ssti_tester`, `idor_tester`, `lfi_tester`,
  `upload_tester` (largest, 1201 ln), `race_tester`, `waf_bypass_tester`,
  `browser_security_auditor`, `generate_poc`, `vuln_report`. `_common.py` (162).
- **Deps:** stdlib + playwright (browser auditor only).
- **Coverage:** `tests/test_webapp_legacy_testers.py` adds a 60-test offline
  matrix for LFI, upload, race, SSRF, SSTI, IDOR, XSS, and WAF-bypass logic;
  network calls are mocked. Browser auditor has pure-function and local
  Playwright/Chromium integration coverage; DOM reviewer, crawler, redirect
  helper, and selected auth/SQLi/PoC/report paths have targeted coverage.
  **Still partial:** auth_tester/sqli_tester network workflows, generate_poc,
  vuln_report, browser state/redaction boundaries, and full multi-step upload
  paths are not exhaustively exercised.
- **Scope controls:** `--active`, `--submit-forms`, `--callback-url`,
  `--allow-destructive-poc`, `--skip-lfi-chains`; HTTPS-verified default.

### api-breaker — `[26 FOCUSED REGRESSIONS; STILL PARTIAL]`
- **Use:** API security from domains — discover REST/GraphQL/SOAP, rebuild
  schemas, test BOLA/IDOR, BFLA, mass assignment, JWT, rate-limit bypass, logic.
- **CLIs (8 + `_common`):** `api_discovery`, `schema_builder` (1647 ln),
  `auth_analyzer`, `authz_tester`, `mass_assignment`, `rate_limiter`,
  `logic_tester`, `api_report`.
- **Coverage:** `tests/test_api_breaker.py` covers same-origin JavaScript
  discovery, imported endpoint scoping in `schema_builder`/`rate_limiter`/
  `logic_tester`, bounded rate-test counts, active-probe preservation, duplicate
  single-endpoint submissions, candidate-confidence/report mapping, and the
  explicit-cookie/canary requirements for active GraphQL CSRF GET/form submits.
  `tests/test_targeted_audit_fixes.py` covers hostile imports and write gating
  in `auth_analyzer`, `authz_tester`, and `mass_assignment`. This is not a full
  per-script matrix: JWT attack cases, GraphQL depth/authz/CSRF, BOLA/BFLA
  integration, rate-limit bypass/batching, business-state read-back, and broad
  report input shapes remain lightly tested or untested.
- **Scope controls:** explicit trusted `--api-base` for imported endpoints in
  schema, auth, authz, mass assignment, rate-limit, and business-logic testing;
  off-origin imported endpoints are skipped. `--allow-mutation-write` gates
  BOLA/BFLA, GraphQL mutation-BOLA, and mass-assignment writes. GraphQL CSRF
  GET/form mutations require `--cookie` and `--csrf-test-id`. Business-logic
  POST/PUT/PATCH payloads remain active without a new flag when selected.
  Rate-limit `--count` is bounded to 1–1000 (default 120).

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

### vuln-chain-composer — `[63-TEST MATRIX; all 7 scripts covered]`
- **Use:** correlate findings across domains into multi-step chains, compute
  chained impact, generate end-to-end PoCs + bug-bounty reports.
- **CLIs (6 + `_common` 52 ln):** `import_findings` (771 ln), `correlate`,
  `build_chains`, `calculate_impact`, `generate_chain_poc`, `generate_report`.
- **Coverage:** `tests/test_vuln_chain_composer.py` covers all seven scripts'
  key normalization, evidence, chaining, CVSS, PoC, and report logic. It fixes
  category derivation that suppressed multi-word finding chains. Some generated
  chain PoCs intentionally contain operator-filled TODO scaffolds; arbitrary
  chains are not guaranteed to become fully executable reproductions.

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

### web-cache-auditor — `[FULL TESTS for its script]`
- **Use:** CDN/cache behavior — cache-key inputs, unkeyed header reflection,
  poisoning preconditions, deception indicators, URL normalization.
- **CLI (1):** `cache_audit` (376 ln). Stdlib.
- **Coverage:** `test_cache_audit.py` (URL validation/redaction, evidence,
  bounded reads, redirect isolation, findings import). Separates reflection from
  cache replay.
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

## Prioritized gaps (for the deepening phase)
1. **`api-breaker`** — several CLIs (`api_discovery`, `schema_builder`,
   `rate_limiter`, `logic_tester`, `api_report`) still lack broad per-script
   regression matrices; write-probe and imported-scope behavior needs continued
   active, authorized validation.
2. **`webapp-exploit-hunter`** — most legacy tester logic now has offline
   coverage, but auth/SQLi network paths, generated reports, and chained upload
   flows need deeper integration fixtures. Continue browser state/redaction and
   form-authorization edge coverage.
3. **`vuln-chain-composer`** — broad matrix added; continue testing unseen input
   shapes and pipeline-level integration, especially arbitrary chain outputs.
4. **Live workflow integration** — current matrices are mainly unit-level or
   loopback fixtures. Exercise full authorized recon→test→import→chain→report
   flows using local fixtures before claiming end-to-end coverage.
5. **`web-protocol-auditor`** — manual methodology only; update against current
   primary sources and validate its steps in an isolated lab where feasible.
