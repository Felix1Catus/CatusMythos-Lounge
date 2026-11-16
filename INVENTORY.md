# Skill inventory

Structural inventory of every skill: intended use, CLIs and their purpose,
dependencies, test coverage, scope controls, integrations, overlaps, and the
clearest coverage gaps. This is a map for prioritizing deeper per-skill review;
it is not itself a line-by-line doc-vs-code audit (that happens per skill).
Generated 2026-11-16 at `main` head `f870a85`.

## Shape of the toolkit

A `recon -> exploit -> chain -> report` pipeline plus specialized side skills.
The **core pipeline is stdlib-only by design** (no third-party packages);
`requirements.txt` carries just two optional packages:

- `requests>=2.31.0` — used by 4 scripts (chiefly `16-ai-llm-security`).
- `playwright>=1.48.0` — used by exactly one script
  (`webapp-exploit-hunter/scripts/browser_security_auditor.py`); its Chromium
  binary is separate (`python3 -m playwright install chromium`).

Plugin wiring (`.claude-plugin/plugin.json`): `skills -> ./skills`,
`agents -> ./agents/swarm-operator.md`, `hooks -> ./hooks/hooks.json`
(SessionStart bootstrap). One agent, no slash-command directory.

Supporting infrastructure outside `skills/`: `scripts/` (bootstrap +
check_common_sync + check_skill_cli_docs), `doctrine/`, `lounge/` (multi-seat
orchestration), `standalone-advanced/hooks/`, `research_notes/`, `tests/`.

## Test coverage at a glance

| Coverage | Skills |
|---|---|
| Has tests (full or partial) | `webapp-exploit-hunter` (partial), `api-breaker` (partial), `vuln-chain-composer` (partial), `web-cache-auditor` (full for its one script) |
| **Zero script tests** | `03-exploit-development`, `16-ai-llm-security`, `attack-path-architect`, `cloud-pivot-finder`, `recon-dominator` |
| No scripts (manual methodology) | `web-protocol-auditor` |

Tested scripts: `browser_security_auditor`, `dom_xss_auditor`, `crawler`,
`cache_audit`, `_common` (redirect scope), `auth_tester`, `auth_analyzer`,
`authz_tester`, `mass_assignment`, `sqli_tester`, `import_findings`,
`generate_poc`, `xss_tester`, plus repo infra (`bootstrap`,
`check_common_sync`, `check_skill_cli_docs`). **~15 of ~60 scripts.**

## Per-skill inventory

### recon-dominator — `[ZERO TESTS]`
- **Use:** full-scope recon from a domain/list — subdomains, ports, tech
  fingerprint, OSINT, Google dorking, Wayback, JS/source-map recon.
- **CLIs (10):** `passive_recon`, `active_recon`, `port_scanner`,
  `tech_fingerprint`, `osint_correlator`, `google_dorker`, `wayback_analyzer`,
  `cve_lookup`, `js_recon`, `generate_report`. Shares `_common.py` (109 ln).
- **Deps:** stdlib; may shell out to user-scoped Go recon tools when present.
- **Coverage:** none. Crawler/redirect tests live in `webapp-exploit-hunter`,
  not here. **Gap:** no end-to-end exercise of recon/OSINT/CVE/port-scan/report.
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
- **Coverage:** `browser_security_auditor` (full), `dom_xss_auditor` (full),
  `crawler` (discovery), `_common` (redirect), `auth_tester`/`sqli_tester`/
  `generate_poc`/`xss_tester` (partial, targeted-fix tests). **Untested:**
  `idor`, `lfi`, `ssrf`, `ssti`, `race`, `upload`, `waf_bypass`, `vuln_report`.
- **Scope controls:** `--active`, `--submit-forms`, `--callback-url`,
  `--allow-destructive-poc`, `--skip-lfi-chains`; HTTPS-verified default.

### api-breaker — `[PARTIAL TESTS]`
- **Use:** API security from domains — discover REST/GraphQL/SOAP, rebuild
  schemas, test BOLA/IDOR, BFLA, mass assignment, JWT, rate-limit bypass, logic.
- **CLIs (8 + `_common`):** `api_discovery`, `schema_builder` (1617 ln),
  `auth_analyzer`, `authz_tester`, `mass_assignment`, `rate_limiter`,
  `logic_tester`, `api_report`.
- **Coverage:** `auth_analyzer`/`authz_tester`/`mass_assignment` partial
  (hostile-import + mutation-gating tests). **Untested:** `api_discovery`,
  `schema_builder`, `rate_limiter`, `logic_tester`, `api_report`.
- **Scope controls:** `--allow-mutation-write` (BOLA/BFLA/mass-assignment write
  methods), explicit trusted `--api-base` for imported endpoints, cross-origin
  imported endpoints skipped.

### cloud-pivot-finder — `[ZERO TESTS]`
- **Use:** map cloud infra from domains; external->internal pivot paths —
  provider detection, S3/GCS/Azure enum, subdomain takeover, serverless, CI/CD
  and IaC leaks, metadata pivot paths.
- **CLIs (7 + `_common`):** `cloud_detector`, `bucket_enum`, `takeover_scanner`,
  `serverless_finder`, `cicd_finder`, `metadata_paths`, `cloud_report`.
- **Coverage:** none (repo-wide lint/timestamp/helper only). **Gap:** no
  domain-specific end-to-end tests. `bucket_enum` has a write-access test that
  only touches a canary it created (ethic reused by `upload_tester`).

### attack-path-architect — `[ZERO TESTS]`
- **Use:** attack trees/kill chains from recon or domain input; MITRE ATT&CK
  mapping, chaining opportunities, trust relationships, prioritization.
- **CLIs (5 + `_common`):** `classify_assets`, `map_trust`,
  `generate_attack_tree`, `mitre_mapper`, `engagement_planner`.
- **Coverage:** none. **Gap:** no end-to-end tree/kill-chain validation.
- **Overlaps:** prioritization/chaining logic overlaps `vuln-chain-composer`.

### vuln-chain-composer — `[PARTIAL TESTS]`
- **Use:** correlate findings across domains into multi-step chains, compute
  chained impact, generate end-to-end PoCs + bug-bounty reports.
- **CLIs (6 + `_common` 52 ln):** `import_findings` (771 ln), `correlate`,
  `build_chains`, `calculate_impact`, `generate_chain_poc`, `generate_report`.
- **Coverage:** `import_findings` partial (confidence/chainability, malformed
  input, candidate handling). **Untested:** `correlate`, `build_chains`,
  `calculate_impact`, `generate_chain_poc`. May emit TODO placeholder steps for
  some chain shapes.

### 16-ai-llm-security — `[ZERO TESTS]`
- **Use:** LLM/AI app security — prompt injection, jailbreak, OWASP LLM Top 10,
  RAG/vector-store, MCP/agent tool-use, model supply chain, unbounded
  consumption.
- **CLIs (5):** `prompt_injection_tester`, `rag_security_tester` (1128 ln),
  `mcp_security_tester` (968 ln), `model_supply_chain`,
  `unbounded_consumption_tester`.
- **Deps:** `requests` (HTTP to target API); `model_supply_chain` stdlib
  (bounded model/archive scanning, 64 MiB caps, streamed pickle opcodes).
- **Coverage:** HTTP/dependency/redirect paths reviewed, but **no adversarial
  tests** of prompt-injection, MCP, RAG, or consumption logic.

### 03-exploit-development — `[ZERO TESTS]`
- **Use:** PoC development + payload generation for a confirmed finding (CVE
  write-up -> working PoC; reverse/bind/web-shell delivery).
- **CLI (1):** `payload_generator` (351 ln). Stdlib-only.
- **Coverage:** none (generated-PoC safety hardening lives in `webapp`/`chain`
  generators, not here).

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
1. **`recon-dominator`** — 10 CLIs, zero tests; foundational to the pipeline.
2. **`cloud-pivot-finder`** — 7 CLIs, zero tests; high-impact pivots.
3. **`16-ai-llm-security`** — large, untested adversarial logic (RAG/MCP).
4. **`attack-path-architect`** — untested; overlaps `vuln-chain` correlation.
5. **Untested `webapp` active testers** — `idor`, `ssrf`, `ssti`, `race`,
   `upload`, `waf_bypass` have no per-script test matrix.
6. **`vuln-chain-composer`** correlation/impact/chain-generation paths.
