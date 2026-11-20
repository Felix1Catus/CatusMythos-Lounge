<p align="center">
  <h1 align="center">CatusMythos-Lounge</h1>
  <p align="center">Created and maintained by <strong>Felix Catus</strong> (<a href="https://github.com/Felix1Catus">Felix1Catus</a>).</p>
  <p align="center">
    <strong>A web, API, cloud, and AI/LLM security assessment toolkit with scoped scanners, campaign orchestration, and evidence-based reporting.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/skills-10-orange.svg" alt="10 Skills">
    <img src="https://img.shields.io/badge/version-0.3.0-lightgrey.svg" alt="v0.3.0">
  </p>
</p>

---

> **Authorized security testing only.** Unauthorized access to computer
> systems is illegal. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

---

## What this is

CatusMythos-Lounge provides ten purpose-built security skills and a campaign
runner for authorized web, API, and cloud assessments. Most command-line
scanners use Python's standard library; browser-backed checks use Playwright
and Chromium. Run a focused skill directly, or use a campaign manifest for
scoped, budgeted testing with explicit coverage and incomplete-state reporting.

- **A 6-stage pipeline**: recon → web/app exploitation → API testing →
  cloud pivoting → attack-path mapping → cross-finding correlation and
  reporting.
- **Four specialist skills**: web-cache behavior auditing, HTTP/WebSocket
  protocol review, AI/LLM application security testing, and PoC/payload
  generation for turning a confirmed finding into a deliverable.
- **Multiple operating modes**: run focused skills, use the campaign runner,
  or coordinate a larger assessment through the orchestrator and lounge tools.
- **A doctrine layer** underneath all three — evidence-first discipline,
  probe budgets, and report-only-when-real rules enforced regardless of
  which mode is running.

## The pipeline

```
 DOMAIN
   │
   ▼
 recon-dominator        subdomain enum · port scan · tech fingerprint · OSINT · CVE match
   │
   ├──► webapp-exploit-hunter   SQLi · XSS · SSRF · SSTI · IDOR · auth bypass · upload · WAF bypass
   ├──► web-cache-auditor       cache keys · unkeyed inputs · cache deception · URL normalization
   ├──► web-protocol-auditor    HTTP desynchronization review · HTTP/2 transitions · WebSocket security
   ├──► api-breaker             REST/GraphQL/SOAP discovery · BOLA/BFLA · JWT · mass assignment
   └──► cloud-pivot-finder      cloud detection · bucket/takeover/CI-CD/serverless exposure
                │
                ▼
        attack-path-architect   asset/trust mapping · MITRE ATT&CK trees · kill chains
                │
                ▼
        vuln-chain-composer     cross-domain correlation · exploit chains · CVSS · reports
```

## Skills

| # | Skill | Role | Key operations |
|---|---|---|---|
| 1 | `recon-dominator` | Attack-surface mapping | Subdomain enumeration, port scanning, tech fingerprinting (incl. WAF/CDN), Google dorking, Wayback analysis, OSINT correlation, NVD/OSV-backed CVE matching, NS lame-delegation ("Sitting Ducks") checks |
| 2 | `webapp-exploit-hunter` | Web app exploitation | SQLi, XSS, SSRF, SSTI, IDOR, auth bypass, file-upload bypass, race conditions, WAF/rate-limit bypass (parameter pollution, header mutation, boundary differentials) |
| 3 | `web-cache-auditor` | Web cache and CDN testing | Cache signals, inert unkeyed-input canaries, opt-in staging replay checks, cache deception and URL-normalization methodology |
| 4 | `web-protocol-auditor` | HTTP and WebSocket protocol review | Research-guided parser-discrepancy assessment, HTTP/2 downgrade review, request-smuggling evidence grading, WebSocket Origin/authz/message-boundary coverage |
| 5 | `api-breaker` | API security testing | REST/GraphQL/SOAP discovery and schema reconstruction, BOLA/BFLA, JWT attacks (`kid` injection, `crit` bypass, algorithm confusion), mass assignment, business-logic flaws, rate-limit and legacy-version bypass |
| 6 | `cloud-pivot-finder` | Cloud infrastructure pivoting | Cloud provider detection, S3/GCS/Azure bucket enumeration, subdomain takeover, serverless/container endpoint discovery, CI/CD and IaC exposure, SSRF-to-metadata pivot mapping |
| 7 | `attack-path-architect` | Attack-path strategy | Asset classification, trust-relationship mapping, MITRE ATT&CK-mapped attack trees, exploit-chain discovery, engagement planning |
| 8 | `vuln-chain-composer` | Correlation and reporting | Cross-domain finding correlation, multi-step exploit-chain composition, CVSS impact scoring, end-to-end PoC generation, bug-bounty-ready reports |
| 9 | `16-ai-llm-security` | AI/LLM application security | Prompt injection and jailbreak testing, OWASP LLM Top 10 checks, MCP tool-poisoning and rug-pull detection, RAG security (cross-tenant leakage, embedding exposure), model supply-chain scanning |
| 10 | `03-exploit-development` | PoC development | CVE-to-PoC workflow and payload generation (reverse/bind/web-shell) for a finding the pipeline already confirmed |

### Operations by stage

| Stage | Script | What it does |
|---|---|---|
| Recon | `active_recon.py` / `passive_recon.py` | Subdomain enumeration, DNS brute-force, lame-delegation checks |
| Recon | `port_scanner.py` / `tech_fingerprint.py` | Port scanning, stack/CDN/WAF fingerprinting |
| Recon | `cve_lookup.py` | Version-matched CVE hypotheses (NVD + OSV) |
| Recon | `google_dorker.py` / `osint_correlator.py` / `js_recon.py` / `wayback_analyzer.py` | Dorking, OSINT, JS-bundle mining, historical snapshots |
| Web app | `sqli_tester.py` / `xss_tester.py` / `dom_xss_auditor.py` / `browser_security_auditor.py` / `ssrf_tester.py` / `ssti_tester.py` | Injection checks, static DOM XSS leads, and isolated browser checks for runtime DOM execution, storage, cookie flags, messages, forms, and headers |
| Web app | `idor_tester.py` / `auth_tester.py` / `race_tester.py` | Access-control, auth, and race-condition testing |
| Web app | `lfi_tester.py` | LFI/path-traversal (incl. sibling-parameter-gated sanitization), XXE including the `php://filter`-as-SSRF variant, and PHP object-injection surface detection — from a real disclosed LFI→deserialization→XXE→SSRF→RCE chain |
| Web app | `upload_tester.py` | File-upload bypass + **stack-aware PHP RCE**: fingerprints nginx/Apache/Caddy/FrankenPHP first, then runs the matching strategy — PATH_INFO path confusion (CVE-2019-11043/2026-27590/2026-24895 class), Apache `.htaccess` handler remap, or direct php-fpm/FastCGI TCP exposure (common in unhardened Docker) via a minimal stdlib FastCGI client |
| Web app | `waf_bypass_tester.py` / `crawler.py` / `generate_poc.py` | WAF/rate-limit bypass, crawling, PoC generation |
| Web cache | `cache_audit.py` | Cache headers, inert unkeyed-input canaries, and explicit replay validation for isolated staging caches |
| Web protocols | `web-protocol-auditor/SKILL.md` | Manual HTTP parser/proxy review and WebSocket handshake, authorization, state, and message-boundary coverage; optional external analysis tools |
| API | `api_discovery.py` / `schema_builder.py` | Endpoint discovery, REST/GraphQL schema reconstruction |
| API | `auth_analyzer.py` / `authz_tester.py` | JWT attacks, BOLA/BFLA |
| API | `mass_assignment.py` / `logic_tester.py` / `rate_limiter.py` | Mass assignment, business logic, rate-limit bypass |
| Cloud | `cloud_detector.py` / `bucket_enum.py` | Provider detection, storage bucket enumeration |
| Cloud | `takeover_scanner.py` / `metadata_paths.py` | Subdomain takeover, SSRF-to-metadata pivot mapping |
| Cloud | `serverless_finder.py` / `cicd_finder.py` | Serverless/container discovery, CI/CD and IaC exposure |
| Attack paths | `classify_assets.py` / `map_trust.py` | Asset classification, trust-relationship graphing |
| Attack paths | `generate_attack_tree.py` / `mitre_mapper.py` | Attack-tree generation, MITRE ATT&CK/ATLAS mapping |
| Attack paths | `engagement_planner.py` | Rules-of-engagement and engagement scoping |
| Correlation | `import_findings.py` / `correlate.py` | Normalize findings, discover exploit chains |
| Correlation | `calculate_impact.py` / `build_chains.py` | CVSS scoring, chain assembly |
| Correlation | `generate_chain_poc.py` / `generate_report.py` | End-to-end PoC, final report |
| AI/LLM security | `prompt_injection_tester.py` / `unbounded_consumption_tester.py` | Jailbreak/injection testing, OWASP LLM10 checks |
| AI/LLM security | `mcp_security_tester.py` / `rag_security_tester.py` | MCP tool-poisoning/rug-pull, RAG tenant-isolation testing |
| AI/LLM security | `model_supply_chain.py` | Malicious model-artifact scanning |
| PoC dev | `payload_generator.py` | Reverse/bind shell and web-shell payload generation |

## Orchestration

| Mode | When to use | How |
|---|---|---|
| Solo (default) | Most engagements | Run skills in sequence, driven by `swarm-operator` |
| Native multi-agent | One session, a surface that splits cleanly (≥3 hosts, or clearly separate web/API/cloud surfaces) | Static work partition, parallel subagents, one merge + skeptic-review step |
| Lounge (multi-seat) | True multi-model or multi-day engagements | `lounge/seatlib.py` — claim/token/push coordination across independent processes, optionally different AI CLIs/accounts |

A doctrine layer (`doctrine/`) enforces evidence-first discipline and probe
budgets underneath all operating modes — see `doctrine/` for the policies and
protocols.

## Installation

### Claude Code plugin

This repository is packaged natively as a Claude Code plugin. From a shell,
register its marketplace and install the plugin:

```bash
claude plugin marketplace add Felix1Catus/CatusMythos-Lounge
claude plugin install catusmythos-lounge@catusmythos-lounge-marketplace
```

Alternatively, in a Claude Code session run:

```text
/plugin install catusmythos-lounge --marketplace Felix1Catus/CatusMythos-Lounge
```

Choose the install scope, then start or reload the session. See the
[Claude Code plugin installation guide](https://code.claude.com/docs/en/plugins/install).

### Codex plugin

This repository includes a Codex-compatible plugin manifest and a local
marketplace entry. From the repository root, register the checkout and install
the plugin:

```powershell
codex plugin marketplace add .
codex plugin add catusmythos-lounge@catusmythos-lounge-local
```

Restart Codex or start a new session after installation. The plugin installs
the skills together with their bundled `skills/<skill-name>/scripts/` and
supporting files. Open this repository as the Codex project when a workflow
uses shared repository data or the campaign runner. For the full campaign CLI,
run `scripts/assessment_campaign.py assess` from the repository root; the
plugin package does not include Claude Code hooks or the `swarm-operator`
agent entrypoint. Codex uses the plugin's local executor for workflows that
run bundled scripts.

You can confirm the install with:

```powershell
codex plugin list
```

### Dependency setup

After installing the plugin or skills, clone/open the repository and run the
preflight from its root:

```bash
python3 scripts/bootstrap.py --strict
```

The strict preflight installs/verifies the complete managed tool stack and
exits nonzero when a required dependency is unavailable. For one focused task,
use a smaller preflight instead of installing every optional recon tool:

For one focused task, use a smaller preflight instead of installing every
optional recon tool:

```bash
python3 scripts/bootstrap.py --require-tool chromium
python3 scripts/bootstrap.py --require-python requests
```

Python scanner core uses the standard library; optional integrations need
additional packages/tools. Browser checks require Playwright and Chromium.
Faster recon may use `subfinder`, `httpx`, `puredns`, `naabu`, `dig`, `whois`,
or `nmap`. The bootstrap uses package managers already installed on the host;
system package installation may require administrator permission.

`amass` remains manual until its installed CLI proves it can perform the
required wordlist enumeration and produce structured results. See
`scripts/bootstrap.py` for the current unblock criteria.

HTTPS certificate checks are enabled by default. For an authorized
self-signed target, set `CATUS_INSECURE_TLS=1` only for that run; this disables
certificate validation for the toolkit's HTTP probes and generated Python
PoCs.

HTTP clients follow redirects only when scheme, host, and port stay the same.
For an authorized target that redirects across origins (including HTTP to
HTTPS), supply the final in-scope URL directly; session headers are not
forwarded to a different origin.

## Usage

Example requests for an agent host that has loaded these skills:

```
Run full reconnaissance on target.com
Find vulnerabilities on app.target.com
Test this API for BOLA and mass assignment issues
Map the cloud infrastructure behind app.target.com
Chain all findings and generate a bug bounty report
Test this chatbot feature for prompt injection
Audit cache behavior on staging.example.com for unkeyed inputs
Build a PoC for the file-upload RCE you just confirmed
```

Or invoke the orchestrator agent for a full engagement:

```
Run a full assessment of target.com with the swarm-operator agent
```

For a repeatable core web/API pass, create a campaign from
[`doctrine/templates/ASSESSMENT_CAMPAIGN.json`](doctrine/templates/ASSESSMENT_CAMPAIGN.json),
then edit the engagement label, exact authorized origin, and role names. The
template's credential fields are environment-variable **names**; put actual
tokens/cookies in your shell or secret manager, never in the JSON file or
scanner arguments. The core profile expects anonymous plus at least two
credentialed identities, including the role ordering used by authorization
checks.

From the repository root:

```bash
mkdir -p targets/assessment
cp doctrine/templates/ASSESSMENT_CAMPAIGN.json targets/assessment/campaign.json
# Edit campaign.json to replace the example origin and engagement label.
# Set APP_USER_A_AUTHORIZATION, APP_USER_B_AUTHORIZATION, and
# APP_ADMIN_AUTHORIZATION in the current shell/secret manager first.
python3 scripts/assessment_campaign.py plan \
  --manifest targets/assessment/campaign.json \
  --output targets/assessment/plan.json
```

Review the plan's origins, roles, dependencies, request budget, and
state-change policy. Then execute:

```bash
python3 scripts/assessment_campaign.py assess \
  --manifest targets/assessment/campaign.json \
  --state-db targets/assessment/campaign.sqlite \
  --campaign-id assessment-2026-11 \
  --output targets/assessment/assessment.json
```

`assess` runs only the registered steps in the manifest and meters their
requests in one local SQLite ledger. It writes a sanitized summary to
`assessment.json` and per-tool JSON under `assessment_artifacts/`. Exit code
`0` means all required steps completed; exit code `2` means a required step was
blocked, failed, throttled, or incomplete. Incomplete is **not** a clean scan.
The report shows which steps need credentials, input artifacts, or tools.
Browser checks preflight Playwright/Chromium automatically. Active form writes
remain off unless you explicitly opt into a scenario with scope authorization
and cleanup. See [campaign usage](scripts/ASSESSMENT_CAMPAIGN.md).

The `core_web_api_v1` campaign profile is the release-gated web/API baseline.
It requires anonymous and authenticated tests for crawling, injection, LFI,
SSRF, and browser behavior, plus sensitive-file checks, API inventory, and
authorization tests. Put disposable user credentials in the environment under
the names in the manifest; never put tokens in manifest arguments. Missing
accounts, preflight failures, request caps, or untested required stages make
the assessment incomplete. Pull requests run the pinned DVWA, Juice Shop, and
crAPI lab suite and fail unless all labeled positive cases are confirmed and
all negative controls remain negative. This gate measures the pinned lab set;
it is not a promise of universal detection on arbitrary applications.

## Local checks

Run the focused stdlib regression tests and the cache auditor's offline
self-check from the repository root:

```bash
python3 -m unittest discover -s tests
python3 scripts/check_common_sync.py
python3 scripts/check_skill_cli_docs.py
python3 skills/web-cache-auditor/scripts/cache_audit.py --demo
```

Optional contributor check (requires Ruff): `python3 -m ruff check .`.

## Status

v0.3.0 — ten security skills, a campaign runner, and a pinned-lab release gate.
The core web/API release profile covers anonymous and authenticated crawling,
injection, LFI/path traversal, SSRF, browser checks, API inventory, and
authorization. Each pull request runs the regression suite and the pinned
DVWA/Juice Shop/crAPI lab matrix. Passing that labeled matrix is a reproducible
baseline, not a guarantee that every vulnerability on an arbitrary target will
be found.

## Credits

CatusMythos-Lounge is created and maintained by **Felix Catus**. It builds on
prior work used and adapted under their respective MIT terms.
Full attribution and per-file provenance: [NOTICE.md](NOTICE.md),
[CREDITS.md](CREDITS.md), [MERGE_MAP.md](MERGE_MAP.md).

- The **mythos-lounge** project — the doctrine engine and multi-seat
  coordination protocol.
