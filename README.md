<p align="center">
  <h1 align="center">CatusMythos-Lounge</h1>
  <p align="center">
    <strong>A web, API, and cloud penetration-testing plugin for Claude Code — one recon-to-report pipeline, plus AI/LLM app security and PoC tooling.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/Claude-Code-blueviolet.svg" alt="Claude Code">
    <img src="https://img.shields.io/badge/skills-8-orange.svg" alt="8 Skills">
    <img src="https://img.shields.io/badge/version-0.3.0-lightgrey.svg" alt="v0.3.0">
  </p>
</p>

---

> **Authorized security testing only.** Unauthorized access to computer
> systems is illegal. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

---

## What this is

CatusMythos-Lounge drives a full assessment of a web target — domain in,
report out — through eight purpose-built skills and an orchestrator agent.
It's stdlib-only (no `pip install` for the core pipeline), zero-config, and
runs as a normal Claude Code plugin or skill set.

- **A 6-stage pipeline**: recon → web/app exploitation → API testing →
  cloud pivoting → attack-path mapping → cross-finding correlation and
  reporting.
- **Two supporting skills**: AI/LLM application security testing, and a
  PoC/payload-generation helper for turning a confirmed finding into a
  deliverable.
- **Three ways to run it**: solo and sequential (default), a native
  in-process multi-agent mode for partitionable surfaces, or a full
  multi-seat "lounge" for true multi-model/multi-day engagements.
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
| 3 | `api-breaker` | API security testing | REST/GraphQL/SOAP discovery and schema reconstruction, BOLA/BFLA, JWT attacks (`kid` injection, `crit` bypass, algorithm confusion), mass assignment, business-logic flaws, rate-limit and legacy-version bypass |
| 4 | `cloud-pivot-finder` | Cloud infrastructure pivoting | Cloud provider detection, S3/GCS/Azure bucket enumeration, subdomain takeover, serverless/container endpoint discovery, CI/CD and IaC exposure, SSRF-to-metadata pivot mapping |
| 5 | `attack-path-architect` | Attack-path strategy | Asset classification, trust-relationship mapping, MITRE ATT&CK-mapped attack trees, exploit-chain discovery, engagement planning |
| 6 | `vuln-chain-composer` | Correlation and reporting | Cross-domain finding correlation, multi-step exploit-chain composition, CVSS impact scoring, end-to-end PoC generation, bug-bounty-ready reports |
| 7 | `16-ai-llm-security` | AI/LLM application security | Prompt injection and jailbreak testing, OWASP LLM Top 10 checks, MCP tool-poisoning and rug-pull detection, RAG security (cross-tenant leakage, embedding exposure), model supply-chain scanning |
| 8 | `03-exploit-development` | PoC development | CVE-to-PoC workflow and payload generation (reverse/bind/web-shell) for a finding the pipeline already confirmed |

### Operations by stage

| Stage | Script | What it does |
|---|---|---|
| Recon | `active_recon.py` / `passive_recon.py` | Subdomain enumeration, DNS brute-force, lame-delegation checks |
| Recon | `port_scanner.py` / `tech_fingerprint.py` | Port scanning, stack/CDN/WAF fingerprinting |
| Recon | `cve_lookup.py` | Version-matched CVE hypotheses (NVD + OSV) |
| Recon | `google_dorker.py` / `osint_correlator.py` / `js_recon.py` / `wayback_analyzer.py` | Dorking, OSINT, JS-bundle mining, historical snapshots |
| Web app | `sqli_tester.py` / `xss_tester.py` / `ssrf_tester.py` / `ssti_tester.py` | Injection-class vulnerability testing |
| Web app | `idor_tester.py` / `auth_tester.py` / `upload_tester.py` / `race_tester.py` | Access-control, auth, upload, and race-condition testing |
| Web app | `waf_bypass_tester.py` / `crawler.py` / `generate_poc.py` | WAF/rate-limit bypass, crawling, PoC generation |
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
budgets underneath all three modes — see `doctrine/CLAUDE_ENFORCEMENT.md`.

## Installation

### As a Claude Code plugin (recommended)

```bash
/plugin install catusmythos-lounge --marketplace Felix1Catus/CatusMythos-Lounge
```

Or as two steps:

```bash
claude plugin marketplace add Felix1Catus/CatusMythos-Lounge
claude plugin install catusmythos-lounge@catusmythos-lounge-marketplace
```

### Skills only, without the plugin machinery

```bash
git clone https://github.com/Felix1Catus/CatusMythos-Lounge.git
cd CatusMythos-Lounge

mkdir -p ~/.claude/skills      # or .claude/skills for project-local
cp -r skills/* ~/.claude/skills/
```

### Requirements

- Python 3.8+ (standard library only — no `pip install` needed for the
  core pipeline)
- Claude Code with skills support
- Optional, for faster recon: `subfinder`, `httpx`, `puredns`, `naabu`,
  `dig`, `whois`, `nmap`

## Usage

Talk to Claude naturally:

```
Run full reconnaissance on target.com
Find vulnerabilities on app.target.com
Test this API for BOLA and mass assignment issues
Map the cloud infrastructure behind app.target.com
Chain all findings and generate a bug bounty report
Test this chatbot feature for prompt injection
Build a PoC for the file-upload RCE you just confirmed
```

Or invoke the orchestrator for a full engagement:

```
Use the swarm-operator agent to run a full assessment of target.com
```

## Status

v0.3.0 — all 8 skills have working, stdlib-only scripts; each pipeline
stage has had a research-driven depth pass with real citations
(`research_notes/`, `reports/`). Not yet done: a from-scratch test suite
exercising the full pipeline end-to-end, and a non-Claude engine variant.

## Credits

CatusMythos-Lounge builds on prior work, used and adapted under MIT terms.
Full attribution and per-file provenance: [NOTICE.md](NOTICE.md),
[CREDITS.md](CREDITS.md), [MERGE_MAP.md](MERGE_MAP.md).

- The **mythos-lounge** project — the doctrine engine and multi-seat
  coordination protocol.
