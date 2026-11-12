<p align="center">
  <h1 align="center">CatusMythos-Lounge</h1>
  <p align="center">
    <strong>A merged Claude Code security toolkit: one pipeline, 24 skills, a doctrine engine, and a multi-seat collaboration protocol.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/Claude-Code-blueviolet.svg" alt="Claude Code">
    <img src="https://img.shields.io/badge/skills-24-orange.svg" alt="24 Skills">
  </p>
</p>

---

> **Authorized security testing only.** Unauthorized access to computer
> systems is illegal. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

---

## What this is

Three real projects, combined so each covers what the others miss:

1. **[Felix1Catus/claude-code-pentest](https://github.com/Felix1Catus/claude-code-pentest)**
   (fork of [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest))
   — a 6-skill, 43-script, zero-dependency pipeline that takes a domain from
   recon through exploitation to a bug-bounty-ready report. **Its workflow is
   this repo's execution backbone, unchanged.**
 
   — 22 skills covering the rest of security work the pipeline doesn't touch:
   malware analysis, reverse engineering, incident response, mobile, OT/ICS,
   cryptography, GRC/compliance, supply chain, threat intel, purple team,
   blue team defense, AI/LLM security, and more. **Its domain breadth is
   added wholesale**, and the four places it overlaps the pipeline had their
   *scripts* folded in rather than shipping a redundant second tool.
2. **mythos-lounge** — a doctrine engine (evidence-first discipline, probe
   budgets, report-only-when-real) and a multi-seat collaboration protocol
   (`seatlib.py`) that lets several agents hunt one target in the same
   window without duplicating work. **This is the governance and
   coordination layer** that sits above both skill sets, usable solo or as
   a table of seats.

See [MERGE_MAP.md](MERGE_MAP.md) for the exact, file-by-file account of what
was combined, what was kept separate, and why — nothing was silently
dropped. See [NOTICE.md](NOTICE.md) and [CREDITS.md](CREDITS.md) for
attribution, which this repo is contractually obligated to preserve under
the MIT terms each source shipped with.

## Architecture

```
                    ┌─────────────────────────────┐
                    │   doctrine/   (governance)   │
                    │  P01-P14 protocols, bootkit   │
                    │  role cards, probe budgets,   │
                    │  evidence-first, resume hooks  │
                    └───────────────┬───────────────┘
                                    │ enforced on every seat
                    ┌───────────────▼───────────────┐
                    │    lounge/   (coordination)    │
                    │  seatlib.py claim/token/push    │
                    │  — solo seat, or a table of     │
                    │  several seats on one target     │
                    └───────────────┬───────────────┘
                                    │ drives
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                          ▼
┌─────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│  skills/ pipeline     │  │  skills/ domain breadth │  │  agents/ entry points  │
│  (Felix1Catus)         │  │  (Masriyan, 18 skills)  │  │  swarm-operator, etc.  │
│                        │  │                         │  │                        │
│  recon-dominator        │  │  03 exploit-dev ...     │  └───────────────────────┘
│    -> webapp-exploit-   │  │  22 purple-team         │
│       hunter            │  │                         │
│    -> api-breaker       │  │  (03-22 minus the 4     │
│    -> cloud-pivot-      │  │  the pipeline overlaps; │
│       finder             │  │  their scripts were     │
│    -> attack-path-       │  │  folded into the        │
│       architect           │  │  pipeline instead)      │
│    -> vuln-chain-        │  │                         │
│       composer            │  │                         │
└─────────────────────┘  └───────────────────────┘
```

## The pipeline (unchanged from Felix1Catus / Orizon-eu)

```
DOMAIN INPUT
    │
    ▼
recon-dominator        subdomain enum, port scan, OSINT, dorking, Wayback
    │                  + Masriyan's WAF/CDN/analytics detection merged into tech_fingerprint.py
    │                  + Masriyan's wildcard-DNS suppression merged into active_recon.py
    │                  + folded-in as-is: dns_recon.py (SPF/DMARC/reverse-DNS, zero overlap)
    ├──► webapp-exploit-hunter   SQLi, XSS, SSRF, SSTI, IDOR, auth bypass, upload, race
    │        + Masriyan's server-version-disclosure check merged into auth_tester.py
    ├──► api-breaker             API discovery, BOLA/BFLA, JWT, mass assignment, GraphQL
    │        (assessed Masriyan's api_security_tester.py — every check it ran was already
    │         covered more thoroughly by Felix's own scripts; nothing to add)
    └──► cloud-pivot-finder      cloud detection, bucket/takeover/CI-CD/serverless exposure
             + folded-in as-is: cloud_auditor.py, iac_scanner.py (different access model —
               authenticated cloud posture + at-rest IaC, genuinely complementary)
                 │
                 ▼
         attack-path-architect   asset/trust mapping, MITRE ATT&CK trees, kill chains
             + folded-in as-is: mitre_mapper.py (ATT&CK technique DB + SIEM queries),
               engagement_planner.py — both zero-overlap new capability
                 │
                 ▼
         vuln-chain-composer     cross-domain correlation, exploit chains, CVSS, reports
             + Masriyan's spec-correct CVSS round-up merged into calculate_impact.py
             + folded-in as-is: cvss_calculator.py, dependency_auditor.py, config_auditor.py
```

Every one of those merge decisions — what got ported into an existing
script vs. shipped alongside it vs. left out entirely, and why — is
assessed and recorded file-by-file in [MERGE_MAP.md](MERGE_MAP.md), not
just asserted here.

## Everything else (Masriyan's domain coverage, shipped standalone)

| # | Skill | Domain |
|---|---|---|
| 03 | exploit-development | PoC templates, payload generation |
| 04 | reverse-engineering | Binary triage, firmware RE, protocol reversing |
| 05 | malware-analysis | Static/dynamic analysis, YARA, IOC extraction |
| 06 | threat-hunting | ATT&CK mapping, hunt hypotheses, Sigma rules |
| 07 | incident-response | PICERL, evidence collection, memory forensics |
| 08 | network-security | PCAP analysis, IDS/IPS rules, firewall auditing |
| 11 | csoc-automation | Alert triage, playbooks, shift reporting |
| 12 | log-analysis | SIEM queries, Sigma rules, correlation |
| 13 | crypto-analysis | TLS auditing, cipher/hash analysis |
| 14 | red-team-ops | Engagement planning, C2, AD attacks, OPSEC |
| 15 | blue-team-defense | Hardening, detection engineering, baselines |
| 16 | ai-llm-security | Prompt injection, OWASP LLM Top 10, RAG/agent security |
| 17 | mobile-security | Android/iOS, MASVS/MASTG, APK/IPA triage |
| 18 | ot-ics-security | Purdue model, Modbus/DNP3/S7, IEC 62443 |
| 19 | grc-compliance | Risk scoring, NIST/ISO/SOC2 crosswalk |
| 20 | supply-chain-security | SBOM, dependency confusion, CI/CD hardening |
| 21 | threat-intelligence | IOC pipeline, STIX/MISP, Diamond/Kill Chain |
| 22 | purple-team | Adversary emulation, detection coverage |

## The lounge (multi-seat mode)

When one target is big enough to want several agents working it
concurrently without re-firing the same request, `lounge/seatlib.py` gives
every seat claim/token/push primitives: claim an exact cell before probing
it, pull a rate-limit token before every network request, and push your
next finding to the other live seats the moment a class flips. Read
[lounge/LOUNGE_PROTOCOL.md](lounge/LOUNGE_PROTOCOL.md) and
[lounge/MACHINE.md](lounge/MACHINE.md) before running it — it's a hard
protocol (exact-cell mutex, mandatory heartbeat, no solo report submission),
not a suggestion.

## The doctrine (governance, solo or lounge)

`doctrine/` is what keeps a run honest regardless of whether it's one agent
or a table of them: `doctrine/protocols/P01_EVIDENCE_FIRST.md` through `P14`,
role cards for HUNTER/OPERATOR/SKEPTIC/SUPERVISOR seats, and the
persistence/resume hooks that make state survive a compaction or a crash.
Read `doctrine/CLAUDE_ENFORCEMENT.md` first.

## Installation

### As a Claude Code plugin (recommended — wires in the `swarm-operator` agent alongside the skills)

This repo is both the marketplace and the plugin it lists
(`.claude-plugin/marketplace.json` + `.claude-plugin/plugin.json` at its
root), so one command adds the marketplace and installs the plugin:

```bash
/plugin install catusmythos-lounge --marketplace Felix1Catus/CatusMythos-Lounge
```

Or as two steps, from inside Claude Code or a shell:

```bash
claude plugin marketplace add Felix1Catus/CatusMythos-Lounge
claude plugin install catusmythos-lounge@catusmythos-lounge-marketplace
```

The doctrine (`doctrine/`) and lounge (`lounge/`) layers aren't part of the
plugin manifest — they're invoked directly by the skills/agent, not loaded
as plugin components — so they come along for free with the clone a plugin
install creates; nothing extra to wire up.

### Skills only, without the plugin machinery

```bash
git clone https://github.com/Felix1Catus/CatusMythos-Lounge.git
cd CatusMythos-Lounge

# Install all skills globally (available in every Claude Code project)
mkdir -p ~/.claude/skills
cp -r skills/* ~/.claude/skills/

# Or project-local
mkdir -p .claude/skills
cp -r /path/to/CatusMythos-Lounge/skills/* .claude/skills/
```

### Requirements

- Python 3.8+ (standard library only for the pipeline; the Masriyan domain
  skills' scripts are documented per-skill under `skills/<n>/SKILL.md`)
- Claude Code with skills support
- Optional, for faster recon: `subfinder`, `httpx`, `puredns`, `naabu`,
  `dig`, `whois`, `nmap`

## Usage

Talk to Claude naturally:

```
Run full reconnaissance on target.com
Find vulnerabilities on app.target.com
Chain all findings and generate a bug bounty report
Analyze this APK against OWASP MASVS
Map these TTPs to MITRE ATT&CK and write detection rules
Run a SOC 2 gap analysis against NIST CSF 2.0
```

Or invoke the entry-point agent for a full engagement:

```
Use the swarm-operator agent to run a full assessment of target.com
```

## Status

This is a v0.1 merge: the content is real (pulled from both upstream repos
at the commit this was built from, not stubbed), the pipeline workflow is
untouched, and the overlap decisions are documented in MERGE_MAP.md rather
than hidden. What's not done yet: a from-scratch test suite exercising the
merged scripts together (each source's own tests still apply to its own
scripts), and the `kimi-mythos` / non-Claude engine variant, which is the
next module once this one is solid.

Since v0.1, a live engagement surfaced and fixed two real behavioral bugs,
not just merge-seam issues:

- `vuln-chain-composer`'s chain-correlation templates used to escalate
  every category-matched chain straight to CRITICAL regardless of whether
  any supporting evidence existed — a username-disclosure finding once
  auto-became a reported CVSS 10.0 "account takeover." Every chain now
  carries a `confidence` field (`"confirmed"` only when the finding data
  actually supports the specific claim) and severity amplification is
  gated on it.
- `swarm-operator` only ever read 2 of the doctrine's 14 protocols at
  startup and had no structural check against fixating on one bug class —
  it's now required to read all 14 (the creative-mutation and
  error-as-oracle protocols, P09/P10, were always there and just weren't
  being consulted), runs a breadth checklist across ~13 vulnerability
  classes before going deep on any one, and has an explicit capability
  check so it stops and hands back cleanly when a step needs a live
  browser session instead of attempting a tool call it doesn't have.
