<p align="center">
  <h1 align="center">CatusMythos-Lounge</h1>
  <p align="center">
    <strong>A web/API/cloud pentest toolkit for Claude Code: one recon-to-report pipeline, a doctrine engine, and solo / native-multi-agent / multi-seat-lounge orchestration.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/Claude-Code-blueviolet.svg" alt="Claude Code">
    <img src="https://img.shields.io/badge/skills-8-orange.svg" alt="8 Skills">
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
2. **[Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)**
   — originally 22 skills covering general security work; this repo keeps
   only the two that extend the web-pentest focus — **`16-ai-llm-security`**
   (prompt injection, agent/RAG security — modern web apps increasingly ship
   AI features) and a trimmed **`03-exploit-development`** (the CVE-PoC
   workflow and payload generation, for turning a confirmed finding into a
   deliverable). The other 16 non-web domain skills (malware analysis,
   reverse engineering, mobile, OT/ICS, GRC, red-team-ops, and so on) were
   dropped to keep this plugin focused — see
   [MERGE_MAP.md](MERGE_MAP.md) for what was removed and why. A handful of
   its scripts that genuinely had zero overlap with the pipeline were folded
   directly into pipeline skills instead of shipping a redundant tool.
3. **mythos-lounge** — a doctrine engine (evidence-first discipline, probe
   budgets, report-only-when-real) and a multi-seat collaboration protocol
   (`seatlib.py`) that lets several agents — optionally different AI
   CLIs/accounts entirely — hunt one target in the same window without
   duplicating work. **This is the governance and coordination layer** that
   sits above the skill set, usable solo, as a native in-process
   multi-agent mode (`swarm-operator`'s own fan-out/fan-in, no external
   processes needed), or as a full table of lounge seats. An older,
   bus-based variant of this idea that never got fully ported in lives in
   [standalone-advanced/](standalone-advanced/README.md) for reference.

See [MERGE_MAP.md](MERGE_MAP.md) for the exact, file-by-file account of what
was combined, what was kept separate, and why — nothing was silently
dropped. See [NOTICE.md](NOTICE.md) and [CREDITS.md](CREDITS.md) for
attribution, which this repo is contractually obligated to preserve under
the MIT terms each source shipped with.

## Architecture

```
                    ┌─────────────────────────────┐
                    │   doctrine/   (governance)   │
                    │  P01-P14 protocols, probe     │
                    │  budgets, evidence-first       │
                    └───────────────┬───────────────┘
                                    │ enforced on every mode
                    ┌───────────────▼───────────────┐
                    │  agents/swarm-operator.md       │
                    │  solo sequential (default), or    │
                    │  native parallel: static-partition │
                    │  fan-out/fan-in, same session       │
                    └───────────────┬───────────────┘
                                    │ or hand off to, for
                                    │ true multi-model/multi-day work
                    ┌───────────────▼───────────────┐
                    │    lounge/   (coordination)    │
                    │  seatlib.py claim/token/push    │
                    │  — a table of seats, optionally  │
                    │  different AI CLIs/accounts       │
                    └───────────────┬───────────────┘
                                    │ drives
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                          ▼
┌─────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│  skills/ pipeline     │  │  skills/ 03, 16         │  │  agents/ entry points  │
│  (Felix1Catus)         │  │  (trimmed PoC-dev +     │  │  swarm-operator        │
│                        │  │   AI/LLM security)      │  │                        │
│  recon-dominator        │  └───────────────────────┘  └───────────────────────┘
│    -> webapp-exploit-   │
│       hunter            │
│    -> api-breaker       │
│    -> cloud-pivot-      │
│       finder             │
│    -> attack-path-       │
│       architect           │
│    -> vuln-chain-        │
│       composer            │
└─────────────────────┘
```

## The pipeline (unchanged from Felix1Catus / Orizon-eu)

```
DOMAIN INPUT
    │
    ▼
recon-dominator        subdomain enum, port scan, OSINT, dorking, Wayback
    │                  + Masriyan's WAF/CDN/analytics detection merged into tech_fingerprint.py
    │                  + Masriyan's wildcard-DNS suppression merged into active_recon.py
    │                  + cve_lookup.py — turns tech_fingerprint.py's versioned-component
    │                    output into version-matched NVD CVE hypotheses with real write-up
    │                    links, so exploitation is driven by what's actually fingerprinted,
    │                    not a blind sweep across every vulnerability class
    ├──► webapp-exploit-hunter   SQLi, XSS, SSRF, SSTI, IDOR, auth bypass, upload, race, WAF bypass
    │        + Masriyan's server-version-disclosure check merged into auth_tester.py
    ├──► api-breaker             API discovery, BOLA/BFLA, JWT, mass assignment, GraphQL
    │        (assessed Masriyan's api_security_tester.py — every check it ran was already
    │         covered more thoroughly by Felix's own scripts; nothing to add)
    └──► cloud-pivot-finder      cloud detection, bucket/takeover/CI-CD/serverless exposure
                 │
                 ▼
         attack-path-architect   asset/trust mapping, MITRE ATT&CK trees, kill chains
             + mitre_mapper.py (ATT&CK technique DB), engagement_planner.py —
               promoted from a Masriyan domain skill that was otherwise removed
                 │
                 ▼
         vuln-chain-composer     cross-domain correlation, exploit chains, CVSS, reports
             + Masriyan's spec-correct CVSS round-up merged into calculate_impact.py
```

Every one of those merge decisions — what got ported into an existing
script vs. shipped alongside it vs. left out entirely, and why — is
assessed and recorded file-by-file in [MERGE_MAP.md](MERGE_MAP.md), not
just asserted here.

## Everything else (the two Masriyan skills kept, both web-pentest-relevant)

This plugin was narrowed from 24 skills to 8 to stay focused on web/API/cloud
pentesting. 16 general-security domain skills (malware analysis, reverse
engineering, incident response, mobile, OT/ICS, cryptography, GRC/compliance,
supply chain, threat intel, purple team, blue/red-team ops, network security,
log analysis, SOC automation, threat hunting) were removed — see
[MERGE_MAP.md](MERGE_MAP.md) for the full list and reasoning. Two survived,
both because they extend the pipeline's own surface rather than covering an
unrelated domain:

| # | Skill | Domain |
|---|---|---|
| 03 | exploit-development | CVE-PoC workflow + payload generation for a finding the pipeline already confirmed (trimmed — the binary-exploitation/AV-evasion content was removed) |
| 16 | ai-llm-security | Prompt injection, OWASP LLM Top 10, RAG/agent security — for the chatbot/agent features modern web apps increasingly ship |

## The lounge (multi-seat mode)

When one target is big enough to want several agents working it
concurrently without re-firing the same request, `lounge/seatlib.py` gives
every seat claim/token/push primitives: claim an exact cell before probing
it, pull a rate-limit token before every network request, and push your
next finding to the other live seats the moment a class flips. Each seat is
its own OS process — optionally a different AI CLI/account entirely (Grok,
a separate Claude Code account, a DeepSeek-backed variant) — coordinated via
a shared, file-based event log. Read
[lounge/LOUNGE_PROTOCOL.md](lounge/LOUNGE_PROTOCOL.md) and
[lounge/MACHINE.md](lounge/MACHINE.md) before running it — it's a hard
protocol (exact-cell mutex, mandatory heartbeat, no solo report submission),
not a suggestion. `swarm-operator.md`'s Section 4 names when to reach for
this vs. staying solo.

## The doctrine (governance, solo or lounge)

`doctrine/` is what keeps a run honest regardless of whether it's one agent
or a table of them: `doctrine/protocols/P01_EVIDENCE_FIRST.md` through `P14`,
and the templates each protocol operationalizes
(`doctrine/templates/*.md` — scope, target model, leads, chain ledger,
coverage map). Read `doctrine/CLAUDE_ENFORCEMENT.md` first. An older,
bus-based multi-account coordination design (role cards for
HUNTER/OPERATOR/SKEPTIC/SUPERVISOR seats, persistence/resume hooks wired to
a standalone external install) never got reconciled with `lounge/` and has
been moved to [standalone-advanced/](standalone-advanced/README.md) — it's
not part of this plugin's own runtime, kept as reference only.

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
Test this API for BOLA and mass assignment issues
Map the cloud infrastructure behind app.target.com
Chain all findings and generate a bug bounty report
Test this chatbot feature for prompt injection
Build a PoC for the file-upload RCE you just confirmed
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

This repo was then narrowed from a general 24-skill security toolkit to a
focused 8-skill web/API/cloud pentest plugin: 16 non-web domain skills were
removed, `03-exploit-development` was trimmed to its web-relevant content,
6 scripts that were silently never wired into any `SKILL.md` were deleted
(their nominal "parent" domain skill didn't exist anywhere in this repo
either), and an orphaned bus-based multi-account coordination design with
zero implementing code in this repo was moved to `standalone-advanced/`
rather than deleted outright, since it documents real ideas someone running
a standalone setup might still want. `vuln-chain-composer`'s capability-graph
chaining engine and `webapp-exploit-hunter`'s `waf_bypass_tester.py` were
both built from a 100-writeup research pass on 2024-2026 bug-bounty
disclosures (`research_notes/Vuln chaining and WAF bypass patterns/`).

`swarm-operator` then gained a native in-process multi-agent mode
(alongside, not replacing, the lounge) after a dedicated competitive-
landscape research pass (`research_notes/Web pentest agent competitive
landscape/`) — a static work partition across parallel subagents, no live
channel between them while they run, one merge+skeptic-review step at the
end. This is deliberately NOT a from-scratch invention: it's the
parallel-crawling literature's well-quantified "firewall mode" (Cho &
Garcia-Molina, WWW 2002), chosen over lounge's live "exchange mode" when an
engagement fits in one session. One real constraint shaped the design and
is worth knowing if you're reading `swarm-operator.md`'s own text:
**the agent cannot spawn its own subagents** — tested directly (a
delegation tool was added to its declared tool list and it tried to use it;
the tool was simply never available at runtime regardless of what was
declared), not assumed. The fan-out happens one level up, from whatever
invokes the agent — it computes the partition and writes a plain JSON
ledger, then hands the dispatch instructions back rather than attempting
it itself. Per the research, the merge/skeptic step matters more than the
partitioning mechanism: a controlled study found up to 71.5% of LLM
pentest agents' self-reported exploit "successes" are invalid under an
actual evidence check, which is why that step re-derives every finding's
confidence from its recorded evidence rather than trusting a slice's own
narration.

Those research-driven depth passes, per kept skill, are now done:

- **recon-dominator**: OSV-backed CVE cross-matching
  (`lookup_via_osv`/`lookup_component_auto`) alongside the existing NVD
  path, a Debian/Ubuntu backport-suffix false-positive fix in
  `cve_lookup.py`, and "Sitting Ducks"-class NS lame-delegation detection
  (`check_lame_delegation`) in `active_recon.py`.
- **`16-ai-llm-security`**: two new scripts —
  `unbounded_consumption_tester.py` (OWASP LLM10 exposure checks) and
  `mcp_security_tester.py`/`rag_security_tester.py` (full-schema poisoning,
  tool-shadowing, rug-pull detection, cross-tenant leakage, raw-embedding
  exposure, hidden-Unicode-instruction smuggling) — plus a many-shot/
  best-of-N jailbreak harness and a real latent bug fix (`dotted_get()`
  never indexed into a list, silently breaking the script's own documented
  `--response-path` example).
- **api-breaker**: JWT `kid`-header injection, `crit`-header bypass, and
  RS256-to-PS256 pure-header-relabeling algorithm confusion in
  `auth_analyzer.py`; a 5-stage GraphQL introspection-disabled fallback
  chain, depth/complexity DoS, and nested-field authorization bypass in
  `schema_builder.py`; legacy-API-version discovery and a
  race-condition/path-mutation rate-limit depth pass in
  `api_discovery.py`/`rate_limiter.py`. (A fully-built, cryptographically
  verified `jwk`-header-injection capability requiring the `cryptography`
  package was deliberately **not** shipped, keeping the core pipeline
  stdlib-only by design — documented as a flagged future option instead.)
- **cloud-pivot-finder**: a subdomain-takeover fingerprint refresh against
  2024-2026 data, fixing a real false-positive bug (six services were
  scored vulnerable on their own "not found" signature) and adding 9 new
  services; ECS/Fargate token-free metadata, kubelet, and GKE/EKS
  depth notes in `metadata_paths.py`; and a fix for three of this skill's
  own five scripts whose findings were never reaching
  `vuln-chain-composer` at all.
- **attack-path-architect**: closed the `mitre_mapper.py` gap an earlier
  pass deliberately left open (3 dotted sub-technique IDs would have
  silently broken on a naive table swap) by filling the missing 15 IDs
  first, then rewiring `generate_attack_tree.py` to call `mitre_mapper.py`
  directly — plus 4 new attack patterns mapping this round's own ECScape/
  GraphQL/JWT/agentic-AI findings to MITRE ATT&CK/ATLAS.

Full citations and technical detail for each are in `research_notes/` and
`reports/`, one subfolder per topic.
