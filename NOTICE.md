# NOTICE

CatusMythos-Lounge is a merge of three separately-authored, separately-licensed
works. Per the MIT License terms each was received under, their copyright
notices and attribution requirements are preserved here and must remain
intact in any fork, redistribution, or derivative of this repository.

## 1. claude-code-pentest (pipeline workflow + 6 execution skills)

- **Original author / copyright:** orizon.one, Copyright (c) 2026
- **Curated fork used as source:** https://github.com/Felix1Catus/claude-code-pentest
- **Upstream:** https://github.com/Orizon-eu/claude-code-pentest
- **License:** MIT — full text in [LICENSE-FELIX1CATUS-ORIZON.md](LICENSE-FELIX1CATUS-ORIZON.md)
- **What was taken:** the six-skill pipeline (`recon-dominator`,
  `attack-path-architect`, `webapp-exploit-hunter`, `api-breaker`,
  `cloud-pivot-finder`, `vuln-chain-composer`) under `skills/`, verbatim, with
  its pipeline workflow preserved as the project's execution backbone. A
  handful of Masriyan scripts were additively copied *into* these skills'
  `scripts/` directories (see `MERGE_MAP.md`); the original Felix/Orizon
  scripts were not altered.

## 2. Claude-Code-CyberSecurity-Skill (22-domain security skill collection)

- **Original author:** Riyan Pratama ("Masriyan" / "sudo3rs")
- **Source:** https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
- **License:** MIT — full text in [LICENSE-MASRIYAN.md](LICENSE-MASRIYAN.md)
- **Attribution requirement:** reproduced verbatim in
  [NOTICE-MASRIYAN.md](NOTICE-MASRIYAN.md); that file's terms are binding on
  this repository and on anyone who forks it.
- **What was taken, originally:** skills `03` through `22` (everything
  outside the four domains the Felix pipeline already owns) copied wholesale
  and unmodified under `skills/`. Select scripts from skills `01`, `02`,
  `06`, `09`, `10`, and `14` were additively copied into the corresponding
  Felix pipeline skill's `scripts/` directory as a capability merge — each
  carries an attribution header naming its origin. **This was a modified
  distribution of parts of Masriyan's work**, as flagged by
  NOTICE-MASRIYAN.md's provenance clause: those specific files were relocated
  and prefixed with an attribution comment, nothing else was changed.
- **What is currently distributed** (after a later web-pentest-refocus pass
  removed 16 of the 18 domain skills — see `MERGE_MAP.md`'s refocus section):
  `skills/03-exploit-development` (trimmed to its web-relevant content) and
  `skills/16-ai-llm-security`, both still unmodified Masriyan work past that
  trim, plus the capability-merge scripts that remain live: the WAF/CDN/
  analytics detection in `recon-dominator/scripts/tech_fingerprint.py`, the
  wildcard-DNS suppression in `recon-dominator/scripts/active_recon.py`, the
  CVSS round-up fix in `vuln-chain-composer/scripts/calculate_impact.py`,
  the server-version-disclosure check in
  `webapp-exploit-hunter/scripts/auth_tester.py`, and
  `attack-path-architect/scripts/{mitre_mapper.py,engagement_planner.py}`
  (originally additive alongside skills `06`/`14`, which were themselves
  removed in the refocus pass — these two scripts' own attribution headers
  are what now carries the requirement, not the deleted skills). Six other
  additively-copied scripts (`cvss_calculator.py`, `dependency_auditor.py`,
  `config_auditor.py`, `dns_recon.py`, `cloud_auditor.py`, `iac_scanner.py`)
  were removed in that same pass — see `MERGE_MAP.md` for why.

## 3. mythos-lounge (doctrine engine + multi-seat collaboration protocol)

- **Original author:** the user who commissioned this merge (local,
  unpublished project).
- **What was taken:** the `claude-mythos` doctrine engine (protocols P01–P14)
  under `doctrine/`, and the `seatlib.py` multi-seat coordination protocol and
  its launcher scripts under `lounge/`. The bootkit role cards and
  persistence/resume hooks were part of this same doctrine engine originally,
  but were never wired into this repo's own runtime and were later moved to
  `standalone-advanced/` (see `MERGE_MAP.md`'s refocus section) rather than
  kept under `doctrine/`. Session-specific journals, dated field reports, and runtime
  telemetry (`router_seen/`) were intentionally left out of this public
  repository — they are personal history, not reusable mechanism, and several
  referenced live program names that have no place in a public tool repo.
  The `kimi-mythos` engine variant was left out for the same reason the task
  scoped this merge to Claude Code first: other model backends are a later
  module, not this one.

If you redistribute a modified version of this repository, state clearly that
changes were made and that it is not the original authors' release, per each
source's license terms.
