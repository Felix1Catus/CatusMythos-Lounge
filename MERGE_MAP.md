# MERGE_MAP — what was combined, what was kept separate, and why

Three sources went into this repo. The goal was additive merging: keep each
source's unique strength, fold overlapping strengths into one place instead
of shipping two half-redundant versions, and never silently drop a
capability.

## Sources

| Source | Shape | Role in the merge |
|---|---|---|
| [Felix1Catus/claude-code-pentest](https://github.com/Felix1Catus/claude-code-pentest) (fork of [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest)) | 6 skills, 43 scripts, one pipeline, zero dependencies | **Execution backbone.** Its recon -> exploit -> chain -> report workflow is preserved unmodified as the pipeline's shape. |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) | 22 skills, ~35 scripts, full-spectrum security coverage | **Domain breadth.** Everything the pipeline doesn't cover (malware, RE, IR, mobile, OT/ICS, crypto, GRC, supply chain, CTI, purple team, blue team, ...) is added wholesale. Where it overlaps the pipeline, its *scripts* are folded in rather than its *skill directories* duplicated. |
| `mythos-lounge` (local) | doctrine engine + multi-seat protocol | **Governance + coordination layer.** Sits above both skill sets: the doctrine enforces evidence-first/probe-budget discipline on any seat (solo or swarm); the lounge protocol lets multiple seats work one target concurrently without duplicating probes. |

## Pipeline skills (Felix1Catus, unchanged workflow)

`skills/recon-dominator`, `skills/attack-path-architect`,
`skills/webapp-exploit-hunter`, `skills/api-breaker`,
`skills/cloud-pivot-finder`, `skills/vuln-chain-composer` — copied verbatim.
Their `SKILL.md`, references, and script set are Felix/Orizon's original
work. Nothing was removed from them.

## Overlap resolution (the actual "merge" part)

Four Masriyan domains cover ground the pipeline also covers. Rather than
ship `skills/01-recon-osint` *and* `skills/recon-dominator` side by side
(two tools, one job, user has to guess which), the non-duplicate scripts
from the overlapping Masriyan skill were copied **into** the pipeline
skill's `scripts/` directory, each with a 4-line attribution header. The
Masriyan skill directory itself is not also shipped for these four — its
unique content lives on inside the pipeline skill now.

| Masriyan skill | Overlaps pipeline skill | Folded in | Skipped (already covered) |
|---|---|---|---|
| `01-recon-osint` | `recon-dominator` | `dns_recon.py`, `subdomain_enum.py` | `tech_fingerprint.py` — Felix's own `tech_fingerprint.py` already does this; keeping both would be the exact duplicate this merge exists to avoid. |
| `02-vulnerability-scanner` | `vuln-chain-composer` | `cvss_calculator.py`, `dependency_auditor.py`, `config_auditor.py` | none — these are net-new (dependency/CVE auditing, config review) that `vuln-chain-composer`'s `calculate_impact.py` didn't do. |
| `09-web-security` | `webapp-exploit-hunter`, `api-breaker` | `owasp_scanner.py` -> webapp-exploit-hunter; `api_security_tester.py` -> api-breaker (split by which pipeline skill actually owns that surface) | none |
| `10-cloud-security` | `cloud-pivot-finder` | `cloud_auditor.py`, `iac_scanner.py` | none — Felix's skill hunts live cloud exposure (buckets, takeover, metadata, CI/CD); Masriyan's scripts audit IaC/config at rest. Genuinely complementary, both kept. |

Two more Masriyan skills contributed one script each to the pipeline's
planning stage, **while also staying intact as their own standalone
skills** (their remaining content — engagement playbooks, C2 notes, AD
attacks, IOC/Sigma work — isn't pipeline-shaped, so duplicating the whole
skill into the pipeline would be the wrong kind of merge):

| Masriyan skill | Contributed | Still ships standalone as |
|---|---|---|
| `06-threat-hunting` | `mitre_mapper.py` -> `attack-path-architect/scripts/` | `skills/06-threat-hunting/` (IOC extraction, Sigma rules, hunt hypotheses) |
| `14-red-team-ops` | `engagement_planner.py` -> `attack-path-architect/scripts/` | `skills/14-red-team-ops/` (AD attacks, C2 design, OPSEC, social engineering) |

## Domain skills shipped wholesale, unmodified (Masriyan, no pipeline overlap)

`skills/03-exploit-development`, `04-reverse-engineering`,
`05-malware-analysis`, `06-threat-hunting`, `07-incident-response`,
`08-network-security`, `11-csoc-automation`, `12-log-analysis`,
`13-crypto-analysis`, `14-red-team-ops`, `15-blue-team-defense`,
`16-ai-llm-security`, `17-mobile-security`, `18-ot-ics-security`,
`19-grc-compliance`, `20-supply-chain-security`, `21-threat-intelligence`,
`22-purple-team`.

## Doctrine + Lounge (mythos-lounge)

Ported from the local `mythos-lounge` project:

- `doctrine/` — the `claude-mythos` engine's protocols (P01–P14), bootkit
  role cards (HUNTER/OPERATOR/SKEPTIC/SUPERVISOR), persistence/resume hooks,
  and state templates. This is what keeps either a solo seat or a lounge
  table honest: evidence before probes, a probe budget, no ritual re-recon,
  report-only-when-real.
- `lounge/` — `seatlib.py` and its launcher scripts: the claim/token/push
  mechanism that lets several seats hunt one target in the same window
  without firing the same request twice, plus `LOUNGE_PROTOCOL.md` and
  `MACHINE.md` describing the loop (GROUND -> HYPO -> SHOT -> REFLECT ->
  PROVE) and citing the public research it's built on.

**Left out on purpose:** `router_seen/` (per-session runtime telemetry —
not reusable), the dated field-journal markdown files (session history,
some referencing live bug-bounty program names that have no business in a
public tool repo), and the `kimi-mythos` engine variant (out of scope — this
pass is "make it work for Claude Code first," per the brief; other model
backends are a later module).

## One upstream compatibility fix

`skills/vuln-chain-composer/scripts/generate_chain_poc.py` used a
backslash-escaped quote inside an f-string expression
(`f"...{payload or \"test\"}..."`), which is a `SyntaxError` on Python
<3.12 despite the project's stated "Python 3.8+" requirement. Fixed by
pulling the expression into a local variable first; the generated PoC
output is unchanged. Every `.py` file in this repo was byte-compiled
(`python3 -m py_compile`) before commit — this was the only failure.

## What "merging" did *not* mean here

No script's internal logic was rewritten to "combine" two implementations
of the same check into one clever hybrid — that would risk silently
breaking either author's tested behavior. Where two sources solve the exact
same problem (subdomain tech-fingerprinting), one was kept and the decision
is recorded above, not hidden. Where they solve adjacent but different
problems under a similar name (cloud *exposure* hunting vs. cloud *config*
auditing), both were kept, because that's not actually overlap.
