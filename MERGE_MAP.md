# MERGE_MAP — what was combined, what was kept separate, and why

Three sources went into this repo. The goal was a genuine merge, not a
side-by-side bundle: where two sources solve the same problem, assess which
does it better (or whether they're each missing something the other has)
and produce one stronger implementation — never ship two half-redundant
tools under one skill and call it done.

## Sources

| Source | Shape | Role in the merge |
|---|---|---|
| [Felix1Catus/claude-code-pentest](https://github.com/Felix1Catus/claude-code-pentest) (fork of [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest)) | 6 skills, 43 scripts, one pipeline, zero dependencies | **Execution backbone.** Its recon -> exploit -> chain -> report workflow is preserved unmodified as the pipeline's shape. |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) | 22 skills, ~35 scripts, full-spectrum security coverage | **Domain breadth.** Everything the pipeline doesn't cover is added wholesale. Where it overlaps the pipeline, each script was assessed on its own merits (see below) instead of being dropped in next to the one that already existed. |
| `mythos-lounge` (local) | doctrine engine + multi-seat protocol | **Governance + coordination layer**, above both skill sets. |

## Pipeline skills (Felix1Catus, unchanged workflow)

`skills/recon-dominator`, `skills/attack-path-architect`,
`skills/webapp-exploit-hunter`, `skills/api-breaker`,
`skills/cloud-pivot-finder`, `skills/vuln-chain-composer` — copied verbatim
as the starting point. Their `SKILL.md`, references, and overall script set
are Felix/Orizon's original work; the changes recorded below are targeted
merges and one upstream bug fix, not a rewrite.

## Overlap resolution — the actual per-script assessment

Every Masriyan script in a domain the pipeline also touches was read
side-by-side with the pipeline script covering the same ground before any
decision was made. Four different outcomes came out of that, not one
blanket rule:

### A. Masriyan had something Felix's version lacked entirely -> ported the capability in, didn't ship a second file

| Domain | What Felix was missing | What was done |
|---|---|---|
| Tech fingerprinting | `recon-dominator/scripts/tech_fingerprint.py` had no WAF, CDN, or analytics-beyond-two-patterns detection. Masriyan's version had all three, but pulled them in via the `requests` library — which would have broken the pipeline's "zero pip dependencies" design if copied as-is. | Reimplemented WAF signatures (Cloudflare/AWS WAF/Akamai/Sucuri/ModSecurity), CDN header detection (CloudFront/Fastly/Cloudflare/`x-cdn`), and a Facebook Pixel analytics pattern **directly into Felix's stdlib `urllib`-based script** (`tech_fingerprint.py`), reusing the header dict it already fetches. No new file, no new dependency, strictly more capable than either source alone. Masriyan's `_analyze_ssl` was skipped — it only checks `scheme == "https"`, which Felix's security-header block already implies, so it added nothing. |
| Wildcard-DNS suppression | `recon-dominator/scripts/active_recon.py`'s `dns_bruteforce` had no wildcard-DNS guard: a target with a wildcard A record makes every brute-force candidate "resolve," flooding output with false positives. Masriyan's `subdomain_enum.py` had `detect_wildcard()` / `_is_wildcard_only()` for exactly this (and the v3.3 changelog of that repo calls it out as a real fix they shipped). | Ported the mechanism into `active_recon.py` as `detect_wildcard_dns()`, called once before the brute-force loop, with results suppressed via a set-containment check — same technique, native to Felix's stdlib socket-based resolver, no `dnspython` dependency added. |
| CVSS round-up correctness | `vuln-chain-composer/scripts/calculate_impact.py` used `math.ceil(score * 10) / 10` to round a CVSS base score to one decimal. This is **not** equivalent to the CVSS v3.1 spec's `Roundup()` function on scores that land on a floating-point representation error just below a `0.1` boundary — it can silently under-score a finding. Masriyan's `cvss_calculator.py` implements the spec's exact integer-math algorithm with a comment explaining why the naive version is wrong. | Replaced Felix's round-up with the spec-correct integer algorithm (`cvss_round_up()`), verified with a boundary-case sanity check. `calculate_impact.py`'s chain-aggregation logic (which Masriyan's tool doesn't have — it only scores a single vector string) is otherwise untouched. The standalone `cvss_calculator.py` is still shipped too (see table B) since it's a different shape of tool (interactive vector-string calculator) that's independently useful outside a chain. |

### B. Genuinely new, no overlap -> shipped as additive scripts inside the pipeline skill

| Masriyan script | Folded into | Why it's not duplicate work |
|---|---|---|
| `cvss_calculator.py` | `vuln-chain-composer/scripts/` | Interactive/standalone CVSS vector-string calculator — a different shape of tool than `calculate_impact.py`'s chain-aggregation (which now reuses its round-up fix, see above). |
| `dependency_auditor.py` | `vuln-chain-composer/scripts/` | SBOM/CVE dependency auditing. Nothing in the pipeline scans dependency manifests. |
| `config_auditor.py` | `vuln-chain-composer/scripts/` | Config-file-at-rest review. Also nothing comparable in the pipeline. |
| `dns_recon.py` | `recon-dominator/scripts/` | SPF/DMARC email-security parsing + reverse DNS. Zero overlap with Felix's `passive_recon.py`/`active_recon.py`. |
| `cloud_auditor.py`, `iac_scanner.py` | `cloud-pivot-finder/scripts/` | **Authenticated** cloud posture auditing (AWS/GCP/Azure CLI, IAM, CloudTrail) and **at-rest** IaC scanning (Terraform/Dockerfile/K8s manifests). Felix's `cloud-pivot-finder` is entirely unauthenticated-external (CNAME detection, public buckets, metadata SSRF, takeover, CI/CD exposure) — different input, different access model, genuinely complementary. |
| `mitre_mapper.py` | `attack-path-architect/scripts/` | ATT&CK technique lookup DB + SIEM detection-query generation + Navigator-layer export. Felix's `generate_attack_tree.py` builds attack trees but has no technique database to look anything up in. |
| `engagement_planner.py` | `attack-path-architect/scripts/` | Red-team engagement scoping/plan generator. Nothing like it in the pipeline. |

### C. Masriyan's version was redundant with something Felix's pipeline already did better -> not shipped, salvaged what little was unique

| Masriyan script | Why it was dropped instead of added |
|---|---|
| `api_security_tester.py` (from `09-web-security`) | Checked BOLA (Felix's `authz_tester.py` does this with dual-token support, more thorough), broken auth/JWT (Felix's `auth_analyzer.py` forges JWTs — none-alg bypass, HS256 key-confusion, secret brute-force — far beyond a presence check), mass assignment (Felix's dedicated `mass_assignment.py` does nested-object mutation testing), rate limiting (Felix's `rate_limiter.py` does concurrent-request racing and GraphQL batching, not just a 20-request burst), and exposed debug/docs endpoints (Felix's `api_discovery.py` already probes 70+ paths including Swagger/OpenAPI/actuator and **parses** the OpenAPI spec for endpoints — this script's flat 14-path list added nothing). Every single check it performed was already covered, and covered more thoroughly, by an existing pipeline script. Shipping it anyway would have meant two tools giving a user different answers to the same question. |
| `owasp_scanner.py` (from `09-web-security`) | `check_security_headers`/`check_cors` duplicate `auth_tester.py`'s `check_security_headers`/`test_cors_misconfiguration` (Felix's version is more thorough — it also flags weak CSP directives and non-standard X-Frame-Options values, not just presence/absence). `check_common_paths` duplicates `crawler.py`'s `fuzz_common_paths`. `check_tls` is a one-line `scheme == "https"` check with no real value. The one thing it had that Felix didn't — flagging a `Server` header that discloses a version string — was folded directly into `auth_tester.py`'s `check_security_headers()` (a 7-line addition) instead of shipping a whole redundant file for it. |
| `subdomain_enum.py` (from `01-recon-osint`) | Its CT-log enumeration duplicates `passive_recon.py`'s `query_crtsh`, its zone-transfer check duplicates `active_recon.py`'s `attempt_zone_transfer`, and its brute-force duplicates `active_recon.py`'s `dns_bruteforce`. The one thing it had that Felix's didn't — wildcard-DNS suppression — was ported directly into `dns_bruteforce()` (table A, above). What's left after that extraction is a strict subset of `active_recon.py` + `passive_recon.py` combined, so it wasn't shipped as a separate file. |

## Domain skills shipped wholesale, unmodified (Masriyan, no pipeline overlap)

`skills/03-exploit-development`, `04-reverse-engineering`,
`05-malware-analysis`, `06-threat-hunting`, `07-incident-response`,
`08-network-security`, `11-csoc-automation`, `12-log-analysis`,
`13-crypto-analysis`, `14-red-team-ops`, `15-blue-team-defense`,
`16-ai-llm-security`, `17-mobile-security`, `18-ot-ics-security`,
`19-grc-compliance`, `20-supply-chain-security`, `21-threat-intelligence`,
`22-purple-team`. `06-threat-hunting` and `14-red-team-ops` also each
contributed one script to `attack-path-architect` (table B) while still
shipping standalone in full — their remaining content (IOC/Sigma work, AD
attacks/C2/OPSEC) isn't pipeline-shaped, so duplicating the whole skill
into the pipeline would have been the wrong kind of merge.

## Doctrine + Lounge (mythos-lounge)

Ported from the local `mythos-lounge` project:

- `doctrine/` — the `claude-mythos` engine's protocols (P01–P14), bootkit
  role cards, persistence/resume hooks, and state templates.
- `lounge/` — `seatlib.py` and its launcher scripts: claim/token/push
  coordination, plus `LOUNGE_PROTOCOL.md` and `MACHINE.md`.

**Left out on purpose:** `router_seen/` (runtime telemetry), dated
field-journal markdown files (session history, some referencing live
bug-bounty program names), and the `kimi-mythos` engine variant (out of
scope for this pass — Claude Code first, per the brief).

## Upstream bug fixed while merging

`skills/vuln-chain-composer/scripts/generate_chain_poc.py` used a
backslash-escaped quote inside an f-string expression, a `SyntaxError` on
Python <3.12 despite the pipeline's stated "Python 3.8+" requirement. Fixed
by pulling the expression into a local variable; generated output is
unchanged. Every `.py` file in this repo is byte-compiled before commit.

## What "merging" still did *not* mean

No script's internal request-firing logic was rewritten to "combine" two
different implementations into one clever hybrid where that risked
changing tested behavior for no real gain — e.g. Felix's and Masriyan's CMS
signature lists both exist and neither replaced the other wholesale,
because listing a few more WordPress patterns isn't the kind of gap worth
a structural merge. The bar for actually touching a script was: either it
was missing a capability the other source clearly had (table A), or it was
genuinely new ground (table B), or keeping it would mean shipping a worse
answer to a question Felix's pipeline already answered better (table C).
