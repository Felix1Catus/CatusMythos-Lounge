---
name: recon-dominator
description: Automated full-scope reconnaissance starting from a domain or domain list. Performs subdomain enumeration, port scanning, technology fingerprinting, OSINT correlation, Google dorking, and Wayback analysis. Use when user provides a domain or list of domains and asks for "recon", "reconnaissance", "attack surface mapping", "subdomain enumeration", "footprinting", or "information gathering". Designed for authorized penetration testing and bug bounty.
metadata:
  author: orizon.one
  version: 1.0.0
---

# Recon Dominator

Full-scope reconnaissance orchestrator. From a single domain to a complete attack surface map.

## Important

CRITICAL: Only use on domains you have explicit authorization to test. Verify scope before every engagement.

## Instructions

### Step 1: Scope Validation
Before ANY reconnaissance activity:
1. Ask the user to confirm they have written authorization to test the target domain(s)
2. Confirm the scope boundaries (wildcard subdomains? specific IPs only? out-of-scope assets?)
3. Document the scope in the output

### Step 2: Passive Subdomain Enumeration
Run passive enumeration first (no direct contact with target):

```bash
python scripts/passive_recon.py --domain {target_domain}
```

This collects subdomains from:
- Certificate Transparency logs (crt.sh)
- DNS datasets (SecurityTrails, DNSDumpster)
- Search engine results
- Wayback Machine archives

Expected output: JSON list of discovered subdomains with source attribution.

### Step 3: Active Subdomain Enumeration
After passive phase, run active enumeration:

```bash
python scripts/active_recon.py --domain {target_domain} --wordlist references/subdomains-wordlist.txt
```

This performs:
- DNS brute-force with common subdomain wordlist
- DNS zone transfer attempts
- **NS-delegation ("Sitting Ducks") lame-delegation check** — for the apex
  domain and for any discovered subdomain that has its own NS records (a
  real zone delegation, e.g. `aws.{target_domain}` delegated straight to a
  cloud DNS provider), asks each listed nameserver directly for the zone's
  SOA record. A nameserver that answers REFUSED/SERVFAIL/NXDOMAIN, or
  NOERROR with an empty answer, is listed as authoritative but doesn't
  actually serve the zone — a live domain/subdomain-hijack candidate if its
  provider lets anyone claim an equivalent hosted-zone resource (2024
  Infoblox/Eclypsium research, reported to affect 1M+ domains).
  Mechanistically independent of, and a real gap versus, cloud-pivot-
  finder's CNAME-only `takeover_scanner.py`. Requires `dig`; skipped with a
  warning (not a failure) when it isn't installed. Disable with
  `--skip-lame-delegation`; tune subdomain-check depth with
  `--max-subdomain-ns-checks` (default 25).
- Virtual host discovery
- Permutation/alteration scanning (dev-, staging-, api-, etc.)

### Step 4: Live Host Detection and Port Scanning

```bash
python scripts/port_scanner.py --input {subdomains_file} --top-ports 1000
```

For each live subdomain:
1. HTTP/HTTPS probe (status codes, redirects, titles)
2. Top 1000 port scan with service version detection
3. Banner grabbing on open ports
4. WAF/CDN detection (Cloudflare, Akamai, AWS CloudFront)

### Step 5: Technology Fingerprinting

```bash
python scripts/tech_fingerprint.py --input {live_hosts_file}
```

Detect:
- Web server (Apache, Nginx, IIS, etc.)
- Programming language/framework (PHP, Django, Rails, Spring, etc.)
- CMS (WordPress, Drupal, Joomla)
- JavaScript frameworks (React, Angular, Vue)
- Third-party services and integrations
- HTTP security headers (or lack thereof)
- **Versioned components** (`versioned_components` in the output): for
  WordPress-style sites, the exact plugin/theme/core version extracted from
  enqueued-asset `?ver=` query strings — e.g. `/wp-content/plugins/
  elementor-pro/assets/css/widget-gallery.min.css?ver=4.0.4` names both the
  component (`elementor-pro`) and its version (`4.0.4`) with no
  authentication needed to read it. This is what Step 5b below acts on.

### Step 5a: JS Bundle & Source-Map Mining

```bash
python scripts/js_recon.py --target https://{live_host} --output js_recon_results.json
```

Modern frontends ship whole route tables, API clients, and sometimes build
artifacts to the browser — this mines that instead of guessing endpoints
blind. For each HTML entry point and every JS chunk it references (BFS-
crawled up to `--max-chunks`):
- **Endpoint strings** — LinkFinder/JSFinder/GoLinkFinder's shared
  endpoint-regex pattern, filtered through jsluice's `MaybeURL` heuristic
  to cut noise.
- **Structured API calls** — `fetch()`, `axios`/`axios.<method>()`,
  `$.ajax`/`$.get`/`$.post`, and raw `XMLHttpRequest.open()` call sites,
  with template-literal placeholders normalized (`${id}` → `{id}`) so
  dynamic-but-real routes aren't lost.
- **Source maps** — if a chunk ships a `//# sourceMappingURL=` comment and
  the `.map` file is actually reachable (routinely left deployed even when
  the comment itself was stripped from production), reads its `sources`/
  `sourcesContent` directly — no VLQ decoding needed — which can recover
  whole original source files (admin components, internal tooling) that
  never shipped a route to the bundler's own output at all.
- **Build manifests** — Next.js's `__BUILD_MANIFEST`/`_buildManifest.js`
  and Vite's `.vite/manifest.json` (including `dynamicImports`) both
  enumerate every route/chunk the framework knows about, including ones
  with no visible `<a href>` anywhere in the rendered page.

Feed anything this surfaces (an unlinked `/admin/*` route, an internal API
client method, a recovered `secrets.js`) straight to webapp-exploit-
hunter/api-breaker as a concrete target — same "version-matched hypothesis
beats blind sweep" logic as Step 5b below, just for hidden surface instead
of CVEs.

### Step 5b: CVE / Public-Exploit Lookup — THIS is what should drive exploitation choices, not a blind vuln-class sweep

```bash
python scripts/cve_lookup.py --input {tech_fingerprint_output.json} --output cve_lookup_results.json
```

Takes every versioned component Step 5 found and queries NVD's public CVE
database for each one, comparing the *discovered* version against each
CVE's *actual published affected-version range* (structured CPE match data
when NVD has it, a description-text heuristic as a fallback when NVD
hasn't enriched the CVE with CPE data yet — recent CVEs often haven't).
Each hit carries NVD's own reference URLs, which routinely include the
real write-up/advisory/PoC, not just the bare CVE ID — this is the "use
public write-ups and recent exploits" step, automated rather than manual.

**This is the step that should determine what webapp-exploit-hunter/
api-breaker/cloud-pivot-finder actually spend probe budget on.** A plugin
with a version-matched CRITICAL unauthenticated-RCE CVE and a public PoC
is a concrete hypothesis worth verifying the precondition for (does the
vulnerable feature/endpoint exist and is it enabled on *this* install?) —
that's a fundamentally different, better-targeted probing choice than
running every exploit-class script against every discovered host
regardless of what's actually running there. Only fall back to the
broader vulnerability-class sweep (webapp-exploit-hunter's own battery)
for surface this step found nothing CVE-specific for, or to catch unknown/
zero-day-class issues a version lookup can never find.

Each result is labeled honestly by confidence — `"nvd-cpe-match"` (NVD's
own structured data says this), `"description-text-heuristic"` (parsed
from the CVE's prose, verify against the linked write-up before trusting
it), `"osv-exact-match"` (see below), or `"keyword-only-unverified"`
(name matched, nothing structured or in the prose confirms or refutes it —
weakest tier, verify manually) — and `version_appears_affected` is a
**hypothesis to verify live**, never a confirmed finding on its own; the
actual vulnerable feature/endpoint still needs to be checked (e.g. "is the
Elementor Forms File Upload field actually enabled on any form on this
site?" — a real install can have a vulnerable plugin version with the
vulnerable feature turned off, which makes it currently non-exploitable
despite being unpatched).

Two further edge cases this step now handles rather than silently getting
wrong:
- **Distro backport false positives** — if the installed version string
  itself carries a Debian/Ubuntu/RHEL/Fedora backport suffix (`+deb12u1`,
  `1ubuntu0.1`, `-1.el9`, `-1.fc40`), the hypothesis is flagged
  `"backport_suspected": true`: the distro may have silently backported
  the exact fix without the version string ever crossing NVD's upstream
  "fixed" threshold (the real, documented regreSSHion/CVE-2024-6387-on-
  Debian case). Treat any `AFFECTED?` hit with this flag as "verify
  against the distro's own security tracker," even at the otherwise-
  highest `nvd-cpe-match` confidence tier.
- **Non-CPE ecosystem coverage** — if a component dict carries an
  `"ecosystem"` key (one of OSV.dev's identifiers: `npm`, `PyPI`, `Go`,
  `Maven`, `crates.io`, `RubyGems`, `Packagist`, `NuGet` — set by future
  JS/dependency-mining output, not by `tech_fingerprint.py`'s WordPress-
  shaped output, which OSV doesn't cover), the lookup is dispatched to
  OSV.dev's free, keyless API instead of NVD's keyword search. OSV range-
  filters server-side, so an `"osv-exact-match"` hit is already confirmed
  for that exact version — no local range comparison, and a documented
  stronger match than NVD's CPE/keyword approach for non-CMS packages
  (Anchore/Grype: thousands fewer false positives, up to 80% fewer).

### Step 6: OSINT Correlation

```bash
python scripts/osint_correlator.py --domain {target_domain}
```

Gather:
- WHOIS history and registrant patterns
- ASN mapping and IP range ownership
- Reverse IP lookups (shared hosting)
- Email addresses associated with the domain
- Social media and GitHub references
- Leaked credentials databases (public sources only)

### Step 7: Google Dorking

```bash
python scripts/google_dorker.py --domain {target_domain} --dork-file references/dorks-database.txt
```

Automated searches for:
- Exposed files: `site:{domain} filetype:pdf|doc|xls|sql|bak|log|env`
- Login panels: `site:{domain} inurl:admin|login|dashboard`
- Directory listings: `site:{domain} intitle:"index of"`
- Error messages: `site:{domain} "sql syntax" | "warning" | "error"`
- Sensitive endpoints: `site:{domain} inurl:api|graphql|swagger|config`

### Step 8: Wayback Machine Analysis

```bash
python scripts/wayback_analyzer.py --domain {target_domain}
```

Extract:
- Historical endpoints no longer linked but still active
- Removed pages with sensitive information
- Old API versions still responding
- Parameter names from archived URLs
- JavaScript files with hardcoded secrets

### Step 9: Output Generation
Compile all findings into a structured report:

```bash
python scripts/generate_report.py --project {project_name}
```

Output format:
1. **Executive Summary**: domain count, subdomain count, live hosts, open ports, technologies
2. **Asset Inventory**: full list with metadata per asset
3. **Technology Matrix**: tech stack per subdomain
4. **Potential Entry Points**: ranked by interest level
5. **Relationship Graph**: JSON graph of domain relationships
6. **Raw Data**: all collected data in JSON for pipeline consumption

## Output Files Structure
```
output/{project_name}/
  summary.md           # Human-readable report
  assets.json          # Full asset inventory
  subdomains.json      # All discovered subdomains
  ports.json           # Port scan results
  technologies.json    # Tech fingerprinting
  osint.json           # OSINT findings
  wayback.json         # Historical data
  graph.json           # Relationship graph
  dorking_results.json # Google dork findings
```

## Error Handling

### Common Issues

#### Rate Limiting on External APIs
If you see "429 Too Many Requests":
1. The scripts have built-in rate limiting and backoff
2. If persistent, increase delay: `--delay 5`
3. For crt.sh: wait 60 seconds between requests

#### DNS Resolution Failures
If subdomains fail to resolve:
1. Try alternative DNS resolvers: `--resolvers 8.8.8.8,1.1.1.1,9.9.9.9`
2. Check if target uses split-horizon DNS
3. Some subdomains may be internal-only

#### Timeout on Port Scanning
For large scope (100+ subdomains):
1. Reduce port count: `--top-ports 100`
2. Increase timeout: `--timeout 10`
3. Run in batches: `--batch-size 20`

## Examples

### Example 1: Single Domain Recon
User says: "Run full recon on example.com"

Actions:
1. Confirm authorization
2. Run all steps sequentially on example.com
3. Generate consolidated report

Result: Complete attack surface map with all subdomains, services, and technologies.

### Example 2: Multi-Domain Bug Bounty Scope
User says: "I have a bug bounty scope: *.example.com, api.example.org, app.example.io"

Actions:
1. Confirm bug bounty program and scope rules
2. Run passive + active enum on each wildcard domain
3. For specific subdomains, skip enumeration, go directly to port scan
4. Cross-correlate findings between domains
5. Generate unified report

### Example 3: Quick Passive Only
User says: "Do passive recon only on example.com, no active scanning"

Actions:
1. Run only Steps 2, 6, 7, 8 (no direct target contact)
2. Skip active DNS brute, port scanning, tech fingerprinting
3. Generate report with passive findings only
