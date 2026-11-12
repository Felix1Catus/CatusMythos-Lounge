---
name: vuln-chain-composer
description: Composes multi-step exploit chains by correlating vulnerabilities across domains, calculates real impact of chained findings, generates end-to-end PoC scripts, and produces bug bounty ready reports. Use when user asks to "chain vulnerabilities", "compose exploit chain", "correlate findings", "calculate real impact", "write bug bounty report", "combine findings", or has multiple vulnerability findings across domains that need strategic analysis. For authorized pentesting and bug bounty only.
metadata:
  author: orizon.one
  version: 1.0.0
---

# Vuln Chain Composer

The strategic brain. Correlates individual vulnerabilities into devastating multi-step exploit chains.

## Important

CRITICAL: This skill produces offensive security analysis. Only use with explicit authorization on the target systems.

## Instructions

### Step 1: Import Findings
Accept vulnerability data from:
1. JSON output from webapp-exploit-hunter, api-breaker, cloud-pivot-finder
2. Manual finding descriptions from the user
3. Attack tree data from attack-path-architect
4. Mixed sources - consolidate everything

```bash
python scripts/import_findings.py --input {findings_dir_or_files}
```

Normalize all findings to a common format:
- Vulnerability type (SQLi, XSS, SSRF, IDOR, etc.)
- Location (domain, URL, parameter)
- Severity (standalone)
- PoC (if available)
- Prerequisites (authentication level, specific conditions)

### Step 2: Cross-Domain Correlation

```bash
python scripts/correlate.py --findings {normalized_findings}
```

Analyze relationships between findings:

**Same-Origin Chains:**
- XSS on subdomain A + sensitive cookies scoped to parent domain = session hijack on all subdomains
- SSRF on subdomain B + internal API access = data exfiltration via internal endpoints
- Open redirect on auth endpoint + OAuth callback = token theft

**Trust-Based Chains:**
- Subdomain takeover + same cookie scope = full session hijack
- CI/CD access + deployment pipeline = production RCE
- Cloud metadata via SSRF + IAM overprivilege = full cloud compromise

**Credential-Based Chains:**
- SQL injection + password hashes = credential cracking + account takeover
- .env file exposure + database credentials = direct data access
- IDOR on user profile + email exposure = targeted phishing + account takeover

**Escalation Chains:**
- Low-privilege IDOR + mass assignment = privilege escalation to admin
- Self-XSS + CSRF = weaponized stored XSS affecting other users
- Rate limit bypass + brute-force + OTP bypass = authentication bypass

**AI-Agent Chains:**
- An AI agent/chatbot with backend admin tool access + a version-matched
  CVE that's unpatched but currently blocked by one missing precondition
  (e.g. an RCE-via-file-upload CVE with no File Upload field enabled on
  any form) = direct or prompt-inject the agent into performing the exact
  action the CVE needs enabled, then exploit it

**The list above (and the 11 `CHAIN_TEMPLATES`) are EXAMPLES of the kind of
chain this skill produces, not the mechanism that produces creative
chaining.** The named templates are a thin, hand-written convenience layer
for a handful of previously-seen patterns. The actual chaining brain is
`discover_generic_chains()`: every finding is tagged with what it
`chainable_as` (what it ENABLES a follow-on finding to do) and what it
`requires` (what precondition it needs to become exploitable), over a
shared capability vocabulary. Any two findings whose enables/requires sets
overlap become a candidate chain — found by graph matching, not because
someone wrote a template for that exact pair. This is what lets the tool
notice a combination its author never specifically imagined (e.g. a JWT
`alg:none` bypass combined with an IDOR that "requires a valid session" —
nobody wrote that template, the graph found it because JWT-bypass enables
`authentication_bypass` and IDOR requires it). **Adding a new named
template is the LAST resort, not the first** — if a chain can be expressed
as a capability pair instead, it belongs in the vocabulary
(`import_findings.py`) and, if it needs a non-trivial evidence check, in
`_GENERIC_CONFIDENCE_CHECKS` (`correlate.py`), so it generalizes to every
future finding with that tag instead of staying a one-off.

The vocabulary is not fixed — it is built from real 2024-2026 bug bounty
writeups and researcher disclosures (see `research_notes/Vuln chaining and
WAF bypass patterns/` and `reports/Vuln chaining and WAF bypass
patterns.md` in this plugin's root), not invented wholesale. Capability
pairs currently implemented from that research, beyond the original set
(`data_access`, `credential_theft`, `authentication_bypass`,
`internal_access`, `cloud_metadata`, `precondition_enabler`, ...):

- `redirect_into_allowlist` — an open redirect's target lands inside an
  SSRF's own destination allowlist, unlocking an otherwise-filtered SSRF
  (PortSwigger/web-app research pattern 1).
- `org_membership_granted` — an IDOR that leaks group/org/team membership
  unlocks a second IDOR (e.g. a role/password/email-change endpoint) that
  only checks membership, not identity (pattern 10).
- `cookie_scope_write` — XSS or subdomain takeover writing a cookie scoped
  to the parent domain, checked against a second finding sharing that
  parent domain (cookie-tossing into an OAuth flow, pattern 4).
- `delivery_mechanism` — self-XSS/POST-only XSS needs something else (CSRF,
  or a method-confusion bug) to actually deliver the payload to a victim
  (pattern 7).
- `waf_bypass_capable` — any finding whose evidence says a payload was
  blocked by a named WAF now requires a demonstrated bypass technique
  (`webapp-exploit-hunter/scripts/waf_bypass_tester.py`'s
  `wafbypass_*` findings grant exactly this) before it's actually
  deliverable.
- `scope_violation` — an agent/chatbot's tool-use access (`agenttoolaccess`)
  is only a reachable chain once something else gets attacker-controlled
  instructions in front of it from a lower-trust channel (email, calendar
  invite, ticket, Slack, MCP tool description) — the EchoLeak/AgentFlayer/
  ForcedLeak/CurXecute class of 2025-2026 AI-agent chains.
- `deploy_access` / `lateral_movement` — CI/CD approval-quorum and
  exposed-artifact chains, and the SSRF-reaches-metadata → IAM-credential →
  lateral-movement chain, as reusable graph edges rather than one-off
  narratives.

Both mechanisms report every chain with a `confidence` field
(`"confirmed"` only when real evidence in the finding data — not just the
category/capability tag — supports the specific claim; `"unconfirmed"`
otherwise, reported as a lead with the finding's own severity, not an
inflated one).

### Step 3: Chain Construction

```bash
python scripts/build_chains.py --correlations {correlation_data}
```

For each identified chain:

1. **Define the chain narrative**: Clear story from initial access to final impact
2. **List each step** with:
   - Vulnerability exploited
   - Specific URL/parameter
   - What is gained at this step
   - How it enables the next step
3. **Map dependencies**: What must succeed for the chain to work
4. **Identify alternatives**: If one step is fixed, is there a bypass?
5. **Calculate chain feasibility**: Product of individual step probabilities

### Step 4: Impact Recalculation

```bash
python scripts/calculate_impact.py --chains {chains_file}
```

Recalculate severity based on chain context:

**Impact Amplifiers:**
- Self-XSS (Low) + CSRF chain = Stored XSS affecting others (High)
- Info disclosure (Low) + credential reuse = Account takeover (Critical)
- SSRF (Medium) + cloud metadata = Full infrastructure access (Critical)
- IDOR (Medium) + PII access + mass enumeration = Data breach (Critical)

**CVSS Recalculation:**
For each chain, calculate:
- Attack Complexity: Based on number of steps and prerequisites
- Privileges Required: Based on initial access requirements
- User Interaction: Based on whether victim action is needed
- Scope: Changed if chain crosses trust boundaries
- Confidentiality/Integrity/Availability impact of the FINAL outcome

### Step 5: PoC Generation

```bash
python scripts/generate_chain_poc.py --chain {chain_file}
```

For each confirmed chain, generate:

1. **Step-by-step reproduction guide** with screenshots descriptions
2. **Automated PoC script** (Python) that:
   - Executes each step in sequence
   - Passes data between steps (tokens, cookies, IDs)
   - Validates each step succeeded before continuing
   - Generates evidence at each step
3. **curl command sequence** for manual reproduction
4. **Video script**: Narrated steps for recording a PoC video

### Step 6: Bug Bounty Report Generation

```bash
python scripts/generate_report.py --chains {chains_file} --format {platform}
```

Platform-optimized reports for:
- **HackerOne format**: Title, severity, description, steps to reproduce, impact, remediation
- **Bugcrowd format**: Similar with VRT classification
- **Generic format**: Professional pentest report style

Report structure per chain:
```
## Title
[Compelling, impact-focused title]

## Severity
[Recalculated severity with justification]

## Summary
[2-3 sentences: what it is, why it matters, what an attacker gains]

## Affected Assets
[List of all domains/endpoints involved]

## Steps to Reproduce
[Numbered steps with exact URLs, payloads, expected results]

## Proof of Concept
[curl commands or script]

## Impact
[Business impact: what data is at risk, what actions are possible]

## Attack Scenario
[Realistic attack narrative from attacker's perspective]

## Remediation
[Fix recommendations for EACH vulnerability in the chain]

## Chain Visualization
[ASCII diagram of the attack flow]
```

### Step 7: Alternative Path Analysis

For each chain, document:
1. **If Step N is fixed**: Does an alternative path exist?
2. **Minimal fix set**: What is the minimum number of fixes to break ALL chains?
3. **Defense in depth**: Which controls would detect/prevent each step?
4. **Monitoring recommendations**: What logs/alerts would catch this chain in action?

## Error Handling

### Insufficient Findings for Chaining
If findings are isolated with no chainable relationships:
1. Report individual findings with standalone severity
2. Suggest additional testing that might reveal chain opportunities
3. Note: "No chain identified, but testing X, Y, Z might reveal connections"

### Unverified Chain Steps
If some steps in a chain haven't been tested:
1. Mark the chain as "theoretical" or "partially verified"
2. Clearly indicate which steps are confirmed vs assumed
3. Provide testing instructions for unverified steps

## Examples

### Example 1: Full Chain Analysis
User says: "I found XSS on blog.example.com, SSRF on docs.example.com, and an open S3 bucket. Chain these."

Actions:
1. Import all three findings
2. Check cookie scope across subdomains
3. Check if SSRF can reach S3 internal endpoint
4. Build chains: XSS -> cookie theft -> access to docs -> SSRF -> S3
5. Calculate impact of full chain (Critical)
6. Generate PoC and report

### Example 2: Bug Bounty Report
User says: "Generate a HackerOne report for this chain of findings"

Actions:
1. Load the chain data
2. Write compelling title and summary
3. Format steps to reproduce with exact payloads
4. Include curl commands as PoC
5. Calculate and justify severity
6. Add remediation recommendations
7. Output markdown ready to paste into HackerOne

### Example 3: What-If Analysis
User says: "If they fix the XSS, can we still get to the S3 bucket?"

Actions:
1. Remove XSS from available findings
2. Re-run correlation with remaining findings
3. Check for alternative initial access paths
4. Report: alternative chains exist/don't exist
5. Recommend which fixes break the most chains
