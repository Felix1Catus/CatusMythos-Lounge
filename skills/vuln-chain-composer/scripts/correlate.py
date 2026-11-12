#!/usr/bin/env python3
"""
Vulnerability Correlator - vuln-chain-composer
Identifies chainable vulnerability combinations across domains.
Author: orizon.one
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


import re as _re

# A chain's whole point is "primitive A, when actually chained to primitive B,
# becomes worse than either alone" -- but every template below used to escalate
# straight to CRITICAL/HIGH the moment the required FINDING CATEGORIES existed,
# with several conditions hardcoded to always pass (`cloud_hosted`,
# `has_auth_system` both just returned True). That's a template match, not a
# proven chain, and it is exactly what produced a CVSS 10.0 "Account Takeover"
# on a real engagement where no credential was ever actually found -- the
# underlying finding was a username disclosure, not a leaked secret.
#
# Fix: every chain now carries a `confidence` field. "unconfirmed" (the
# default) keeps the PRIMARY FINDING's OWN reported severity -- it is reported
# as a hypothesis/lead worth investigating, not as the amplified severity.
# "confirmed" is only set when the template's own evidence check (below)
# finds something in the finding data that actually supports the specific
# chain claim, and only then does calculate_impact.py apply the CVSS
# override / amplified severity.
_CREDENTIAL_PATTERNS = _re.compile(
    r"(?i)(password\s*[:=]|api[_-]?key\s*[:=]|secret[_-]?key\s*[:=]|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN\s+(RSA|OPENSSH|PGP|PRIVATE)|"
    r"bearer\s+[a-z0-9._-]{20,}|authorization\s*:\s*\S{20,}|"
    r"client_secret\s*[:=])"
)


def _finding_text(f):
    """All the free-text fields worth scanning for real evidence, joined."""
    parts = [
        str(f.get("evidence", "")), str(f.get("note", "")), str(f.get("title", "")),
        json.dumps(f.get("raw", {})) if f.get("raw") else "",
    ]
    return " ".join(parts)


def _credential_evidence_present(matched_findings):
    """For the info-disclosure->credential-reuse chain: is there an actual
    credential-shaped string in the evidence, or just 'information was
    disclosed' (a username, a version string, an email address, ...)?"""
    for f in matched_findings.get("info", []):
        if _CREDENTIAL_PATTERNS.search(_finding_text(f)):
            return True
    return False


def _cloud_metadata_evidence_present(findings):
    """For SSRF->cloud chain: does any finding's own evidence actually show
    the metadata endpoint was reached (not just 'this looks cloud-hosted')?"""
    for f in findings:
        if _re.search(r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data",
                       _finding_text(f) + f.get("url", ""), _re.I):
            return True
    return False


def _auth_system_evidence_present(findings):
    """For SQLi->account-takeover chain: is there an actual discovered login/
    auth surface in this engagement's own findings, not just 'most apps have
    one'?"""
    return any(
        _re.search(r"login|signin|sign-in|/auth|/wp-login|/admin", f.get("url", ""), _re.I)
        for f in findings
    )


# Chain templates: (vuln_a_category, vuln_b_category) -> chain description
CHAIN_TEMPLATES = [
    {
        "name": "XSS to Session Hijacking Across Subdomains",
        "requires": [("xss", None)],
        "condition": "shared_cookie_scope",
        "impact_amplifier": "HIGH->CRITICAL",
        "description": "XSS on any subdomain steals session cookies valid across all subdomains",
        "steps_template": [
            "Exploit {xss_finding} on {xss_domain}",
            "Steal session cookie scoped to .{parent_domain}",
            "Use stolen cookie to access {target_domain} as victim",
        ],
    },
    {
        "name": "SSRF to Cloud Infrastructure Compromise",
        "requires": [("ssrf", None)],
        "condition": "cloud_hosted",
        "impact_amplifier": "MEDIUM->CRITICAL",
        "description": "SSRF accesses cloud metadata to steal IAM credentials",
        "steps_template": [
            "Exploit {ssrf_finding} on {ssrf_domain}",
            "Access cloud metadata endpoint (169.254.169.254)",
            "Extract IAM/service account credentials",
            "Use credentials to access cloud resources",
        ],
    },
    {
        "name": "SSRF + Public Bucket = Data Exfiltration",
        "requires": [("ssrf", None), ("bucket", None)],
        "condition": None,
        "impact_amplifier": "MEDIUM+HIGH->CRITICAL",
        "description": "SSRF enables access to internal bucket endpoints, public bucket confirms data exposure",
        "steps_template": [
            "Exploit {ssrf_finding} to access internal S3/GCS endpoint",
            "List contents of {bucket_name}",
            "Exfiltrate sensitive data from bucket",
        ],
    },
    {
        "name": "SQLi to Credential Theft to Account Takeover",
        "requires": [("sqli", None)],
        "condition": "has_auth_system",
        "impact_amplifier": "HIGH->CRITICAL",
        "description": "SQL injection extracts password hashes, cracked passwords give account access",
        "steps_template": [
            "Exploit {sqli_finding} on {sqli_domain}",
            "Extract user table with password hashes",
            "Crack hashes (bcrypt/argon2 may resist, MD5/SHA1 will fall)",
            "Login as admin/privileged user",
        ],
    },
    {
        "name": "Subdomain Takeover to Cookie Theft",
        "requires": [("takeover", None)],
        "condition": "shared_cookie_scope",
        "impact_amplifier": "HIGH->CRITICAL",
        "description": "Subdomain takeover hosts attacker-controlled page that steals wildcard cookies",
        "steps_template": [
            "Take over {takeover_subdomain} via {takeover_method}",
            "Host cookie-stealing page on taken-over subdomain",
            "Cookies scoped to .{parent_domain} are sent to attacker",
            "Use stolen cookies to access other subdomains",
        ],
    },
    {
        "name": "Open Redirect + OAuth = Token Theft",
        "requires": [("redirect", None)],
        "condition": "has_oauth",
        "impact_amplifier": "LOW->HIGH",
        "description": "Open redirect in OAuth callback leaks authorization code/token to attacker",
        "steps_template": [
            "Identify open redirect on {redirect_domain}",
            "Craft OAuth authorization URL with redirect to attacker",
            "Victim clicks link, authenticates normally",
            "Authorization code/token redirected to attacker",
        ],
    },
    {
        "name": "IDOR + PII Exposure = Mass Data Breach",
        "requires": [("idor", None)],
        "condition": None,
        "impact_amplifier": "MEDIUM->CRITICAL",
        "description": "IDOR enables enumeration of all user records containing PII",
        "steps_template": [
            "Exploit {idor_finding} on {idor_domain}",
            "Enumerate sequential/predictable IDs",
            "Collect PII (email, name, address) from all user records",
            "Impact: Full user database exposure",
        ],
    },
    {
        "name": "Self-XSS + CSRF = Weaponized Stored XSS",
        "requires": [("xss", None)],
        "condition": "no_csrf_protection",
        "impact_amplifier": "LOW->HIGH",
        "description": "Self-XSS becomes exploitable when combined with missing CSRF protection",
        "steps_template": [
            "Identify self-XSS in user profile/settings on {xss_domain}",
            "Craft CSRF page that submits XSS payload to victim's profile",
            "Victim visits attacker page, XSS payload stored in their profile",
            "XSS triggers when victim (or admin) views the profile",
        ],
    },
    {
        "name": "CI/CD Access to Production RCE",
        "requires": [("attack_path", "ci_cd")],
        "condition": None,
        "impact_amplifier": "HIGH->CRITICAL",
        "description": "Access to CI/CD system enables code deployment to production",
        "steps_template": [
            "Access CI/CD system via {initial_access}",
            "Modify build pipeline to inject backdoor",
            "Code automatically deployed to production",
            "Full RCE on production servers",
        ],
    },
    {
        "name": "Info Disclosure + Credential Reuse = Account Takeover",
        "requires": [("info", None)],
        "condition": None,
        "impact_amplifier": "LOW->HIGH",
        "description": "Exposed credentials or API keys from info disclosure used to access other systems",
        "steps_template": [
            "Extract credentials from {info_source}",
            "Test credentials against other services (admin panels, APIs, SSH)",
            "Credential reuse grants access to additional systems",
        ],
    },
]


def get_parent_domain(domain):
    """Extract parent domain from subdomain."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def find_chains(findings):
    """Find all possible chains from the findings."""
    chains = []

    # Group findings by domain and category
    by_domain = defaultdict(list)
    by_category = defaultdict(list)
    by_parent_domain = defaultdict(list)
    all_domains = set()

    for f in findings:
        by_domain[f["domain"]].append(f)
        by_category[f["category"]].append(f)
        parent = get_parent_domain(f["domain"])
        by_parent_domain[parent].append(f)
        all_domains.add(f["domain"])

    # Check each chain template
    for template in CHAIN_TEMPLATES:
        # Check if required vulnerability types exist
        required_met = True
        matched_findings = {}

        for req_category, req_subtype in template["requires"]:
            matching = by_category.get(req_category, [])
            if req_subtype:
                matching = [f for f in matching if req_subtype in f["type"]]
            if not matching:
                required_met = False
                break
            matched_findings[req_category] = matching

        if not required_met:
            continue

        # Check conditions
        condition = template.get("condition")
        condition_met = True

        if condition == "shared_cookie_scope":
            # Multiple subdomains under same parent domain
            for parent, domain_findings in by_parent_domain.items():
                domains_with_findings = set(f["domain"] for f in domain_findings)
                if len(domains_with_findings) >= 2:
                    condition_met = True
                    break
            else:
                # Even single domain with wildcard cookie scope is risky
                condition_met = len(all_domains) >= 1

        elif condition == "cloud_hosted":
            # This gate decides whether to SURFACE the hypothesis at all, not
            # whether to trust it -- stays permissive (SSRF is itself worth
            # flagging as a lead regardless), but it no longer silently
            # becomes the reason a CRITICAL gets reported: see `confidence`
            # below, which checks for REAL metadata-endpoint evidence before
            # any severity amplification happens.
            condition_met = True

        elif condition == "has_auth_system":
            condition_met = True  # same: a plausibility gate, not proof -- see `confidence` below

        elif condition == "has_oauth":
            # Check if any finding mentions OAuth/SSO
            condition_met = any("oauth" in f["url"].lower() or "sso" in f["url"].lower()
                               for f in findings)

        elif condition == "no_csrf_protection":
            # Check missing security headers
            condition_met = any("csrf" not in json.dumps(f.get("raw", {})).lower()
                                for f in findings)

        if not condition_met:
            continue

        # Does this SPECIFIC chain have real supporting evidence, or is it
        # purely a category-name match? Only the templates we have an actual
        # evidence check for can ever be "confirmed" -- everything else stays
        # "unconfirmed" (a lead to investigate, not a finding to report at
        # the amplified severity) until a human verifies it.
        if template["name"] == "Info Disclosure + Credential Reuse = Account Takeover":
            confidence = "confirmed" if _credential_evidence_present(matched_findings) else "unconfirmed"
        elif template["name"] == "SSRF to Cloud Infrastructure Compromise":
            confidence = "confirmed" if _cloud_metadata_evidence_present(findings) else "unconfirmed"
        elif template["name"] == "SQLi to Credential Theft to Account Takeover":
            confidence = "confirmed" if _auth_system_evidence_present(findings) else "unconfirmed"
        else:
            # No evidence-check implemented yet for this template -- stay
            # honest about that rather than silently trusting the category
            # match the way every template used to.
            confidence = "unconfirmed"

        # Build concrete chains from matched findings
        primary_category = template["requires"][0][0]
        for finding in matched_findings.get(primary_category, []):
            amplified_severity = "CRITICAL" if "CRITICAL" in template["impact_amplifier"] else "HIGH"
            chain = {
                "name": template["name"],
                "description": template["description"],
                "impact_amplification": template["impact_amplifier"],
                "confidence": confidence,
                "confidence_note": (
                    "Evidence in the matched finding(s) supports this specific chain claim."
                    if confidence == "confirmed" else
                    "This is a PATTERN MATCH on finding categories, not a proven chain -- "
                    "no evidence in the finding data confirms the chain's premise "
                    "(e.g. no actual credential string found, no metadata-endpoint hit "
                    "observed). Treat as a lead to manually verify, not a confirmed "
                    "finding at the amplified severity."
                ),
                "primary_finding": {
                    "id": finding["id"],
                    "type": finding["type"],
                    "domain": finding["domain"],
                    "url": finding["url"],
                    "severity": finding["severity"],
                },
                "supporting_findings": [],
                "steps": [],
                "feasibility": 7,  # Default, adjusted below
                "impact": 9,
                # Only amplify severity when the chain is actually confirmed --
                # otherwise report it at the primary finding's own reported
                # severity, which is what it's known to be worth right now.
                "overall_severity": amplified_severity if confidence == "confirmed" else finding["severity"],
            }

            # Add supporting findings
            for cat, cat_findings in matched_findings.items():
                if cat != primary_category:
                    for sf in cat_findings:
                        chain["supporting_findings"].append({
                            "id": sf["id"],
                            "type": sf["type"],
                            "domain": sf["domain"],
                        })

            # Build steps from template
            for step_template in template["steps_template"]:
                step = step_template
                step = step.replace("{xss_domain}", finding["domain"])
                step = step.replace("{ssrf_domain}", finding["domain"])
                step = step.replace("{sqli_domain}", finding["domain"])
                step = step.replace("{idor_domain}", finding["domain"])
                step = step.replace("{redirect_domain}", finding["domain"])
                step = step.replace("{parent_domain}", get_parent_domain(finding["domain"]))
                step = step.replace("{xss_finding}", finding["type"])
                step = step.replace("{ssrf_finding}", finding["type"])
                step = step.replace("{sqli_finding}", finding["type"])
                step = step.replace("{idor_finding}", finding["type"])
                chain["steps"].append(step)

            chains.append(chain)

    # Sort by severity/impact
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    chains.sort(key=lambda c: severity_order.get(c["overall_severity"], 0), reverse=True)

    return chains


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Correlator - orizon.one")
    parser.add_argument("--findings", "-f", required=True, help="Normalized findings JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Starting vulnerability correlation...")

    with open(args.findings) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    log(f"Loaded {len(findings)} findings to correlate")

    chains = find_chains(findings)

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "vulnerability_correlation",
            "tool": "vuln-chain-composer by orizon.one",
            "input_findings": len(findings),
            "chains_identified": len(chains),
        },
        "chains": chains,
    }

    output_path = args.output or "chains.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  VULNERABILITY CHAIN ANALYSIS")
    print(f"{'='*60}")
    print(f"  Input findings    : {len(findings)}")
    print(f"  Chains identified : {len(chains)}")

    for i, chain in enumerate(chains[:10]):
        print(f"\n  Chain {i+1}: {chain['name']}")
        print(f"    Severity: {chain['overall_severity']} (amplified from {chain['impact_amplification']})")
        print(f"    Primary: {chain['primary_finding']['type']} on {chain['primary_finding']['domain']}")
        for j, step in enumerate(chain["steps"]):
            print(f"    Step {j+1}: {step}")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
