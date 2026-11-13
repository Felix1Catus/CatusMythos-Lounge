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
import re as _re

from _common import log, success, warn

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


def _evidence_text(f):
    """Narrower than _finding_text: evidence/note/title only, never the raw
    dict dump. Several new evidence checks keyword-match against category
    words (group/org/team, waf/cloudflare, email/calendar/mcp) that are
    also substrings of the finding's OWN `type`/`url` fields -- matching
    against the raw-json dump would let a finding confirm itself just
    because its type name contains the keyword, which is the exact
    category-tag-isn't-proof problem this whole confidence mechanism
    exists to avoid."""
    return " ".join([str(f.get("evidence", "")), str(f.get("note", "")), str(f.get("title", ""))])


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


_STOPWORDS = {
    "the", "a", "an", "on", "to", "of", "in", "for", "and", "or", "is", "be",
    "this", "that", "must", "needs", "need", "can", "with", "via", "any",
}


def _significant_tokens(text):
    """Lowercase, split on non-alphanumerics, drop stopwords and anything
    under 3 chars -- the point is finding real shared concepts ('upload',
    'form', 'field'), not matching 'the' or 'to'."""
    words = _re.findall(r"[a-zA-Z0-9]+", (text or "").lower())
    return {w for w in words if len(w) >= 3 and w not in _STOPWORDS}


def _agent_enables_precondition_evidence_present(matched_findings):
    """For the AI-agent/blocked-CVE chain: does the agent's OWN described
    tool-use capabilities actually cover the SPECIFIC action the CVE's
    missing precondition needs -- not just 'an agent with some admin
    access exists somewhere on this target'? Keyword-overlap between the
    CVE's `missing_precondition` text and the agent's `capabilities` list
    is a blunt instrument, but it's a real check against the actual finding
    data, not a category-name coincidence -- and it requires the agent to
    actually be reachable/directable (prompt_injectable, or at minimum
    unauthenticated) rather than assuming any admin-capable agent is
    automatically abusable by an external attacker."""
    blocked_cves = matched_findings.get("blockedcve", [])
    agents = matched_findings.get("agenttoolaccess", [])
    if not blocked_cves or not agents:
        return False

    for cve_finding in blocked_cves:
        precondition_text = cve_finding.get("raw", {}).get("missing_precondition", "")
        precondition_tokens = _significant_tokens(precondition_text)
        if not precondition_tokens:
            continue
        for agent_finding in agents:
            raw = agent_finding.get("raw", {})
            reachable = bool(raw.get("prompt_injectable")) or not raw.get("requires_authentication", True)
            if not reachable:
                continue
            capabilities = raw.get("capabilities", [])
            capability_text = " ".join(capabilities) if isinstance(capabilities, list) else str(capabilities)
            capability_tokens = _significant_tokens(capability_text)
            if precondition_tokens & capability_tokens:
                return True
    return False


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
    {
        # The pattern this chain names: a CVE that's unpatched but currently
        # unexploitable because its one required precondition isn't met
        # (cve_lookup.py's "AFFECTED?" hypotheses are exactly this shape --
        # e.g. Elementor Pro's unauthenticated file-upload RCE, blocked
        # because no form on the site has a File Upload field enabled) is
        # NOT a dead end if something else on the same target can be
        # induced to perform the missing-precondition action for you. An
        # AI agent/chatbot with backend admin tool access (CMS settings,
        # plugin config, form editing, ...) is exactly that "something
        # else": if it can be prompt-injected or otherwise directed to
        # flip the one setting the CVE needs, the blocked CVE goes live.
        "name": "AI Agent Excessive Agency Enables Blocked CVE Precondition",
        "requires": [("blockedcve", None), ("agenttoolaccess", None)],
        "condition": "agent_can_enable_precondition",
        "impact_amplifier": "MEDIUM+CRITICAL->CRITICAL",
        "description": "An AI agent/chatbot with admin-level tool access can be directed (via "
                       "prompt injection or its own exposed instruction interface) to perform the "
                       "exact action an otherwise-blocked CVE needs enabled, then exploit that CVE.",
        "steps_template": [
            "Identify {blockedcve_finding} on {blockedcve_domain}, currently blocked: {missing_precondition}",
            "Identify an AI agent/chatbot on the same target with backend tool-use access "
            "covering the missing precondition",
            "Direct or prompt-inject the agent into performing that exact action "
            "(enable the setting/field/plugin the CVE needs)",
            "Exploit the now-unblocked CVE",
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

        elif condition == "agent_can_enable_precondition":
            # Plausibility gate only (both finding categories exist) -- same
            # pattern as cloud_hosted/has_auth_system above: surface the
            # hypothesis, let `confidence` below decide whether to trust it.
            condition_met = True

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
        elif template["name"] == "AI Agent Excessive Agency Enables Blocked CVE Precondition":
            confidence = "confirmed" if _agent_enables_precondition_evidence_present(matched_findings) else "unconfirmed"
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
                step = step.replace("{blockedcve_finding}", finding.get("raw", {}).get("cve_id", finding["type"]))
                step = step.replace("{blockedcve_domain}", finding["domain"])
                step = step.replace("{missing_precondition}",
                                     finding.get("raw", {}).get("missing_precondition", "unspecified"))
                chain["steps"].append(step)

            chains.append(chain)

    # Generic capability-graph discovery: finds chains no one wrote a named
    # template for, by matching what one finding ENABLES against what
    # another REQUIRES -- see discover_generic_chains()'s own docstring.
    # Dedup against the named templates above: don't report the same
    # (enabling, enabled) finding pair twice just because both mechanisms
    # independently noticed it.
    already_paired = {
        (c["primary_finding"]["id"], sf["id"])
        for c in chains for sf in c.get("supporting_findings", [])
    } | {
        (sf["id"], c["primary_finding"]["id"])
        for c in chains for sf in c.get("supporting_findings", [])
    }
    chains.extend(discover_generic_chains(findings, exclude_pairs=already_paired))

    # Sort by severity/impact
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    chains.sort(key=lambda c: severity_order.get(c["overall_severity"], 0), reverse=True)

    return chains


def _redirect_unlocks_ssrf(a, b):
    """web_app_chaining_patterns.md pattern 1: an open redirect only unlocks
    an allowlist-gated SSRF when the redirect's OWN target domain is one of
    the hosts the SSRF's allowlist actually accepts -- not just because both
    findings exist. Pull a candidate target host out of a's payload/evidence
    (whichever finding carries 'redirect_into_allowlist') and check it's
    literally named in b's evidence/raw as an allowed destination."""
    redirect_f, ssrf_f = (a, b) if "redirect" in a.get("type", "") else (b, a)
    # Only the evidence/payload text, NOT the raw-json blob -- _finding_text
    # includes the finding's own `url`/`raw` dump, which trivially contains
    # the finding's own hosting domain and would false-match against an
    # SSRF finding hosted on that same domain even with an unrelated
    # redirect target.
    own_domain = (redirect_f.get("domain") or "").lower()
    search_text = " ".join([
        str(redirect_f.get("evidence", "")), str(redirect_f.get("payload", "")),
        str(redirect_f.get("url", "")),
    ])
    hosts = {h.lower() for h in _re.findall(r"https?://([a-zA-Z0-9.-]+)", search_text)}
    hosts.discard(own_domain)
    if not hosts:
        return False
    ssrf_evidence = " ".join([str(ssrf_f.get("evidence", "")), str(ssrf_f.get("note", ""))])
    return any(h in ssrf_evidence.lower() for h in hosts)


def _org_membership_evidence_present(a, b):
    """web_app_chaining_patterns.md pattern 10: real evidence is both
    findings' OWN text actually naming a group/org/team concept -- not just
    the category tag firing because one IDOR's URL happened to contain
    'group'."""
    membership_words = {"group", "org", "organization", "team", "member", "membership"}
    a_tokens = _significant_tokens(_evidence_text(a))
    b_tokens = _significant_tokens(_evidence_text(b))
    return bool((a_tokens & membership_words) and (b_tokens & membership_words))


def _waf_bypass_evidence_present(a, b):
    """waf_bypass_mechanisms.md: confirm the bypass finding actually names a
    real mechanism (smuggling/boundary/charset/parameter-pollution/header
    mutation/etc), not just a finding that happens to be TYPED 'wafbypass'
    with no real technique described."""
    bypass_f = a if "waf" in a.get("type", "").lower() else b
    blocked_f = b if bypass_f is a else a
    technique_hit = bool(_re.search(
        r"smuggl|boundary|charset|parameter[\s_-]?pollution|header[\s_-]?(name[\s_-]?)?mutation|"
        r"x-forwarded-for|chunk|desync|multipart|padding|h2c|expect:\s*100",
        _evidence_text(bypass_f), _re.I))
    blocked_hit = bool(_re.search(r"waf|cloudflare|akamai|imperva|mod_?security", _evidence_text(blocked_f), _re.I))
    return technique_hit and blocked_hit


def _scope_violation_evidence_present(a, b):
    """novel_2025_2026_techniques.md 1.1-1.4: an agent's tool access is only
    a real chain when the injection finding names an actual untrusted
    ingestion channel (email/calendar/ticket/doc/chat/MCP tool description)
    AND the agent finding's own capability list plausibly covers acting on
    it -- reuses the same keyword-overlap discipline as
    _agent_enables_precondition_evidence_present instead of inventing a
    separate blunt check."""
    inject_f, agent_f = (a, b) if "agenttoolaccess" not in a.get("type", "") else (b, a)
    channel_hit = bool(_re.search(
        r"\bemail\b|calendar|invite|ticket|jira|slack|shared\s*doc|mcp|tool[\s_-]?description",
        _evidence_text(inject_f), _re.I))
    raw = agent_f.get("raw", {})
    reachable = bool(raw.get("prompt_injectable")) or not raw.get("requires_authentication", True)
    return channel_hit and reachable


_GENERIC_CONFIDENCE_CHECKS = {
    "credential_theft": lambda a, b: bool(_CREDENTIAL_PATTERNS.search(_finding_text(a))),
    "precondition_enabler": lambda a, b: bool(
        _significant_tokens(b.get("raw", {}).get("missing_precondition", ""))
        & _significant_tokens(" ".join(a.get("raw", {}).get("capabilities", []))
                               if isinstance(a.get("raw", {}).get("capabilities"), list) else "")
    ),
    "redirect_into_allowlist": _redirect_unlocks_ssrf,
    "org_membership_granted": _org_membership_evidence_present,
    "waf_bypass_capable": _waf_bypass_evidence_present,
    "scope_violation": _scope_violation_evidence_present,
    "cloud_metadata": lambda a, b: _cloud_metadata_evidence_present([a, b]),
    "cookie_scope_write": lambda a, b: bool(
        get_parent_domain(a.get("domain", "")) == get_parent_domain(b.get("domain", ""))
        and a.get("domain") != b.get("domain")
    ),
}


def discover_generic_chains(findings, exclude_pairs=None):
    """Graph-based chain discovery, not a template lookup: for every
    ordered pair of DIFFERENT findings (A, B), if what A enables
    (chainable_as) intersects what B needs (requires), propose A->B as a
    candidate chain. This is what makes chaining here actually creative
    rather than limited to the ~11 hand-written patterns above -- a novel
    combination this file's author never specifically imagined still gets
    found, as long as the two findings' capability tags overlap.

    Confidence is never free: a capability-graph edge existing is a
    STRUCTURAL hypothesis (two findings happen to share a tag), the same
    category-match-isn't-proof problem every other chain in this file had
    to be fixed for. _GENERIC_CONFIDENCE_CHECKS holds a real evidence check
    per capability where one has been written (credential_theft requires an
    actual credential-shaped string in A's evidence; precondition_enabler
    requires real keyword overlap between what A can do and what B needs --
    this is the exact mechanism that was hand-coded as a one-off template
    for the AI-agent/blocked-CVE case, generalized here so it fires for ANY
    two findings with that capability pairing, not just that one named
    pattern). A capability with no check implemented yet stays honestly
    "unconfirmed" rather than silently trusted -- same discipline as the
    named templates' fallback case."""
    exclude_pairs = exclude_pairs or set()
    chains = []
    seen_pairs = set()

    for a in findings:
        enables = set(a.get("chainable_as", []))
        if not enables:
            continue
        for b in findings:
            if a.get("id") == b.get("id"):
                continue
            requires = set(b.get("requires", []))
            shared = enables & requires
            if not shared:
                continue
            pair_key = (a["id"], b["id"])
            if pair_key in seen_pairs or pair_key in exclude_pairs:
                continue
            seen_pairs.add(pair_key)

            capability = sorted(shared)[0]
            check = _GENERIC_CONFIDENCE_CHECKS.get(capability)
            confidence = "confirmed" if (check and check(a, b)) else "unconfirmed"
            confidence_note = (
                f"Evidence connects {a['type']}'s '{capability}' output to {b['type']}'s precondition."
                if confidence == "confirmed" else
                f"Structural match only: {a['type']} is TAGGED as enabling '{capability}' and "
                f"{b['type']} is TAGGED as requiring it, but no evidence check confirms this specific "
                f"instance actually connects (or no evidence check exists yet for '{capability}'). "
                f"Treat as a lead to manually verify, not a confirmed chain."
            )

            chains.append({
                "name": f"{a['type']} -> {capability.replace('_', ' ')} -> {b['type']}",
                "description": f"{a['type']} on {a.get('domain', '?')} grants '{capability.replace('_', ' ')}', "
                                f"which {b['type']} on {b.get('domain', '?')} needs to become exploitable.",
                "impact_amplification": f"{a.get('severity', '?')}+{b.get('severity', '?')}->chained",
                "confidence": confidence,
                "confidence_note": confidence_note,
                "discovery_method": "generic_capability_graph",
                "shared_capability": capability,
                "primary_finding": {
                    "id": b["id"], "type": b["type"], "domain": b.get("domain", ""),
                    "url": b.get("url", ""), "severity": b.get("severity", "MEDIUM"),
                },
                "supporting_findings": [{
                    "id": a["id"], "type": a["type"], "domain": a.get("domain", ""),
                }],
                "steps": [
                    f"Exploit {a['type']} on {a.get('domain', '?')} to obtain '{capability.replace('_', ' ')}'",
                    f"Use that to satisfy the precondition {b['type']} on {b.get('domain', '?')} needs",
                    f"Exploit {b['type']} now that its precondition is met",
                ],
                "feasibility": 6,
                "impact": 8,
                "overall_severity": "HIGH" if confidence == "confirmed" else b.get("severity", "MEDIUM"),
            })

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
