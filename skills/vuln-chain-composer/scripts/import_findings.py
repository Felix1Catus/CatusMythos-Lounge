#!/usr/bin/env python3
"""
Findings Importer - vuln-chain-composer
Normalizes vulnerability findings from multiple sources.
Author: orizon.one
"""

import argparse
import json
import glob
import re as _re
from pathlib import Path
from datetime import datetime


def _finding_blob(finding):
    """All the free-text fields on a RAW (pre-normalize) finding dict worth
    pattern-matching against -- evidence/note/title plus the whole raw dict
    as JSON, so category-inference regexes see real content, not just the
    'type' field."""
    parts = [
        str(finding.get("evidence", "")), str(finding.get("note", "")),
        str(finding.get("title", "")), str(finding.get("url", "")),
        json.dumps(finding),
    ]
    return " ".join(parts)


from _common import log, success, warn
# Severity mapping
SEVERITY_MAP = {
    "error_based_sqli": "HIGH",
    "boolean_based_sqli": "MEDIUM",
    "time_based_sqli": "HIGH",
    "reflected_xss": "MEDIUM",
    "stored_xss": "HIGH",
    "dom_xss": "MEDIUM",
    "ssrf": "HIGH",
    "ssrf_cloud_metadata": "CRITICAL",
    "idor": "MEDIUM",
    "bola": "HIGH",
    "bfla": "HIGH",
    "mass_assignment": "MEDIUM",
    "jwt_none_algorithm": "CRITICAL",
    "jwt_weak_secret": "HIGH",
    "subdomain_takeover": "HIGH",
    "public_bucket": "HIGH",
    "ssti": "CRITICAL",
    "file_upload_rce": "CRITICAL",
    "open_redirect": "LOW",
    "info_disclosure": "LOW",
    "missing_headers": "INFO",
    "blockedcve": "MEDIUM",  # a version-matched, unpatched CVE whose precondition isn't met yet
    "agenttoolaccess": "LOW",  # the access existing isn't itself a vuln; the chain is
    "promptinjection": "MEDIUM",  # untrusted content an agent ingests; impact depends what it enables
    "wafbypass": "LOW",  # a demonstrated bypass technique; impact depends what it unblocks
    "hostheadertrust": "LOW",
    "cicdexposure": "MEDIUM",
    "cloudresourceaccess": "MEDIUM",
    "modelsupplychain": "HIGH",  # a DANGEROUS static pickle-opcode verdict -- RCE if this artifact gets loaded
    "unboundedconsumption": "LOW",  # OWASP LLM10: a missing config control (rate limit/logprobs/token cap), not a chainable primitive
}

# OWASP API Top 10 / Web Top 10 mapping
OWASP_MAP = {
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "ssrf": "A10:2021 - SSRF",
    "idor": "API1:2023 - BOLA",
    "bola": "API1:2023 - BOLA",
    "bfla": "API5:2023 - BFLA",
    "mass_assignment": "API6:2023 - Mass Assignment",
    "jwt": "API2:2023 - Broken Authentication",
    "ssti": "A03:2021 - Injection",
    "subdomain_takeover": "A05:2021 - Security Misconfiguration",
    "public_bucket": "A01:2021 - Broken Access Control",
    "open_redirect": "A01:2021 - Broken Access Control",
    "file_upload": "A04:2021 - Insecure Design",
}


def normalize_finding(finding, source_tool):
    """Normalize a finding to common format."""
    vuln_type = finding.get("type", "unknown")
    param = finding.get("param", finding.get("parameter", ""))
    url = finding.get("url", finding.get("target", ""))

    # Extract domain from URL
    domain = ""
    if url:
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).hostname or ""
        except Exception:
            pass

    severity = finding.get("severity", SEVERITY_MAP.get(vuln_type, "MEDIUM"))

    # Map to OWASP
    owasp = "Unknown"
    for key, mapping in OWASP_MAP.items():
        if key in vuln_type.lower():
            owasp = mapping
            break

    normalized = {
        "id": f"{vuln_type}_{domain}_{param}".replace(".", "_").replace("/", "_")[:100],
        "type": vuln_type,
        "category": vuln_type.split("_")[0] if "_" in vuln_type else vuln_type,
        "severity": severity,
        "owasp": owasp,
        "domain": domain,
        "url": url,
        "parameter": param,
        "method": finding.get("method", "GET"),
        "payload": finding.get("payload", ""),
        "evidence": finding.get("evidence", ""),
        "poc_curl": finding.get("poc_curl", ""),
        "source_tool": source_tool,
        "chainable_as": [],  # Populated in correlation step
        # The complement of chainable_as: what precondition this finding's
        # OWN exploitability depends on, from the same capability
        # vocabulary. correlate.py's generic chain-discovery walks this
        # against every OTHER finding's chainable_as -- A enables X, B
        # requires X => A->B is a candidate chain -- instead of needing a
        # hand-written named template for every pair. Not every finding
        # type has a real, currently-modeled precondition; [] means
        # "structurally reachable as-is, nothing else needed" rather than
        # "unknown".
        "requires": [],
        "raw": finding,
    }

    # Determine what this finding ENABLES for a follow-on finding (its
    # contribution to a chain as the earlier step) and what it REQUIRES to
    # become reachable/exploitable (its contribution as the later step).
    # correlate.py's generic chain-discovery walks every finding's enables
    # against every OTHER finding's requires over this same vocabulary --
    # A enables X, B requires X => A->B is a candidate chain, found by
    # graph matching rather than needing a named template per pair.
    if "sqli" in vuln_type:
        normalized["chainable_as"] = ["data_access", "credential_theft", "rce_potential"]
    elif "xss" in vuln_type:
        normalized["chainable_as"] = ["session_theft", "phishing", "keylogging", "cookie_scope_write"]
        if "self" in vuln_type or "post_only" in vuln_type or "postonly" in vuln_type:
            # Self-XSS / POST-only XSS can't reach a victim on its own -- it
            # needs something else to deliver it (CSRF, or a method-confusion
            # bug that lets the POST-only sink be hit via GET). See
            # web_app_chaining_patterns.md pattern 7 (PortSwigger 2025).
            normalized["requires"].append("delivery_mechanism")
    elif "methodconfusion" in vuln_type or "method_confusion" in vuln_type:
        normalized["chainable_as"] = ["delivery_mechanism"]
    elif "ssrf" in vuln_type:
        normalized["chainable_as"] = ["internal_access", "cloud_metadata", "port_scan"]
        # Pattern 1 (web_app_chaining_patterns.md): an SSRF that's actually
        # gated by a destination allowlist can be unlocked by a separate
        # open-redirect finding whose target happens to land inside that
        # allowlist -- a real, evidence-checked connection
        # (_redirect_unlocks_ssrf in correlate.py), not just a category tag.
        if _re.search(r"allow[\s_-]?list|whitelist|blocked|denied|filter", _finding_blob(finding), _re.I):
            normalized["requires"].append("redirect_into_allowlist")
    elif "idor" in vuln_type or "bola" in vuln_type:
        normalized["chainable_as"] = ["data_access", "privilege_escalation"]
        normalized["requires"] = ["authentication_bypass"]  # most IDORs still need SOME valid session
        # Pattern 10 (web_app_chaining_patterns.md): an IDOR that grants
        # group/org/team membership can unlock a SECOND IDOR (e.g. a
        # password/email-change endpoint) that only checks membership, not
        # identity. Only tag the enabling side when the evidence actually
        # talks about group/org/team; only tag the requiring side when it
        # talks about an account-management action -- so the graph edge
        # still needs _org_membership_evidence_present to confirm.
        blob = _finding_blob(finding)
        if _re.search(r"\b(group|org(?:anization)?|team|member(?:ship)?)\b", blob, _re.I):
            normalized["chainable_as"].append("org_membership_granted")
        if _re.search(r"password|email|role|permission|invite", blob, _re.I):
            normalized["requires"].append("org_membership_granted")
    elif "jwt" in vuln_type or "auth" in vuln_type:
        normalized["chainable_as"] = ["authentication_bypass", "impersonation"]
    elif "takeover" in vuln_type:
        normalized["chainable_as"] = ["phishing", "session_theft", "cookie_theft", "cookie_scope_write"]
    elif "bucket" in vuln_type or "storage" in vuln_type:
        normalized["chainable_as"] = ["data_access", "data_modification"]
    elif "ssti" in vuln_type:
        normalized["chainable_as"] = ["rce", "data_access"]
    elif "upload" in vuln_type:
        normalized["chainable_as"] = ["rce", "webshell"]
    elif "redirect" in vuln_type:
        normalized["chainable_as"] = ["phishing", "token_theft", "redirect_into_allowlist"]
    elif "blockedcve" in vuln_type:
        normalized["chainable_as"] = ["rce_potential", "precondition_dependent"]
        normalized["requires"] = ["precondition_enabler"]  # the one thing standing between it and live
    elif "agenttoolaccess" in vuln_type:
        normalized["chainable_as"] = ["precondition_enabler", "excessive_agency"]
        # novel_2025_2026_techniques.md 1.1-1.4 (EchoLeak/AgentFlayer/CurXecute):
        # an agent's tool/connector access only becomes an attacker-reachable
        # chain when something ELSE gets attacker-controlled instructions in
        # front of it (a scope violation). Tag it as needing that, same
        # discipline as blockedcve needing precondition_enabler.
        normalized["requires"].append("scope_violation")
    elif "promptinjection" in vuln_type or "scopeviolation" in vuln_type:
        # The untrusted-content side of the EchoLeak/AgentFlayer/ForcedLeak/
        # CurXecute/calendar-invite class: an injection point an AI agent
        # ingests from a lower-trust scope (email, calendar, ticket, shared
        # doc, Slack channel, MCP tool description).
        normalized["chainable_as"] = ["scope_violation"]
    elif "wafbypass" in vuln_type or "waf_bypass" in vuln_type:
        # Output of waf_bypass_tester.py (webapp-exploit-hunter): a
        # demonstrated technique that gets a payload past the WAF. On its
        # own it's not a vuln; it's what turns a "findings blocked by WAF"
        # entry into a live chain.
        normalized["chainable_as"] = ["waf_bypass_capable"]
    elif "hostheadertrust" in vuln_type or "host_header" in vuln_type:
        normalized["chainable_as"] = ["cache_poisoning", "ssrf_via_host_header"]
    elif "cicdexposure" in vuln_type or "ci_cd" in vuln_type:
        # cloud_api_chaining_patterns.md pattern 3: bot-counts-as-approver +
        # no branch protection + no deploy gate = PR-write implies prod RCE.
        normalized["chainable_as"] = ["deploy_access", "rce_potential"]
    elif "cloudresourceaccess" in vuln_type or "iamrole" in vuln_type:
        # cloud_api_chaining_patterns.md pattern 1: the lateral-movement step
        # after SSRF reaches cloud metadata -- requires that an SSRF (or
        # anything else) already proved metadata/IMDS reachability.
        normalized["chainable_as"] = ["data_access", "lateral_movement"]
        normalized["requires"] = ["cloud_metadata"]
    elif "modelsupplychain" in vuln_type:
        # model_supply_chain.py (16-ai-llm-security): a DANGEROUS verdict
        # means loading this specific artifact executes attacker code --
        # same directly-exploitable-once-reached shape as "upload" above,
        # not a blockedcve-style unconfirmed precondition, since the
        # scanner only flags a file it already found a real reason to
        # believe would get loaded.
        normalized["chainable_as"] = ["rce_potential"]

    # Cross-cutting: ANY finding whose own evidence says a payload got
    # blocked/filtered by a WAF (regardless of its vuln_type) now needs a
    # demonstrated bypass technique to actually be deliverable --
    # waf_bypass_tester.py findings grant exactly that capability. This is
    # what lets "XSS payload blocked by Cloudflare" + "parameter-pollution
    # WAF bypass confirmed on this target" become a chain, per
    # waf_bypass_mechanisms.md.
    if _re.search(r"\bwaf\b.*(block|filter|reject|denied|403)|cloudflare|akamai|imperva|"
                  r"aws\s*waf|azure\s*waf|mod_?security", _finding_blob(finding), _re.I):
        if "waf_bypass_capable" not in normalized["requires"]:
            normalized["requires"].append("waf_bypass_capable")

    return normalized


def load_findings_from_file(filepath):
    """Load and normalize findings from a JSON file."""
    try:
        with open(filepath) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        warn(f"Could not load {filepath}: {e}")
        return []

    # Detect source tool
    tool = data.get("meta", {}).get("tool", "unknown")
    finding_type = data.get("meta", {}).get("type", "")

    # Infer vulnerability type from filename when data lacks explicit type info
    fname = Path(filepath).stem.lower()
    inferred_type = ""
    if "sqli" in fname:
        inferred_type = "sqli"
    elif "xss" in fname:
        inferred_type = "xss"
    elif "ssrf" in fname:
        inferred_type = "ssrf"
    elif "api_discovery" in fname or "api-discovery" in fname:
        inferred_type = "info_disclosure"
    elif "bucket" in fname:
        inferred_type = "public_bucket"
    elif "trust_map" in fname or "trust-map" in fname:
        inferred_type = "trust_relationship"
    elif "attack_tree" in fname or "attack-tree" in fname:
        inferred_type = "attack_path"

    findings = data.get("findings", [])
    if not findings:
        # Try other common keys
        for key in ["vulnerabilities", "results", "issues"]:
            if key in data:
                findings = data[key]
                break

    # Handle recon-dominator consolidated.json format
    # Structure: {"meta": {...}, "data": {"passive_recon": {...}, "port_scan": {"results": [...]}, "tech_fingerprint": {...}}}
    if "data" in data and isinstance(data["data"], dict):
        consolidated = data["data"]

        # Import port scan results
        port_scan = consolidated.get("port_scan", {})
        for result in port_scan.get("results", []):
            host = result.get("host", result.get("ip", ""))
            for port_info in result.get("ports", result.get("open_ports", [])):
                port = port_info if isinstance(port_info, (int, str)) else port_info.get("port", "")
                service = port_info.get("service", "unknown") if isinstance(port_info, dict) else "unknown"
                findings.append({
                    "type": "info_disclosure",
                    "url": f"https://{host}:{port}",
                    "severity": "INFO",
                    "evidence": f"Open port {port} ({service}) on {host}",
                })

        # Import tech fingerprint findings
        tech = consolidated.get("tech_fingerprint", {})
        for target, tech_info in (tech.items() if isinstance(tech, dict) else []):
            if isinstance(tech_info, dict):
                for tech_name, details in tech_info.items():
                    version = details.get("version", "") if isinstance(details, dict) else str(details)
                    if version:
                        findings.append({
                            "type": "info_disclosure",
                            "url": f"https://{target}",
                            "severity": "LOW",
                            "evidence": f"Technology detected: {tech_name} {version}",
                        })

        # Import passive recon data (subdomains, DNS records, etc.)
        passive = consolidated.get("passive_recon", {})
        for sub in passive.get("subdomains", []):
            subdomain = sub if isinstance(sub, str) else sub.get("hostname", sub.get("subdomain", ""))
            if subdomain:
                findings.append({
                    "type": "info_disclosure",
                    "url": f"https://{subdomain}",
                    "severity": "INFO",
                    "evidence": f"Subdomain discovered: {subdomain}",
                })

        # Import any vulnerability data nested inside consolidated data sections
        for section_key, section_val in consolidated.items():
            if isinstance(section_val, dict):
                for nested_key in ["findings", "vulnerabilities", "results", "issues"]:
                    nested = section_val.get(nested_key, [])
                    if isinstance(nested, list):
                        findings.extend(nested)

    # Also import from attack trees
    if "attack_paths" in data:
        for path in data["attack_paths"]:
            findings.append({
                "type": f"attack_path_{path.get('attack_name', 'unknown').lower().replace(' ', '_')}",
                "url": f"https://{path.get('target', '')}",
                "severity": "HIGH" if path.get("combined_score", 0) >= 7 else "MEDIUM",
                "evidence": json.dumps(path.get("steps", [])[:3]),
            })

    # Import bucket findings
    if "public_buckets" in data:
        for bucket in data["public_buckets"]:
            findings.append({
                "type": "public_bucket",
                "url": f"https://{bucket['name']}.s3.amazonaws.com/" if bucket.get("provider") == "aws_s3" else bucket["name"],
                "severity": "HIGH",
                "evidence": f"Public listing with {bucket.get('files_visible', '?')} files",
            })

    # Import subdomain takeover findings
    if "relationships" in data:
        for rel in data["relationships"]:
            if rel.get("type") == "DANGLING_CNAME":
                findings.append({
                    "type": "subdomain_takeover",
                    "url": f"https://{rel.get('source', '')}",
                    "severity": "HIGH",
                    "evidence": f"Dangling CNAME to {rel.get('target', '')}",
                    "param": rel.get("target", ""),
                })

    # Import trust map data (trust_map.json)
    if "trust_relationships" in data or "trust_map" in data:
        trust_data = data.get("trust_relationships", data.get("trust_map", []))
        if isinstance(trust_data, list):
            for rel in trust_data:
                findings.append({
                    "type": "trust_relationship",
                    "url": f"https://{rel.get('source', rel.get('from', ''))}",
                    "severity": "INFO",
                    "evidence": f"Trust: {rel.get('source', rel.get('from', ''))} -> {rel.get('target', rel.get('to', ''))} ({rel.get('type', 'unknown')})",
                })
        elif isinstance(trust_data, dict):
            for source, targets in trust_data.items():
                target_list = targets if isinstance(targets, list) else [targets]
                for t in target_list:
                    target_name = t if isinstance(t, str) else t.get("target", t.get("to", str(t)))
                    findings.append({
                        "type": "trust_relationship",
                        "url": f"https://{source}",
                        "severity": "INFO",
                        "evidence": f"Trust: {source} -> {target_name}",
                    })

    # Import attack tree data (attack_tree.json)
    if "attack_tree" in data or "trees" in data:
        trees = data.get("attack_tree", data.get("trees", []))
        tree_list = trees if isinstance(trees, list) else [trees]
        for tree in tree_list:
            if isinstance(tree, dict):
                goal = tree.get("goal", tree.get("name", "unknown"))
                target = tree.get("target", "")
                score = tree.get("score", tree.get("risk_score", 5))
                findings.append({
                    "type": f"attack_path_{goal.lower().replace(' ', '_')[:50]}",
                    "url": f"https://{target}" if target else "",
                    "severity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
                    "evidence": json.dumps(tree.get("steps", tree.get("nodes", []))[:5]),
                })

    # Import API discovery data (api_discovery_*.json)
    if "endpoints" in data or "apis" in data:
        endpoints = data.get("endpoints", data.get("apis", []))
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url", ep.get("endpoint", ""))
                method = ep.get("method", "GET")
                auth_required = ep.get("auth_required", ep.get("authenticated", True))
                if not auth_required:
                    findings.append({
                        "type": "info_disclosure",
                        "url": url,
                        "method": method,
                        "severity": "MEDIUM",
                        "evidence": f"Unauthenticated API endpoint: {method} {url}",
                    })
                else:
                    findings.append({
                        "type": "info_disclosure",
                        "url": url,
                        "method": method,
                        "severity": "INFO",
                        "evidence": f"API endpoint discovered: {method} {url}",
                    })

    # Apply inferred type from filename to findings that lack a type
    if inferred_type:
        for f in findings:
            if not f.get("type") or f["type"] == "unknown":
                f["type"] = inferred_type

    normalized = []
    for finding in findings:
        normalized.append(normalize_finding(finding, tool))

    return normalized


def main():
    parser = argparse.ArgumentParser(description="Findings Importer - orizon.one")
    parser.add_argument("--input", "-i", required=True, nargs="+",
                        help="JSON files or directories with findings")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Importing and normalizing findings...")

    all_findings = []
    files_processed = 0

    for input_path in args.input:
        path = Path(input_path)
        if path.is_dir():
            json_files = list(path.glob("**/*.json"))
            for jf in json_files:
                findings = load_findings_from_file(str(jf))
                if findings:
                    all_findings.extend(findings)
                    files_processed += 1
                    success(f"Loaded {len(findings)} findings from {jf.name}")
        elif path.is_file():
            findings = load_findings_from_file(str(path))
            if findings:
                all_findings.extend(findings)
                files_processed += 1
                success(f"Loaded {len(findings)} findings from {path.name}")

    # Deduplicate by ID
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique_findings.append(f)

    # Stats
    by_severity = {}
    by_type = {}
    by_domain = {}
    for f in unique_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        typ = f["category"]
        by_type[typ] = by_type.get(typ, 0) + 1
        dom = f["domain"]
        by_domain[dom] = by_domain.get(dom, 0) + 1

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "normalized_findings",
            "tool": "vuln-chain-composer by orizon.one",
            "files_processed": files_processed,
            "total_findings": len(unique_findings),
        },
        "stats": {
            "by_severity": by_severity,
            "by_type": by_type,
            "by_domain": by_domain,
        },
        "findings": unique_findings,
    }

    output_path = args.output or "normalized_findings.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  FINDINGS IMPORT SUMMARY")
    print(f"{'='*60}")
    print(f"  Files processed : {files_processed}")
    print(f"  Total findings  : {len(unique_findings)}")
    print(f"\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            print(f"    {sev:10s} : {by_severity[sev]}")
    print(f"\n  By Type:")
    for typ, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {typ:25s} : {count}")
    print(f"\n  By Domain:")
    for dom, count in sorted(by_domain.items(), key=lambda x: -x[1])[:10]:
        print(f"    {dom:35s} : {count}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
