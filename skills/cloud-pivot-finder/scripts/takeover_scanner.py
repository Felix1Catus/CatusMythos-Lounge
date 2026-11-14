#!/usr/bin/env python3
"""
Subdomain Takeover Scanner - cloud-pivot-finder
Checks subdomains for dangling CNAME records that may be claimable.
Author: orizon.one
"""

import argparse
import json
import re
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
import concurrent.futures
from pathlib import Path
from datetime import datetime


from _common import log, success, vuln, warn
# Fingerprints: service -> {cname_patterns, response_fingerprints, info}
#
# Refreshed against 2024-2026 can-i-take-over-xyz / nuclei-templates data
# (research_notes/Cloud pivot finder depth techniques/current_takeover_fingerprints.md).
# Two real bugs this refresh fixes:
#   1. CloudFront, GCS, Firebase, Fastly, and Zendesk were all coded with
#      their NEGATIVE (not-vulnerable) fingerprint strings but scored as
#      VULNERABLE on a match -- a confirmed false-positive on every one of
#      these five services. They're now `negative_fingerprints` entries.
#   2. AWS ELB's NXDOMAIN was scored as vulnerable, but per current
#      research an NXDOMAIN ELB CNAME target is not independently
#      claimable -- `nxdomain_vulnerable: False` makes it inert instead of
#      a false positive.
# Entries with `edge_case: True` still get reported but flagged as needing
# manual confirmation before treating them as a high-confidence finding
# (current account-verification models on these platforms make a bare
# fingerprint match insufficient proof).
TAKEOVER_FINGERPRINTS = {
    "AWS S3": {
        "cnames": [r"\.s3[.-].*\.amazonaws\.com", r"\.s3\.amazonaws\.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        # 2026 opt-in "account-regional namespace" buckets (suffix -an) can't
        # be re-claimed cross-account -- excluded per ProjectDiscovery's
        # maintained nuclei template, copied verbatim rather than re-derived.
        "exclude_cname": r"-[0-9]{12}-[a-z0-9-]+-an\.s3\.[a-z0-9-]+\.amazonaws\.com",
        "impact": "high",
        "method": "Create an S3 bucket with the matching name in any AWS account.",
    },
    "AWS CloudFront": {
        "cnames": [r"\.cloudfront\.net"],
        "negative_fingerprints": ["ViewerCertificateException"],
        "status": "fixed",
        "note": "Confirmed not exploitable -- 'ViewerCertificateException' means the distribution still exists under another owner.",
    },
    "AWS Elastic Beanstalk": {
        "cnames": [r"\.elasticbeanstalk\.com"],
        "nxdomain": True,
        "impact": "high",
        "method": "Create an Elastic Beanstalk environment with the matching subdomain prefix.",
    },
    "AWS ELB": {
        "cnames": [r"\.elb\.amazonaws\.com"],
        "nxdomain": True,
        "nxdomain_vulnerable": False,
        "status": "fixed",
        "note": "NXDOMAIN on an ELB CNAME target is not independently claimable -- not a takeover lead.",
    },
    "Azure (NXDOMAIN-confirmed)": {
        # Azure is confirmed-current-vulnerable via DNS resolution (NXDOMAIN
        # on the CNAME target), not via an HTTP body fingerprint, across this
        # broader suffix list -- the per-service body-fingerprint entries
        # below remain as a secondary signal for the services that also
        # resolve (don't NXDOMAIN) but still 404 with a service-specific body.
        "cnames": [
            r"\.cloudapp\.net", r"\.cloudapp\.azure\.com", r"\.azurewebsites\.net",
            r"\.blob\.core\.windows\.net", r"\.azure-api\.net", r"\.azurehdinsight\.net",
            r"\.azureedge\.net", r"\.azurecontainer\.io", r"\.database\.windows\.net",
            r"\.azuredatalakestore\.net", r"\.search\.windows\.net", r"\.azurecr\.io",
            r"\.redis\.cache\.windows\.net", r"\.servicebus\.windows\.net", r"\.trafficmanager\.net",
            r"\.visualstudio\.com",
        ],
        "nxdomain": True,
        "impact": "high",
        "method": "Create the matching Azure resource (App Service, Storage account, Traffic Manager profile, etc.) in any Azure subscription.",
    },
    "Azure Websites": {
        "cnames": [r"\.azurewebsites\.net"],
        "fingerprints": ["404 - Web Site not found", "404 Web Site not found"],
        "impact": "high",
        "method": "Create an Azure App Service with the matching name and add a custom domain.",
    },
    "Azure Blob Storage": {
        "cnames": [r"\.blob\.core\.windows\.net"],
        "fingerprints": ["BlobNotFound", "The specified blob does not exist", "ContainerNotFound"],
        "impact": "medium",
        "method": "Create an Azure Storage account with the matching name.",
    },
    "GCP Cloud Storage": {
        "cnames": [r"\.storage\.googleapis\.com"],
        "negative_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": "fixed",
        "note": "GCS's NoSuchBucket XML body is a suppression signal, not a takeover confirmation.",
    },
    "GCP App Engine": {
        "cnames": [r"\.appspot\.com"],
        "fingerprints": ["Error: Not Found", "The requested URL was not found on this server"],
        "nxdomain": True,
        "impact": "high",
        "method": "Create a GCP project with the matching App Engine application ID.",
    },
    "GCP Firebase": {
        "cnames": [r"\.firebaseapp\.com", r"\.web\.app"],
        "negative_fingerprints": ["Site Not Found", "Firebase Hosting Setup"],
        "status": "fixed",
        "note": "Firebase's default-bucket naming changed 2024-10-30 and legacy appspot.com bucket access for non-Blaze projects ends 2026-02-02 -- treat as not vulnerable.",
    },
    "Heroku": {
        "cnames": [r"\.herokuapp\.com", r"\.herokudns\.com"],
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"],
        "impact": "high",
        "edge_case": True,
        "method": "Create a Heroku app with the matching name and add the subdomain as a custom domain.",
    },
    "GitHub Pages": {
        "cnames": [r"\.github\.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
        "impact": "high",
        "edge_case": True,
        "note": "GitHub offers opt-in TXT-record domain verification (_github-challenge.<domain>), but it's per-account, not a platform-wide fix.",
        "method": "Create a GitHub repository matching the CNAME target and enable GitHub Pages.",
    },
    "Fastly": {
        "cnames": [r"\.fastly\.net", r"\.fastlylb\.net"],
        "negative_fingerprints": ["Fastly error: unknown domain:"],
        "status": "fixed",
        "note": "This fingerprint is Fastly's own suppression signature, not a takeover confirmation.",
    },
    "Shopify": {
        "cnames": [r"\.myshopify\.com", r"shops\.myshopify\.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "impact": "medium",
        "edge_case": True,
        "method": "Create a Shopify store and add the subdomain as a custom domain.",
    },
    "Zendesk": {
        "cnames": [r"\.zendesk\.com"],
        "negative_fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "status": "fixed",
        "note": "This fingerprint is Zendesk's own suppression signature, not a takeover confirmation.",
    },
    "Netlify": {
        "cnames": [r"\.netlify\.app", r"\.netlify\.com"],
        "fingerprints": ["Not Found - Request ID"],
        "impact": "high",
        "edge_case": True,
        "note": "Netlify requires TXT-record domain verification, but no official advisory confirms a platform-wide fix; live 2024-2025 community takeover reports continue.",
        "method": "Create a Netlify site and add the subdomain as a custom domain.",
    },
    "Vercel": {
        "cnames": [r"\.vercel\.app", r"\.now\.sh", r"cname\.vercel-dns\.com"],
        "fingerprints": ["DEPLOYMENT_NOT_FOUND."],
        "impact": "high",
        "edge_case": True,
        "note": "Disputed 'no longer vulnerable' claims are unresolved; live bug-bounty reports continue.",
        "method": "Create a Vercel project and add the subdomain as a custom domain.",
    },
    "Bitbucket": {
        "cnames": [r"\.bitbucket\.io"],
        "fingerprints": ["Repository not found"],
        "impact": "high",
        "edge_case": True,
        "note": "can-i-take-over-xyz issue #97 questions whether Bitbucket still supports CNAME-based custom domains at all -- confirm manually before reporting.",
        "method": "Create a Bitbucket repository with the matching name and configure a custom domain.",
    },
    "Wasabi": {
        "cnames": [r"\.wasabisys\.com"],
        "fingerprints": ["The specified bucket does not exist", "BucketName"],
        "impact": "high",
        "method": "Create a Wasabi bucket with the matching name (S3-compatible storage; not in the original 2017-era takeover lists).",
    },
    "Ngrok": {
        "cnames": [r"\.ngrok\.io"],
        "fingerprints": ["not found", "ngrok.io not found"],
        "impact": "medium",
        "method": "Start an ngrok tunnel claiming the matching subdomain.",
    },
    "Surge.sh": {
        "cnames": [r"\.surge\.sh"],
        "fingerprints": ["project not found"],
        "impact": "medium",
        "method": "Publish a Surge.sh project with the matching name.",
    },
    "Pantheon": {
        "cnames": [r"\.pantheonsite\.io"],
        "fingerprints": ["404 error unknown site!"],
        "impact": "high",
        "method": "Create a Pantheon site with the matching name.",
    },
    "Readme.io": {
        "cnames": [r"\.readme\.io"],
        "fingerprints": ["The creators of this project are still working on making everything perfect"],
        "impact": "medium",
        "method": "Create a ReadMe project with the matching subdomain.",
    },
    "Strikingly": {
        "cnames": [r"\.strikinglydns\.com"],
        "fingerprints": ["PAGE NOT FOUND"],
        "impact": "medium",
        "method": "Create a Strikingly site with the matching subdomain.",
    },
    "Ghost": {
        "cnames": [r"\.ghost\.io"],
        "fingerprints": ["Site unavailable.", "Failed to resolve DNS path for this host"],
        "impact": "medium",
        "method": "Create a Ghost(Pro) site with the matching subdomain.",
    },
    "Help Scout": {
        "cnames": [r"\.helpscoutdocs\.com"],
        "fingerprints": ["No settings were found for this company:"],
        "impact": "medium",
        "method": "Create a Help Scout Docs site with the matching subdomain.",
    },
    "WordPress.com": {
        "cnames": [r"\.wordpress\.com"],
        "fingerprints": ["Do you want to register"],
        "impact": "medium",
        "method": "Register the matching WordPress.com site.",
    },
}


def resolve_cname(hostname):
    """Get CNAME record for a hostname."""
    try:
        result = subprocess.run(
            ["dig", "CNAME", hostname, "+short"],
            capture_output=True, text=True, timeout=5
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def resolve_ip(hostname):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def check_nxdomain(hostname):
    """Check if a hostname resolves to NXDOMAIN."""
    try:
        socket.gethostbyname(hostname)
        return False
    except socket.gaierror:
        return True


def http_probe(hostname, timeout=5):
    """Probe a hostname via HTTP/HTTPS and return status + body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ["https", "http"]:
        url = f"{scheme}://{hostname}/"
        req = urllib.request.Request(url, headers={
            "User-Agent": "orizon-recon/1.0",
            "Host": hostname,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(16384).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(16384).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body
        except Exception:
            continue

    return 0, ""


def scan_subdomain(subdomain):
    """Scan a single subdomain for takeover vulnerability."""
    finding = {
        "subdomain": subdomain,
        "vulnerable": False,
        "cname": None,
        "cname_chain": [],
        "service": None,
        "evidence": None,
        "impact": None,
        "method": None,
        "edge_case": False,
        "not_vulnerable_checked": [],  # services whose negative fingerprint ruled them out
    }

    # Resolve CNAME chain
    cname = resolve_cname(subdomain)
    seen = set()
    chain = []

    current = cname
    while current and current not in seen:
        seen.add(current)
        chain.append(current)
        next_cname = resolve_cname(current)
        if next_cname == current:
            break
        current = next_cname

    finding["cname"] = cname
    finding["cname_chain"] = chain

    if not cname:
        return finding

    probed_body = None
    probed_status = None

    # Check each CNAME in the chain against fingerprints
    for service, fp in TAKEOVER_FINGERPRINTS.items():
        matched_cname = None
        for c in chain:
            for pattern in fp["cnames"]:
                if re.search(pattern, c, re.IGNORECASE):
                    matched_cname = c
                    break
            if matched_cname:
                break

        if not matched_cname:
            continue

        # A 2026 account-regional-namespace (or similarly excluded) target
        # isn't independently claimable -- skip this service entirely rather
        # than let it fall through to a fingerprint match.
        exclude = fp.get("exclude_cname")
        if exclude and re.search(exclude, matched_cname, re.IGNORECASE):
            continue

        # Check for NXDOMAIN on the CNAME target. nxdomain_vulnerable
        # defaults to True for backward compatibility with entries that
        # don't set it; AWS ELB explicitly sets it False since an NXDOMAIN
        # ELB target isn't independently claimable (see fingerprint note).
        if fp.get("nxdomain"):
            if check_nxdomain(matched_cname):
                if fp.get("nxdomain_vulnerable", True):
                    finding["vulnerable"] = True
                    finding["service"] = service
                    finding["evidence"] = f"CNAME target {matched_cname} returns NXDOMAIN"
                    finding["impact"] = fp["impact"]
                    finding["method"] = fp["method"]
                    finding["edge_case"] = fp.get("edge_case", False)
                    return finding
                else:
                    finding["not_vulnerable_checked"].append(
                        {"service": service, "reason": fp.get("note", "NXDOMAIN alone is not sufficient evidence")}
                    )
                continue

        # HTTP probe for error signatures (fetched once, reused across services)
        if probed_body is None:
            probed_status, probed_body = http_probe(subdomain)
            probed_status, probed_body = probed_status, probed_body or ""

        if probed_body:
            # Negative/suppression fingerprints are checked FIRST and, on a
            # match, positively rule the service out -- these are the
            # service's own "not found, name is already taken" signature,
            # not a takeover confirmation. Treating any fingerprint match as
            # "vulnerable" (the bug this refresh fixes) produced a false
            # positive on CloudFront/GCS/Firebase/Fastly/Zendesk.
            neg_hit = next((sig for sig in fp.get("negative_fingerprints", [])
                            if sig.lower() in probed_body.lower()), None)
            if neg_hit:
                finding["not_vulnerable_checked"].append(
                    {"service": service, "reason": fp.get("note", f"matched negative fingerprint '{neg_hit}'")}
                )
                continue

            for sig in fp.get("fingerprints", []):
                if sig.lower() in probed_body.lower():
                    finding["vulnerable"] = True
                    finding["service"] = service
                    finding["evidence"] = f"HTTP response contains '{sig}'"
                    finding["impact"] = fp["impact"]
                    finding["method"] = fp["method"]
                    finding["http_status"] = probed_status
                    finding["edge_case"] = fp.get("edge_case", False)
                    if fp.get("edge_case"):
                        finding["edge_case_note"] = fp.get(
                            "note", "Fingerprint match alone is insufficient proof -- confirm manually before reporting at high severity.")
                    return finding

    return finding


def load_subdomains(path):
    """Load subdomains from a file (text or JSON)."""
    p = Path(path)
    if p.suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        subs = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    subs.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "subdomain", "name"):
                        if key in item and isinstance(item[key], str):
                            subs.append(item[key])
                            break
        elif isinstance(data, dict):
            for key in ("subdomains", "hosts", "domains", "results", "targets"):
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, str):
                            subs.append(item)
                        elif isinstance(item, dict):
                            for k in ("host", "hostname", "domain", "subdomain", "name"):
                                if k in item and isinstance(item[k], str):
                                    subs.append(item[k])
                                    break
        return subs
    else:
        return [line.strip() for line in p.read_text().strip().split("\n") if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner - orizon.one")
    parser.add_argument("--subdomains", "-s", required=True,
                        help="File with subdomains (one per line or JSON)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=15,
                        help="Number of concurrent threads (default: 15)")
    args = parser.parse_args()

    log("Starting subdomain takeover scan...")

    subdomains = load_subdomains(args.subdomains)
    # Deduplicate
    subdomains = list(dict.fromkeys(s.lower().strip() for s in subdomains if s.strip()))

    log(f"Scanning {len(subdomains)} subdomain(s) for takeover vulnerabilities...")

    results = []
    vulnerable = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result["vulnerable"]:
                vulnerable.append(result)
                tag = "EDGE CASE (confirm manually)" if result["edge_case"] else "TAKEOVER"
                vuln(f"{tag}: {result['subdomain']} -> {result['cname']} "
                     f"({result['service']}, impact: {result['impact']})")
            elif result["cname"]:
                log(f"{result['subdomain']} -> {result['cname']} (not vulnerable)")

    confirmed = [v for v in vulnerable if not v["edge_case"]]
    edge_cases = [v for v in vulnerable if v["edge_case"]]

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "subdomain_takeover_scan",
            "tool": "cloud-pivot-finder by orizon.one",
            "subdomains_scanned": len(subdomains),
        },
        "stats": {
            "total_scanned": len(subdomains),
            "with_cname": sum(1 for r in results if r["cname"]),
            "vulnerable": len(vulnerable),
            "confirmed": len(confirmed),
            "edge_case": len(edge_cases),
        },
        "vulnerable": vulnerable,
        "all_results": results,
    }

    output_path = args.output or "takeover_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  SUBDOMAIN TAKEOVER SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Subdomains scanned : {len(subdomains)}")
    print(f"  With CNAME         : {sum(1 for r in results if r['cname'])}")
    print(f"  CONFIRMED          : {len(confirmed)}")
    print(f"  EDGE CASE          : {len(edge_cases)} (needs manual confirmation)")
    if confirmed:
        print(f"\n  CONFIRMED VULNERABLE SUBDOMAINS:")
        for v in confirmed:
            print(f"    {v['subdomain']}")
            print(f"      CNAME   : {v['cname']}")
            print(f"      Service : {v['service']}")
            print(f"      Impact  : {v['impact']}")
            print(f"      Evidence: {v['evidence']}")
            print(f"      Method  : {v['method']}")
            print()
    if edge_cases:
        print(f"\n  EDGE CASE SUBDOMAINS (fingerprint matched, needs manual confirmation):")
        for v in edge_cases:
            print(f"    {v['subdomain']} -> {v['service']}: {v.get('edge_case_note', '')}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
