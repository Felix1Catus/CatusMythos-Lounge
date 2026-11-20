#!/usr/bin/env python3
"""
Cloud Provider Detector - cloud-pivot-finder
Identifies cloud hosting from domain analysis.
Author: orizon.one
"""

import argparse
import importlib.util
import json
import re
import socket
import subprocess
import os
import ssl
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone


from _common import log, scoped_urlopen, success, warn
# Cloud service CNAME patterns
CNAME_PATTERNS = {
    "AWS S3": [r"\.s3[-.].*\.amazonaws\.com", r"\.s3\.amazonaws\.com"],
    "AWS CloudFront": [r"\.cloudfront\.net"],
    "AWS ELB": [r"\.elb\.amazonaws\.com"],
    "AWS Elastic Beanstalk": [r"\.elasticbeanstalk\.com"],
    "AWS API Gateway": [r"\.execute-api\..*\.amazonaws\.com"],
    "AWS Lambda URL": [r"\.lambda-url\..*\.on\.aws"],
    "AWS Amplify": [r"\.amplifyapp\.com"],
    "GCP Storage": [r"\.storage\.googleapis\.com"],
    "GCP App Engine": [r"\.appspot\.com"],
    "GCP Cloud Run": [r"\.run\.app"],
    "GCP Cloud Functions": [r"\.cloudfunctions\.net"],
    "GCP Firebase": [r"\.firebaseapp\.com", r"\.web\.app"],
    "Azure Websites": [r"\.azurewebsites\.net"],
    "Azure CDN": [r"\.azureedge\.net"],
    "Azure Traffic Manager": [r"\.trafficmanager\.net"],
    "Azure Blob Storage": [r"\.blob\.core\.windows\.net"],
    "Azure Front Door": [r"\.azurefd\.net"],
    "Heroku": [r"\.herokuapp\.com", r"\.herokudns\.com"],
    "Netlify": [r"\.netlify\.app", r"\.netlify\.com"],
    "Vercel": [r"\.vercel\.app", r"\.now\.sh"],
    "GitHub Pages": [r"\.github\.io"],
    "Cloudflare Pages": [r"\.pages\.dev"],
    "Fastly": [r"\.fastly\.net", r"\.fastlylb\.net"],
    "DigitalOcean Spaces": [r"\.digitaloceanspaces\.com"],
    "DigitalOcean App": [r"\.ondigitalocean\.app"],
}

# Response header patterns
HEADER_PATTERNS = {
    "AWS": ["x-amz-", "x-amzn-", "AmazonS3", "awselb", "cloudfront"],
    "GCP": ["x-guploader-", "x-goog-", "x-cloud-trace", "google"],
    "Azure": ["x-ms-", "x-azure-", "windows-azure", "microsoft"],
    "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
    "Fastly": ["x-fastly-", "fastly", "x-served-by"],
    "Akamai": ["x-akamai-", "akamai"],
}
CLOUD_PROVIDER_TTL = 3600


def _knowledge_target(hostname):
    """Build a credential-free origin for a hostname without probing it."""
    value = str(hostname).strip().strip(".")
    if not value or any(char in value for char in "/?#@"):
        raise ValueError("cloud knowledge requires a hostname, not a URL or path")
    rendered = f"[{value}]" if ":" in value and not value.startswith("[") else value
    return f"https://{rendered}/"


def _cloud_observation(result):
    """Return positive provider data only; omit IPs and all request/response material."""
    providers = result.get("providers_detected", [])
    if not isinstance(providers, list):
        return None
    providers = sorted({str(provider)[:120] for provider in providers if isinstance(provider, str) and provider.strip()})
    if not providers:
        return None
    services = []
    for item in result.get("cloud_services", []):
        if not isinstance(item, dict):
            continue
        safe = {key: str(item[key])[:300] for key in ("type", "hostname", "cname", "service", "provider", "header_match")
                if isinstance(item.get(key), str)}
        if safe:
            services.append(safe)
    return {"providers_detected": providers, "cloud_services": services}


def _restore_cloud_observation(hostname, value):
    """Rehydrate a cached positive provider result without implying a fresh IP lookup."""
    if not isinstance(value, dict):
        return None
    providers = value.get("providers_detected")
    services = value.get("cloud_services")
    if not isinstance(providers, list) or not providers or not isinstance(services, list):
        return None
    return {
        "hostname": hostname,
        "ip": None,
        "cloud_services": services,
        "providers_detected": providers,
        "knowledge_reused": True,
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
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def detect_from_cname(hostname):
    """Detect cloud provider from CNAME chain."""
    findings = []
    cname = resolve_cname(hostname)
    seen = set()

    while cname and cname not in seen:
        seen.add(cname)
        for service, patterns in CNAME_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, cname, re.IGNORECASE):
                    findings.append({
                        "type": "cname",
                        "hostname": hostname,
                        "cname": cname,
                        "service": service,
                    })
        # Follow CNAME chain
        next_cname = resolve_cname(cname)
        if next_cname == cname:
            break
        cname = next_cname

    return findings


def detect_from_headers(hostname, campaign_origin=None):
    """Detect cloud provider from HTTP response headers."""
    findings = []

    if campaign_origin:
        parsed_origin = urllib.parse.urlsplit(campaign_origin)
        if (parsed_origin.hostname or "").lower() != hostname.lower():
            return findings
        urls = [campaign_origin.rstrip("/") + "/"]
    else:
        urls = [f"{scheme}://{hostname}/" for scheme in ("https", "http")]

    for url in urls:
        ctx = ssl.create_default_context()
        if os.environ.get("CATUS_INSECURE_TLS") == "1":
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
        try:
            with scoped_urlopen(req, timeout=5, context=ctx) as resp:
                headers = dict(resp.headers)
                headers_str = json.dumps(headers).lower()

                for provider, patterns in HEADER_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.lower() in headers_str:
                            findings.append({
                                "type": "header",
                                "hostname": hostname,
                                "provider": provider,
                                "header_match": pattern,
                            })
                            break
                break
        except Exception:
            continue

    return findings


def detect_from_ip_whois(ip):
    """Check IP ownership for cloud provider."""
    if not ip:
        return None

    try:
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10
        )
        output = result.stdout.lower()

        if "amazon" in output or "aws" in output:
            return "AWS"
        elif "google" in output or "gcp" in output:
            return "GCP"
        elif "microsoft" in output or "azure" in output:
            return "Azure"
        elif "digitalocean" in output:
            return "DigitalOcean"
        elif "hetzner" in output:
            return "Hetzner"
        elif "ovh" in output:
            return "OVH"
        elif "linode" in output or "akamai" in output:
            return "Akamai/Linode"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def analyze_host(hostname, http_only=False, campaign_origin=None):
    """Analyze one host; campaign mode can limit detection to scoped HTTP headers."""
    result = {
        "hostname": hostname,
        "ip": None if http_only else resolve_ip(hostname),
        "cloud_services": [],
        "providers_detected": set(),
    }

    if not http_only:
        # DNS and WHOIS use network paths outside the HTTP request gate.
        cname_findings = detect_from_cname(hostname)
        for f in cname_findings:
            result["cloud_services"].append(f)
            provider = f["service"].split()[0]  # First word is usually the provider
            result["providers_detected"].add(provider)

    # Header analysis
    header_findings = detect_from_headers(hostname, campaign_origin=campaign_origin)
    for f in header_findings:
        result["cloud_services"].append(f)
        result["providers_detected"].add(f["provider"])

    # IP whois
    if not http_only and result["ip"]:
        ip_provider = detect_from_ip_whois(result["ip"])
        if ip_provider:
            result["providers_detected"].add(ip_provider)
            result["cloud_services"].append({
                "type": "ip_whois",
                "ip": result["ip"],
                "provider": ip_provider,
            })

    result["providers_detected"] = sorted(result["providers_detected"])
    return result


def _extract_hosts_from_json(data):
    """Extract hostnames from various recon JSON formats.

    Supported formats:
      - consolidated.json: {"subdomains": [{"host": ...}, ...], "results": [...]}
      - passive_recon_*.json: {"subdomains": [...], "hosts": [...]}
      - active_recon_*.json: {"results": [{"host": ...}, ...], "hosts": [...]}
      - port_scan_results.json: {"hosts": [{"ip": ..., "hostname": ...}, ...], "results": {...}}
      - Simple list: ["host1", "host2", ...]
      - Dict with domain keys: {"example.com": {...}, ...}
    """
    hosts = []

    if isinstance(data, list):
        # Plain list of strings or dicts
        for item in data:
            if isinstance(item, str):
                hosts.append(item)
            elif isinstance(item, dict):
                for key in ("host", "hostname", "domain", "name", "subdomain", "target"):
                    if key in item and isinstance(item[key], str):
                        hosts.append(item[key])
                        break
        return hosts

    if not isinstance(data, dict):
        return hosts

    # consolidated.json / passive_recon / active_recon: "subdomains" key
    if "subdomains" in data:
        subs = data["subdomains"]
        if isinstance(subs, list):
            for item in subs:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name", "subdomain"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "results" key (active_recon, consolidated)
    if "results" in data:
        results = data["results"]
        if isinstance(results, list):
            for item in results:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break
        elif isinstance(results, dict):
            # port_scan_results format: {"results": {"host_ip": {data}}}
            for key in results:
                if isinstance(results[key], dict):
                    inner = results[key]
                    for hk in ("hostname", "host", "domain"):
                        if hk in inner and isinstance(inner[hk], str):
                            hosts.append(inner[hk])
                            break
                    else:
                        # Use the key itself if it looks like a hostname
                        if not key.replace(".", "").isdigit():
                            hosts.append(key)

    # "hosts" key (passive_recon, port_scan_results)
    if "hosts" in data:
        h_list = data["hosts"]
        if isinstance(h_list, list):
            for item in h_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("hostname", "host", "domain", "ip", "name", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "domains" key
    if "domains" in data:
        d_list = data["domains"]
        if isinstance(d_list, list):
            for item in d_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "targets" key
    if "targets" in data:
        t_list = data["targets"]
        if isinstance(t_list, list):
            for item in t_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    return hosts


def main():
    parser = argparse.ArgumentParser(description="Cloud Detector - orizon.one", allow_abbrev=False)
    parser.add_argument("--domain", "-d", help="Single domain to analyze")
    parser.add_argument("--input", "-i", help="File with hostnames (one per line) or recon JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--knowledge-db", help="Opt-in shared SQLite target-knowledge file")
    parser.add_argument("--engagement", help="Required engagement namespace when knowledge is enabled")
    parser.add_argument("--knowledge-refresh", action="store_true", help="Force fresh DNS/header/WHOIS detection")
    parser.add_argument("--campaign-http-only", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    campaign_origin = os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN")
    if args.campaign_http_only and (not os.environ.get("CATUS_CAMPAIGN_GATE_DB")
                                    or not campaign_origin or not args.domain or args.input):
        parser.error("--campaign-http-only requires a campaign gate and one --domain")
    if args.engagement and not args.knowledge_db:
        parser.error("--engagement requires --knowledge-db")
    if args.knowledge_db and not args.engagement:
        parser.error("--knowledge-db requires --engagement")
    if args.knowledge_refresh and not args.knowledge_db:
        parser.error("--knowledge-refresh requires --knowledge-db")

    knowledge = None
    if args.knowledge_db:
        module_path = Path(__file__).resolve().parents[3] / "scripts" / "target_knowledge.py"
        if not module_path.is_file():
            parser.error("shared knowledge requires the full plugin checkout, including scripts/target_knowledge.py")
        spec = importlib.util.spec_from_file_location("catus_target_knowledge", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            knowledge = module.KnowledgeStore(args.knowledge_db, args.engagement,
                                              refresh=args.knowledge_refresh)
        except (ValueError, OSError, module.sqlite3.Error) as exc:
            parser.error(str(exc))

    log("Starting cloud provider detection...")

    hosts = []
    if args.domain:
        hosts = [args.domain.strip().lower()]

    if args.input:
        input_path = Path(args.input)
        if input_path.suffix == ".json":
            with open(input_path) as f:
                data = json.load(f)
            hosts.extend(_extract_hosts_from_json(data))
        else:
            hosts.extend([h.strip() for h in input_path.read_text().strip().split("\n") if h.strip()])

    # Deduplicate while preserving order
    seen = set()
    unique_hosts = []
    for h in hosts:
        h_lower = h.lower().strip()
        if h_lower and h_lower not in seen:
            seen.add(h_lower)
            unique_hosts.append(h_lower)
    hosts = unique_hosts

    log(f"Analyzing {len(hosts)} host(s)...")

    results = []
    provider_summary = {}
    hosts_to_scan = []

    for host in hosts:
        target = None
        if knowledge is not None:
            try:
                target = _knowledge_target(host)
            except ValueError:
                target = None
            if target and args.knowledge_refresh:
                knowledge.forget(target, "cloud_provider", "provider-detection", resource="/")
            if target and not args.knowledge_refresh:
                cached = knowledge.query(target, kind="cloud_provider", key="provider-detection", resource="/")
                if cached:
                    restored = _restore_cloud_observation(host, cached[-1].get("value"))
                    if restored:
                        results.append(restored)
                        continue
        hosts_to_scan.append(host)

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(
            analyze_host, host, args.campaign_http_only,
            campaign_origin if args.campaign_http_only else None): host for host in hosts_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if knowledge is not None:
                try:
                    target = _knowledge_target(result["hostname"])
                    observation = _cloud_observation(result)
                    if observation:
                        knowledge.observe(target, "cloud_provider", "provider-detection", observation,
                                          "cloud-pivot-finder/cloud_detector", confidence="observed",
                                          ttl=CLOUD_PROVIDER_TTL, resource="/")
                except (ValueError, OSError, module.sqlite3.Error):
                    warn(f"Could not save cloud-provider knowledge for {result['hostname']}")
            if result["providers_detected"]:
                success(f"{result['hostname']}: {', '.join(result['providers_detected'])}")

    for result in results:
        for provider in result["providers_detected"]:
            provider_summary[provider] = provider_summary.get(provider, 0) + 1

    output = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "type": "cloud_detection",
            "tool": "cloud-pivot-finder by orizon.one",
            "hosts_analyzed": len(hosts),
            "knowledge_reused_hosts": sum(1 for result in results if result.get("knowledge_reused")),
        },
        "provider_summary": provider_summary,
        "results": results,
    }

    domain = args.domain or "multi"
    output_path = args.output or f"cloud_detection_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=list)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  CLOUD DETECTION SUMMARY")
    print(f"{'='*60}")
    print(f"  Hosts analyzed: {len(hosts)}")
    print(f"  Cloud-hosted  : {sum(1 for r in results if r['providers_detected'])}")
    print(f"\n  Providers:")
    for provider, count in sorted(provider_summary.items(), key=lambda x: -x[1]):
        print(f"    {provider:25s} : {count} hosts")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
