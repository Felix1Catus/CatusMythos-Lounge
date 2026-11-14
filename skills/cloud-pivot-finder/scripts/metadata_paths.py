#!/usr/bin/env python3
"""
Cloud Metadata Pivot Path Mapper - cloud-pivot-finder
Identifies SSRF vectors and maps metadata->credential->pivot chains.
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime


from _common import log, success, vuln, warn
# Cloud metadata service endpoints
METADATA_ENDPOINTS = {
    "AWS IMDSv1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "credential_path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "token_header": None,
        "provider": "AWS",
    },
    "AWS IMDSv2": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "credential_path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "token_header": "X-aws-ec2-metadata-token",
        "token_url": "http://169.254.169.254/latest/api/token",
        "provider": "AWS",
    },
    "GCP Metadata": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "credential_path": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "required_header": {"Metadata-Flavor": "Google"},
        "provider": "GCP",
    },
    "Azure IMDS": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "credential_path": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "required_header": {"Metadata": "true"},
        "provider": "Azure",
    },
    "DigitalOcean Metadata": {
        "url": "http://169.254.169.254/metadata/v1/",
        "credential_path": None,
        "provider": "DigitalOcean",
    },
    # Container/orchestrator metadata variants beyond plain EC2 IMDS --
    # research_notes/Cloud pivot finder depth techniques/container_orchestrator_metadata.md.
    # These sit on a separate link-local address (ECS) or require the
    # attacker to already be running code inside a pod/container (the
    # others), so they're documented here for the pivot-path narrative
    # rather than probed directly by this external-recon tool.
    "AWS ECS Task Metadata v4": {
        "url": "http://169.254.170.2/v4/metadata",
        "credential_path": "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}",
        "token_header": None,
        "provider": "AWS",
        "note": "No token/PUT step at all -- reachability alone yields task-role credentials. "
                "v2 (http://169.254.170.2/v2/metadata) still works but AWS calls it no longer "
                "actively maintained; prefer v4. Hop-limit=1 does NOT block this on awsvpc/host "
                "network mode (only bridge mode adds the extra hop) -- AWS's actual fix is "
                "ECS_AWSVPC_BLOCK_IMDS=true in /etc/ecs/ecs.config.",
    },
    "Kubernetes kubelet (unauthenticated read-only)": {
        "url": "http://<node-ip>:10255/pods",
        "credential_path": None,
        "token_header": None,
        "provider": "Kubernetes",
        "note": "Deprecated but still found; CIS Kubernetes Benchmark 4.2.4 flags it. "
                "CVE-2025-0426 is a node-disk-fill DoS via this same unauthenticated endpoint "
                "(kubelet 1.30.0-1.30.9/1.31.0-1.31.5/1.32.0-1.32.1). The authenticated port "
                "10250 is a separate, still-relevant surface if --anonymous-auth=true (the "
                "Kubernetes default) is left unset.",
    },
    "GKE/GCP Metadata (node-level, from inside a pod)": {
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "credential_path": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "required_header": {"Metadata-Flavor": "Google"},
        "provider": "GCP",
        "note": "Only reachable from code already running inside a pod with node-metadata "
                "access (no NetworkPolicy/metadata-concealment blocking it). Google now labels "
                "pod-level metadata concealment (--workload-metadata=SECURE) Beta/deprecated and "
                "directs operators to Workload Identity Federation instead. Legacy v0.1/v1beta1 "
                "endpoints were fully shut down 2020-09-30 and should not respond.",
    },
    "EKS Pod Identity (token-gated variant)": {
        "url": "${AWS_CONTAINER_CREDENTIALS_FULL_URI}",
        "credential_path": "${AWS_CONTAINER_CREDENTIALS_FULL_URI}",
        "token_header": "Authorization (from AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)",
        "provider": "AWS",
        "note": "Unlike plain ECS task roles, EKS Pod Identity DOES require a bearer token read "
                "from a local file -- architecturally stronger than the token-free ECS surface above.",
    },
}

# AWS "ECScape" cross-task credential theft (Sweet Security, disclosed Black
# Hat USA 2025, no CVE assigned -- AWS calls it a design consideration, not a
# vulnerability): once code is already running inside ONE ECS container on a
# host where the host-level IMDS (169.254.169.254, not the per-task
# 169.254.170.2 endpoint) is reachable and the instance-profile role holds
# ecs:DiscoverPollEndpoint/ecs:Poll, that container can impersonate the ECS
# agent over the ACS WebSocket and receive every co-located TASK's
# credentials on that host -- not just its own. This is a post-exploitation
# escalation note for the pivot narrative, not something this external
# recon tool can probe for without already having a foothold.
ECSCAPE_NOTE = (
    "If host-level IMDS (169.254.169.254) is reachable from inside this "
    "container (not just the per-task 169.254.170.2 endpoint) and the "
    "instance role holds ecs:DiscoverPollEndpoint/ecs:Poll, the 'ECScape' "
    "technique (Sweet Security, Black Hat USA 2025) lets this container "
    "impersonate the ECS agent and harvest every other task's credentials "
    "on the same host -- a bigger blast radius than this task's own role."
)

# DNS-rebinding TOCTOU note -- CVE-2026-27127 (Craft CMS) is the clearest
# recent concrete example: an SSRF-blocklist that re-resolves a hostname
# separately from the actual connect (rather than pinning the validated IP)
# can be defeated by a short-TTL domain that answers safely on the check and
# flips to 169.254.169.254/127.0.0.1 at connect time. This requires attacker-
# controlled DNS infrastructure to actually run, so it's documented as a
# manual technique rather than coded as a live check here.
DNS_REBINDING_NOTE = (
    "If the target's SSRF filter re-resolves the hostname on each request "
    "rather than pinning a validated IP (a real TOCTOU pattern -- see "
    "CVE-2026-27127), a short-TTL rebinding domain that resolves safely on "
    "the filter's check and flips to the metadata IP at connect time can "
    "bypass a hostname-based allowlist. Requires attacker-controlled DNS; "
    "not something this tool probes for automatically."
)

# SSRF vector patterns found in web applications
SSRF_VECTOR_PATTERNS = {
    "url_parameter": {
        "patterns": [
            r"[?&](url|uri|link|href|src|source|target|dest|destination|redirect|redirect_url|"
            r"redirect_uri|return|return_url|returnTo|callback|next|continue|path|file|page|"
            r"load|fetch|proxy|proxy_url|image|img|avatar|icon|logo|preview|webhook|"
            r"feed|rss|xml|pdf|doc|download|upload|import|export|api|endpoint)=",
        ],
        "description": "URL parameter that may accept arbitrary URLs",
        "ssrf_likelihood": "high",
    },
    "pdf_generator": {
        "patterns": [
            r"/pdf", r"/generate.*pdf", r"/export.*pdf", r"/print",
            r"/render", r"/screenshot", r"/capture", r"/html2pdf",
            r"/wkhtmltopdf", r"/puppeteer", r"/phantom",
        ],
        "description": "PDF/screenshot generation endpoint (common SSRF vector)",
        "ssrf_likelihood": "high",
    },
    "webhook": {
        "patterns": [
            r"/webhook", r"/hook", r"/callback", r"/notify",
            r"/integration", r"/connect", r"/subscribe",
        ],
        "description": "Webhook/callback endpoint that may make outbound requests",
        "ssrf_likelihood": "medium",
    },
    "proxy_endpoint": {
        "patterns": [
            r"/proxy", r"/cors", r"/relay", r"/fetch",
            r"/gateway", r"/forward", r"/passthrough",
        ],
        "description": "Proxy/relay endpoint for outbound requests",
        "ssrf_likelihood": "high",
    },
    "import_endpoint": {
        "patterns": [
            r"/import", r"/upload.*url", r"/from.?url",
            r"/remote", r"/external", r"/crawl", r"/scrape",
        ],
        "description": "Import/upload-from-URL endpoint",
        "ssrf_likelihood": "high",
    },
    "image_processing": {
        "patterns": [
            r"/resize", r"/thumbnail", r"/crop", r"/transform",
            r"/optimize", r"/compress", r"/convert",
        ],
        "description": "Image processing endpoint that may fetch remote images",
        "ssrf_likelihood": "medium",
    },
}

# IAM role common permissions to document
IAM_ROLE_RISKS = {
    "AWS": {
        "s3_access": "Read/write to S3 buckets (data exfiltration, malware staging)",
        "ec2_access": "Manage EC2 instances (lateral movement, crypto mining)",
        "iam_access": "Manage IAM (privilege escalation, persistence)",
        "lambda_access": "Invoke/manage Lambda (code execution, data access)",
        "dynamodb_access": "Read/write DynamoDB (data exfiltration)",
        "secrets_manager": "Read secrets (credential theft)",
        "ssm_access": "SSM (command execution on instances)",
        "sts_assume_role": "AssumeRole (cross-account pivot)",
    },
    "GCP": {
        "storage_access": "Read/write Cloud Storage (data exfiltration)",
        "compute_access": "Manage Compute instances (lateral movement)",
        "iam_access": "Manage IAM (privilege escalation)",
        "functions_access": "Invoke Cloud Functions (code execution)",
        "service_account_token": "Create service account tokens (impersonation)",
        "secret_manager": "Read Secret Manager (credential theft)",
    },
    "Azure": {
        "storage_access": "Read/write Blob Storage (data exfiltration)",
        "vm_access": "Manage VMs (lateral movement)",
        "keyvault_access": "Read Key Vault secrets (credential theft)",
        "ad_access": "Azure AD operations (privilege escalation)",
        "managed_identity": "Managed identity token (cross-service pivot)",
    },
}


def http_get(url, timeout=5, extra_headers=None):
    """HTTP GET with SSL bypass."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "orizon-recon/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(32768).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return 0, ""


def extract_urls_from_recon(data):
    """Extract URLs and endpoints from recon data."""
    urls = set()

    def _walk(obj, depth=0):
        if depth > 10:
            return
        if isinstance(obj, str):
            # Extract URLs
            found = re.findall(r'https?://[^\s"\'<>]+', obj)
            urls.update(found)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, depth + 1)
        elif isinstance(obj, dict):
            for val in obj.values():
                _walk(val, depth + 1)

    _walk(data)
    return urls


def extract_hosts_from_recon(data):
    """Extract hosts and their cloud provider info from recon data."""
    hosts = {}

    if isinstance(data, dict):
        # Check for cloud_detection results
        if data.get("meta", {}).get("type") == "cloud_detection":
            for result in data.get("results", []):
                hostname = result.get("hostname", "")
                providers = result.get("providers_detected", [])
                if hostname:
                    hosts[hostname] = {
                        "providers": providers if isinstance(providers, list) else list(providers),
                        "services": result.get("cloud_services", []),
                    }
            return hosts

        # Generic extraction
        for key in ("subdomains", "hosts", "domains", "results", "targets"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        hosts[item] = {"providers": [], "services": []}
                    elif isinstance(item, dict):
                        for k in ("host", "hostname", "domain", "name"):
                            if k in item and isinstance(item[k], str):
                                hosts[item[k]] = {
                                    "providers": item.get("providers_detected", []),
                                    "services": item.get("cloud_services", []),
                                }
                                break

    return hosts


def identify_ssrf_vectors(urls):
    """Identify potential SSRF vectors from collected URLs."""
    vectors = []

    for url in urls:
        for vector_type, info in SSRF_VECTOR_PATTERNS.items():
            for pattern in info["patterns"]:
                if re.search(pattern, url, re.IGNORECASE):
                    vectors.append({
                        "url": url,
                        "vector_type": vector_type,
                        "description": info["description"],
                        "ssrf_likelihood": info["ssrf_likelihood"],
                    })
                    break  # One match per URL per type

    return vectors


def build_pivot_path(host, host_info, ssrf_vectors):
    """Build the complete pivot path description for a host."""
    providers = host_info.get("providers", [])
    if not providers:
        return None

    paths = []

    for provider in providers:
        provider_upper = provider.upper()
        if provider_upper in ("AWS", "AMAZON"):
            provider_key = "AWS"
        elif provider_upper in ("GCP", "GOOGLE"):
            provider_key = "GCP"
        elif provider_upper in ("AZURE", "MICROSOFT"):
            provider_key = "Azure"
        else:
            continue

        # Find relevant SSRF vectors for this host
        host_vectors = [v for v in ssrf_vectors if host in v.get("url", "")]

        # Build metadata chain
        metadata_info = {}
        for name, endpoint in METADATA_ENDPOINTS.items():
            if endpoint["provider"] == provider_key:
                metadata_info[name] = endpoint

        # Build IAM risk assessment
        iam_risks = IAM_ROLE_RISKS.get(provider_key, {})

        path = {
            "host": host,
            "provider": provider_key,
            "ssrf_vectors": host_vectors if host_vectors else [{
                "vector_type": "unknown",
                "description": "No specific SSRF vector identified - manual testing needed",
                "ssrf_likelihood": "unknown",
            }],
            "metadata_chain": {
                "step_1_ssrf": f"Exploit SSRF vulnerability to reach internal metadata endpoint",
                "step_2_metadata": {
                    name: {
                        "endpoint": ep["url"],
                        "credential_endpoint": ep.get("credential_path", "N/A"),
                        "required_headers": ep.get("required_header", ep.get("token_header", "none")),
                    }
                    for name, ep in metadata_info.items()
                },
                "step_3_credentials": f"Extract IAM role/service account credentials from metadata",
                "step_4_pivot": f"Use obtained credentials to access {provider_key} services",
            },
            "potential_iam_access": iam_risks,
            "pivot_description": (
                f"1. Identify SSRF vector on {host}\n"
                f"2. Exploit SSRF to query {provider_key} metadata service\n"
                f"3. Extract temporary credentials from IAM role/service account\n"
                f"4. Use credentials to access {provider_key} resources\n"
                f"5. Escalate privileges if IAM policy allows"
            ),
            "impact_assessment": {
                "data_access": "Potential access to cloud storage, databases, secrets",
                "lateral_movement": "Credentials may allow access to other cloud services",
                "persistence": "May be able to create new credentials or backdoor access",
                "privilege_escalation": "IAM role may have excessive permissions",
            },
            "depth_notes": (
                [DNS_REBINDING_NOTE] + ([ECSCAPE_NOTE] if provider_key == "AWS" else [])
            ),
        }

        paths.append(path)

    return paths


def main():
    parser = argparse.ArgumentParser(description="Metadata Pivot Path Mapper - orizon.one")
    parser.add_argument("--recon-data", "-r", required=True,
                        help="Recon JSON file (cloud_detection output or general recon)")
    parser.add_argument("--crawl-data", "-c",
                        help="Crawl data JSON file with discovered URLs")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Starting cloud metadata pivot path analysis...")

    # Load recon data
    with open(args.recon_data) as f:
        recon_data = json.load(f)

    # Extract hosts and their cloud info
    hosts = extract_hosts_from_recon(recon_data)
    log(f"Found {len(hosts)} host(s) with cloud provider information")

    # Extract URLs from recon data for SSRF vector identification
    urls = extract_urls_from_recon(recon_data)

    # Load additional crawl data if provided
    if args.crawl_data:
        with open(args.crawl_data) as f:
            crawl_data = json.load(f)
        crawl_urls = extract_urls_from_recon(crawl_data)
        urls.update(crawl_urls)
        log(f"Loaded {len(crawl_urls)} additional URLs from crawl data")

    log(f"Analyzing {len(urls)} URL(s) for SSRF vectors...")

    # Identify SSRF vectors
    ssrf_vectors = identify_ssrf_vectors(urls)
    if ssrf_vectors:
        warn(f"Found {len(ssrf_vectors)} potential SSRF vector(s)")
        for v in ssrf_vectors:
            warn(f"  [{v['ssrf_likelihood'].upper()}] {v['vector_type']}: {v['url'][:100]}")

    # Build pivot paths for each cloud-hosted application
    all_paths = []
    for host, host_info in hosts.items():
        if not host_info.get("providers"):
            continue
        paths = build_pivot_path(host, host_info, ssrf_vectors)
        if paths:
            all_paths.extend(paths)
            for p in paths:
                success(f"Pivot path mapped: {p['host']} -> {p['provider']} metadata -> credentials")

    # Generate summary of unique SSRF vector types
    ssrf_summary = {}
    for v in ssrf_vectors:
        vtype = v["vector_type"]
        if vtype not in ssrf_summary:
            ssrf_summary[vtype] = {"count": 0, "likelihood": v["ssrf_likelihood"]}
        ssrf_summary[vtype]["count"] += 1

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "metadata_pivot_paths",
            "tool": "cloud-pivot-finder by orizon.one",
            "hosts_analyzed": len(hosts),
        },
        "stats": {
            "cloud_hosts": len([h for h in hosts.values() if h.get("providers")]),
            "ssrf_vectors_found": len(ssrf_vectors),
            "pivot_paths_mapped": len(all_paths),
        },
        "ssrf_vectors": ssrf_vectors,
        "ssrf_summary": ssrf_summary,
        "pivot_paths": all_paths,
        "metadata_endpoints_reference": {
            name: {
                "url": ep["url"],
                "credential_path": ep.get("credential_path"),
                "provider": ep["provider"],
            }
            for name, ep in METADATA_ENDPOINTS.items()
        },
    }

    output_path = args.output or "metadata_pivot_paths.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  METADATA PIVOT PATH ANALYSIS")
    print(f"{'='*60}")
    print(f"  Cloud hosts analyzed  : {len(hosts)}")
    print(f"  SSRF vectors found    : {len(ssrf_vectors)}")
    print(f"  Pivot paths mapped    : {len(all_paths)}")
    if ssrf_summary:
        print(f"\n  SSRF Vector Types:")
        for vtype, info in sorted(ssrf_summary.items(), key=lambda x: -x[1]["count"]):
            print(f"    {vtype:25s} : {info['count']} ({info['likelihood']} likelihood)")
    if all_paths:
        print(f"\n  PIVOT PATHS:")
        for p in all_paths:
            print(f"    {p['host']} -> {p['provider']}:")
            print(f"      {p['pivot_description'].split(chr(10))[0]}")
            vectors = [v['vector_type'] for v in p['ssrf_vectors']]
            print(f"      Vectors: {', '.join(vectors)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
