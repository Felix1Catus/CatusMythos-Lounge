#!/usr/bin/env python3
"""
Cloud Storage Bucket Enumerator - cloud-pivot-finder
Discovers and tests S3, GCS, and Azure Blob storage.
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import urllib.request
import urllib.parse
import concurrent.futures
from pathlib import Path
from datetime import datetime

# Credential-shaped strings worth scanning sample bucket contents for.
# Cross-cloud by design -- the real-world pattern this targets isn't
# provider-specific: "8 Minutes to AWS Admin" (cloudmagazin.com, 2026) and a
# honeypot that caught attackers dumping 15,000 stolen credentials into an
# open S3 bucket (SecurityWeek) both turn on long-lived keys sitting in a
# PUBLIC bucket, not a vuln in the storage service itself. Azure/GCP
# equivalents (connection strings, service-account JSON) are just as real.
_CRED_PATTERNS = re.compile(
    r"(?i)AKIA[0-9A-Z]{16}|aws_secret_access_key\s*[:=]|"
    r"AccountKey=[A-Za-z0-9+/=]{20,}|DefaultEndpointsProtocol=|"
    r'"type"\s*:\s*"service_account"|private_key_id|'
    r"client_secret\s*[:=]|-----BEGIN\s+(RSA|OPENSSH|PGP|PRIVATE)"
)

# Common Azure Blob container names to probe once the storage ACCOUNT exists
# but account-level listing (?comp=list) is denied -- the gap this file used
# to have: it only ever tested the account root, never individual
# containers, so a locked-down account with one wide-open container (the
# realistic Azure Blob misconfiguration, not an open account) was invisible.
COMMON_CONTAINERS = [
    "$web", "public", "data", "files", "backup", "backups", "uploads",
    "static", "assets", "logs", "config", "images", "media", "documents",
    "exports", "container1", "test", "dev", "prod", "staging",
]


from _common import log, success, vuln, warn
def http_get(url, timeout=5, max_bytes=32768):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(max_bytes).decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read(8192).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body, dict(e.headers or {})
    except Exception:
        return 0, "", {}


def generate_bucket_names(domain, company_name=None):
    """Generate potential bucket names from domain and company name."""
    base = domain.replace(".", "-")
    parts = domain.split(".")
    name = parts[0]  # e.g., "example" from "example.com"

    names = set()

    bases = [name, base]
    if company_name:
        bases.append(company_name.lower().replace(" ", "-"))
        bases.append(company_name.lower().replace(" ", ""))

    for b in bases:
        # Direct names
        names.add(b)

        # Environment suffixes
        for env in ["dev", "staging", "stage", "prod", "production", "test", "qa", "uat", "demo", "sandbox"]:
            names.add(f"{b}-{env}")
            names.add(f"{env}-{b}")

        # Purpose suffixes
        for purpose in ["assets", "uploads", "media", "images", "static", "files",
                        "backup", "backups", "data", "db", "database", "logs",
                        "reports", "docs", "documents", "exports", "imports",
                        "public", "private", "internal", "web", "app", "api",
                        "config", "secrets", "keys", "certs", "ssl",
                        "builds", "artifacts", "deploy", "release"]:
            names.add(f"{b}-{purpose}")
            names.add(f"{purpose}-{b}")

        # Numbered variants
        for i in range(1, 4):
            names.add(f"{b}{i}")
            names.add(f"{b}-{i}")

    return sorted(names)


def _scan_sample_files_for_credentials(sample_urls):
    """Fetch a handful of the listed files and regex-scan them for
    credential-shaped strings. This is the concrete, cross-cloud shape of
    the real pattern behind 'Effective in 8 Minutes: AWS Admin via an Open
    S3 Bucket' and SecurityWeek's honeypot that caught attackers dumping
    15,000 stolen credentials into an open bucket: the storage service
    itself isn't the vuln, a secret sitting in it is. Bounded to a handful
    of small files so this stays fast and non-destructive (read-only)."""
    hits = []
    for url in sample_urls[:5]:
        status, body, _ = http_get(url, timeout=4, max_bytes=16384)
        if status == 200 and _CRED_PATTERNS.search(body):
            hits.append(url)
    return hits


def _claimable_note(provider):
    return (
        f"Name does not currently exist on {provider} and is available to "
        f"register. If anything on the target (a DNS CNAME, a hardcoded "
        f"asset URL in JS, a CI/CD config, a Terraform/CloudFormation "
        f"template) still references this exact name, an attacker who "
        f"registers it first can intercept logs, backups, or served assets "
        f"-- this is the 'bucket namespace hijacking' class Unit 42 "
        f"documented across AWS, GCS, and Azure in 2026 (AWS partially "
        f"mitigated it in March 2026 with opt-in regional namespaces; GCS "
        f"and Azure have no announced fix). Worth checking for a dangling "
        f"reference before dismissing this as a non-finding."
    )


def check_s3_bucket(name):
    """Check if an S3 bucket exists and its permissions."""
    findings = {"name": name, "provider": "aws_s3", "exists": False}

    url = f"https://{name}.s3.amazonaws.com/"
    status, body, headers = http_get(url)

    # A bucket that exists but lives in a non-default region 301s with the
    # real region in a response header/body -- treating that as "doesn't
    # exist" (the bug this used to have) silently drops every
    # non-us-east-1 bucket, which is most of them.
    region_hint = headers.get("x-amz-bucket-region") or (
        re.search(r"<Region>([^<]+)</Region>", body).group(1) if "<Region>" in body else None
    )
    if status in (301, 400) and region_hint:
        url = f"https://{name}.s3.{region_hint}.amazonaws.com/"
        status, body, headers = http_get(url)

    if status == 200:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
        if "<Key>" in body:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
            findings["files_visible"] = len(keys)
            findings["sample_files"] = keys[:10]
            cred_hits = _scan_sample_files_for_credentials(
                [f"{url}{urllib.parse.quote(k)}" for k in keys[:5]])
            if cred_hits:
                findings["credential_exposure"] = True
                findings["credential_bearing_files"] = cred_hits
        return findings
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status
        return findings
    elif status == 404 or "NoSuchBucket" in body:
        findings["claimable"] = True
        findings["claimable_note"] = _claimable_note("AWS S3")
        return findings

    return findings


def check_gcs_bucket(name):
    """Check if a GCS bucket exists and its permissions."""
    findings = {"name": name, "provider": "gcp_gcs", "exists": False}

    url = f"https://storage.googleapis.com/{name}/"
    status, body, _ = http_get(url)

    # The XML listing endpoint alone misses buckets where the OWNER meant
    # public access (a static site, a CDN origin) but ListBucket is off --
    # the GCS JSON API's IAM policy exposes allUsers/allAuthenticatedUsers
    # bindings independently of whether object listing works, which is the
    # realistic GCS misconfiguration (public read, not public list).
    iam_url = f"https://storage.googleapis.com/storage/v1/b/{name}/iam/testPermissions?permissions=storage.objects.list"
    iam_status, iam_body, _ = http_get(iam_url)
    public_via_iam = iam_status == 200 and '"storage.objects.list"' in iam_body

    if status == 200 or public_via_iam:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
        if "<Key>" in body:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
            findings["files_visible"] = len(keys)
            findings["sample_files"] = keys[:10]
            cred_hits = _scan_sample_files_for_credentials(
                [f"{url}{urllib.parse.quote(k)}" for k in keys[:5]])
            if cred_hits:
                findings["credential_exposure"] = True
                findings["credential_bearing_files"] = cred_hits
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status
    elif status == 404 or "NoSuchBucket" in body or "doesn't exist" in body.lower():
        findings["claimable"] = True
        findings["claimable_note"] = _claimable_note("GCS")

    return findings


def check_azure_blob(name):
    """Check if an Azure Storage account exists, and -- the gap this used
    to have -- probe individual containers when the account itself is
    locked down. A locked account with one wide-open container is the
    realistic Azure Blob misconfiguration; testing only ?comp=list at the
    account root misses it entirely."""
    findings = {"name": name, "provider": "azure_blob", "exists": False}

    account_url = f"https://{name}.blob.core.windows.net/?comp=list"
    status, body, _ = http_get(account_url)

    if status == 200:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
        return findings
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status
        # Account exists but is locked -- check individual containers.
        open_containers = []
        for container in COMMON_CONTAINERS:
            c_url = f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
            c_status, c_body, _ = http_get(c_url, timeout=4)
            if c_status == 200:
                blob_names = re.findall(r"<Name>([^<]+)</Name>", c_body)
                open_containers.append({
                    "container": container,
                    "files_visible": len(blob_names),
                    "sample_files": blob_names[:10],
                })
                if blob_names:
                    cred_hits = _scan_sample_files_for_credentials([
                        f"https://{name}.blob.core.windows.net/{container}/{urllib.parse.quote(b)}"
                        for b in blob_names[:5]
                    ])
                    if cred_hits:
                        open_containers[-1]["credential_exposure"] = True
                        open_containers[-1]["credential_bearing_files"] = cred_hits
        if open_containers:
            findings["public_list"] = True  # at least one container is wide open
            findings["open_containers"] = open_containers
        return findings
    elif status == 404:
        findings["claimable"] = True
        findings["claimable_note"] = _claimable_note("Azure Storage")

    return findings


def check_bucket(name, providers, is_reference=False):
    """Check a bucket name across specified providers.

    `is_reference` marks names that came from an actual discovered artifact
    (a CNAME, a hardcoded asset URL, a CI/CD config) rather than blind
    brute-force guessing -- only THOSE names get their `claimable` result
    surfaced as a finding. Reporting "this guessed name happens to be
    unclaimed" for every one of the hundreds of brute-forced candidates
    would be true of almost any string and tells an operator nothing; it's
    only a real bucket-namespace-hijacking lead when something on the
    target still points at that exact name."""
    results = []

    if "aws" in providers or "all" in providers:
        r = check_s3_bucket(name)
        if r["exists"] or (is_reference and r.get("claimable")):
            results.append(r)

    if "gcp" in providers or "all" in providers:
        r = check_gcs_bucket(name)
        if r["exists"] or (is_reference and r.get("claimable")):
            results.append(r)

    if "azure" in providers or "all" in providers:
        r = check_azure_blob(name)
        if r["exists"] or (is_reference and r.get("claimable")):
            results.append(r)

    return results


def main():
    parser = argparse.ArgumentParser(description="Bucket Enumerator - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--company", "-c", help="Company name for additional patterns")
    parser.add_argument("--provider", default="all", choices=["aws", "gcp", "azure", "all"])
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--custom-names", help="File with additional bucket names to try")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    log(f"Starting bucket enumeration for: {domain}")

    # Generate names
    names = generate_bucket_names(domain, args.company)
    reference_names = set()

    if args.custom_names:
        custom = Path(args.custom_names).read_text().strip().split("\n")
        custom = [n.strip() for n in custom if n.strip()]
        # Names from --custom-names are presumed to be REAL discovered
        # references (a CNAME target, a hardcoded asset URL, a CI config
        # value) rather than guesses -- that's what makes a `claimable`
        # result on one of them an actual bucket-namespace-hijacking lead.
        reference_names.update(custom)
        names.extend(custom)
        names = sorted(set(names))

    log(f"Testing {len(names)} bucket names against {args.provider} provider(s)...")

    all_found = []
    providers = [args.provider]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_bucket, name, providers, name in reference_names): name
            for name in names
        }
        for future in concurrent.futures.as_completed(futures):
            results = future.result()
            for r in results:
                all_found.append(r)
                if r.get("credential_exposure") or any(
                    c.get("credential_exposure") for c in r.get("open_containers", [])
                ):
                    vuln(f"CREDENTIAL EXPOSURE in public bucket: {r['name']} ({r['provider']})")
                elif r.get("public_list"):
                    vuln(f"PUBLIC BUCKET: {r['name']} ({r['provider']}) - Listing allowed!")
                elif r.get("claimable"):
                    vuln(f"CLAIMABLE/UNCLAIMED bucket referenced by target: {r['name']} ({r['provider']})")
                else:
                    success(f"Bucket exists: {r['name']} ({r['provider']}) - Access denied (good)")

    # Categorize
    public_buckets = [b for b in all_found if b.get("public_list")]
    private_buckets = [b for b in all_found if not b.get("public_list") and not b.get("claimable")]
    claimable_buckets = [b for b in all_found if b.get("claimable")]
    credential_exposed = [
        b for b in all_found
        if b.get("credential_exposure") or any(c.get("credential_exposure") for c in b.get("open_containers", []))
    ]

    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "bucket_enumeration",
            "tool": "cloud-pivot-finder by orizon.one",
            "names_tested": len(names),
        },
        "stats": {
            "total_found": len(all_found),
            "public_listing": len(public_buckets),
            "private": len(private_buckets),
            "claimable": len(claimable_buckets),
            "credential_exposure": len(credential_exposed),
        },
        "public_buckets": public_buckets,
        "private_buckets": private_buckets,
        "claimable_buckets": claimable_buckets,
        "credential_exposed_buckets": credential_exposed,
    }

    output_path = args.output or f"buckets_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  BUCKET ENUMERATION SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  Names tested    : {len(names)}")
    print(f"  Buckets found   : {len(all_found)}")
    print(f"  PUBLIC (listing): {len(public_buckets)}")
    print(f"  Private         : {len(private_buckets)}")
    if public_buckets:
        print(f"\n  PUBLIC BUCKETS (CRITICAL):")
        for b in public_buckets:
            files = b.get("files_visible", "?")
            print(f"    {b['name']} ({b['provider']}) - {files} files visible")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
