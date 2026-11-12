---
name: cloud-pivot-finder
description: Maps cloud infrastructure from domains and identifies pivot paths from external to cloud internals. Detects cloud providers, enumerates S3/GCS/Azure storage, finds subdomain takeover opportunities, discovers serverless functions, CI/CD exposure, and IaC leaks. Use when user asks for "cloud security", "S3 enumeration", "subdomain takeover", "cloud recon", "bucket enumeration", "cloud pivot", or provides domains hosted on AWS/GCP/Azure. For authorized testing only.
metadata:
  author: orizon.one
  version: 1.0.0
---

# Cloud Pivot Finder

From external domains to cloud infrastructure compromise paths.

## Important

CRITICAL: Only test cloud infrastructure you have explicit authorization to test. Unauthorized access to cloud resources is a criminal offense.

## Instructions

### Step 1: Cloud Provider Detection

```bash
python scripts/cloud_detector.py --domain {target_domain}
```

Identify cloud hosting:
1. **IP range analysis**: Match IPs against AWS, GCP, Azure published IP ranges
2. **DNS analysis**: CNAME patterns (*.amazonaws.com, *.googleusercontent.com, *.azurewebsites.net)
3. **Header analysis**: Server headers, X-Amz-*, X-GUploader-*, x-ms-* headers
4. **Certificate analysis**: Issuer and SAN entries pointing to cloud services
5. **CDN detection**: CloudFront, Cloud CDN, Azure CDN distributions

Output: Map of domain -> cloud provider -> service type.

### Step 2: Storage Bucket Enumeration

```bash
python scripts/bucket_enum.py --domain {target_domain} --provider {aws|gcp|azure|all}
```

**Naming pattern brute-force:**
- {domain}, {domain}-backup, {domain}-dev, {domain}-staging
- {company}-assets, {company}-uploads, {company}-data
- {project}-{env} combinations

**Per-provider testing** (built with real depth across all three, not just a
single endpoint check per provider — see 2024-2026 incidents below):
- **S3**: Direct + region-redirect retry (a bucket outside `us-east-1`
  301s with the real region in `x-amz-bucket-region`; treating that as
  "doesn't exist" silently drops most real-world buckets).
- **GCS**: Object-listing AND the JSON API's IAM policy
  (`storage.objects.list` test for `allUsers`), since the realistic GCS
  misconfiguration is public *read* with listing off, not public listing.
- **Azure Blob**: Account-level `?comp=list` AND, when the account itself
  is locked (403), per-container enumeration against common container
  names — a locked account with one wide-open container is the realistic
  Azure misconfiguration; testing only the account root misses it.
- **Cross-provider, every accessible bucket/container**: fetch a handful
  of the listed files and regex-scan them for credential-shaped strings
  (AWS keys, Azure `AccountKey=`/connection strings, GCP service-account
  JSON, private keys). This is the actual shape of real 2025-2026
  incidents — "8 Minutes to AWS Admin" (long-lived keys in an open S3
  bucket plus an over-privileged Lambda role) and a honeypot that caught
  attackers dumping 15,000 stolen credentials into an open bucket — the
  storage service being public isn't the finding, a live secret sitting
  in it is.
- **Cross-provider, unclaimed names**: when a name from `--custom-names`
  (a REAL discovered reference — a dangling CNAME, a hardcoded asset URL,
  a CI config value — not a blind guess) doesn't exist on a provider, flag
  it as claimable. This is Unit 42's 2026 "bucket namespace hijacking"
  finding: deleted/unclaimed bucket names across AWS, GCS, *and* Azure can
  be re-registered by an attacker to intercept logs, backups, or served
  assets. Blind brute-force guesses are never reported as claimable —
  almost any string is technically unclaimed, so that signal is only real
  when something on the target still points at the exact name.

For each accessible bucket:
1. List contents (if ListBucket allowed)
2. Check for sensitive files (.env, credentials, backups, database dumps) —
   now automated by the credential scan above, not manual-only
3. Test write access (attempt to upload test file, delete immediately)
4. Check bucket policy for overly permissive configurations

### Step 3: Subdomain Takeover Detection

```bash
python scripts/takeover_scanner.py --subdomains {subdomain_list}
```

Check every subdomain's CNAME for dangling references:
- **AWS**: S3, CloudFront, Elastic Beanstalk, ELB
- **Azure**: Azure Websites, Traffic Manager, CDN, Blob
- **GCP**: Cloud Storage, App Engine, Firebase
- **Other**: Heroku, GitHub Pages, Fastly, Shopify, Zendesk, Unbounce, Surge.sh

For each dangling CNAME:
1. Verify the target is actually unclaimed
2. Determine the takeover method
3. Assess impact (cookie scope, same-origin policy implications)
4. Generate takeover PoC instructions

### Step 4: Serverless and Container Discovery

```bash
python scripts/serverless_finder.py --domain {target_domain}
```

Discover:
- **Lambda Function URLs**: {function-id}.lambda-url.{region}.on.aws
- **API Gateway**: {api-id}.execute-api.{region}.amazonaws.com
- **Cloud Functions**: {region}-{project}.cloudfunctions.net
- **Cloud Run**: *.run.app
- **Azure Functions**: {app}.azurewebsites.net/api/
- **Container registries**: ECR, GCR, ACR public images

Test each for:
- Unauthenticated access
- Error messages revealing internal details
- Excessive function output (debug mode)

### Step 5: CI/CD and IaC Exposure

```bash
python scripts/cicd_finder.py --domain {target_domain}
```

Search for:
- **Exposed CI/CD**: Jenkins, GitLab CI, GitHub Actions artifacts
- **Terraform state files**: .tfstate files on S3/GCS/HTTP
- **CloudFormation templates**: Exposed template files
- **Docker/K8s configs**: docker-compose.yml, kubernetes manifests
- **Helm charts**: values.yaml with secrets
- **Environment files**: .env files with cloud credentials

### Step 6: Cloud Metadata Pivot Paths

```bash
python scripts/metadata_paths.py --recon-data {recon_json}
```

For each web application on cloud infrastructure:
1. Identify potential SSRF vectors (URL parameters, PDF generators, webhooks)
2. Map the SSRF -> metadata -> credential chain
3. Assess what the IAM role/service account can access
4. Document the complete pivot path

### Step 7: Report Generation

```bash
python scripts/cloud_report.py --project {name}
```

Output:
1. Cloud infrastructure map
2. Accessible storage buckets with content inventory
3. Subdomain takeover opportunities
4. Serverless/container exposure
5. CI/CD and IaC exposure
6. Pivot paths from web to cloud
7. Prioritized remediation plan

## Error Handling

### Rate Limiting on Cloud APIs
1. S3 listing: Built-in exponential backoff
2. DNS resolution: Use multiple resolvers
3. If blocked: Reduce concurrency with `--threads 5`

### No Cloud Infrastructure Detected
If domain appears to be on-premise:
1. Still check for cloud storage buckets (may use S3 for backups)
2. Check for CI/CD exposure (GitHub Actions, etc.)
3. Inform user and suggest alternative approaches

## Examples

### Example 1: Full Cloud Assessment
User says: "Map the cloud infrastructure for example.com"

Actions:
1. Detect cloud providers
2. Enumerate storage buckets
3. Check for subdomain takeover
4. Find serverless endpoints
5. Check CI/CD exposure
6. Map pivot paths
7. Generate comprehensive report

### Example 2: S3 Bucket Hunt
User says: "Find S3 buckets for example.com"

Actions:
1. Generate naming patterns from domain/company name
2. Test each pattern for existence
3. Check permissions on found buckets
4. List accessible contents
5. Report findings

### Example 3: Subdomain Takeover Scan
User says: "Check for subdomain takeover on these 50 subdomains"

Actions:
1. Resolve CNAME for each subdomain
2. Check each CNAME against takeover fingerprints
3. Verify dangling references
4. Generate takeover PoC for confirmable targets
