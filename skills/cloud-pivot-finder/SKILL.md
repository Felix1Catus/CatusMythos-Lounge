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

Check every subdomain's CNAME for dangling references. Fingerprints were
refreshed against 2024-2026 can-i-take-over-xyz/nuclei-templates data
(`research_notes/Cloud pivot finder depth techniques/current_takeover_fingerprints.md`)
and now distinguish three states rather than a single vulnerable/not:

- **Confirmed-current-vulnerable**: AWS S3 (excluding 2026 `-an`
  account-regional buckets, which can't be re-claimed cross-account),
  AWS Elastic Beanstalk, Azure (checked via NXDOMAIN across a broad suffix
  list — `cloudapp.net`, `azurewebsites.net`, `blob.core.windows.net`,
  `azure-api.net`, `trafficmanager.net`, and 10 more — since NXDOMAIN, not
  an HTTP body fingerprint, is Azure's reliable confirmation signal), plus
  new entries not in the original 2017-era list: Wasabi, Ngrok, Surge.sh,
  Pantheon, Readme.io, Strikingly, Ghost, Help Scout, WordPress.com.
- **Fixed / not vulnerable (negative fingerprints)**: AWS CloudFront, AWS
  ELB, GCP Cloud Storage, GCP Firebase, Fastly, Zendesk. **This fixes a
  real bug**: these five services' own "not found" suppression strings
  were previously scored as a *positive* takeover match, producing a
  false positive on every one of them.
- **Edge case — needs manual confirmation**: Heroku, Shopify, GitHub
  Pages, Netlify, Vercel, Bitbucket. These platforms now require
  TXT-record domain verification, but no official advisory confirms a
  platform-wide fix and live 2024-2025 bug-bounty reports continue — a
  bare fingerprint match is flagged (`edge_case: true`) rather than
  reported as a confirmed finding.

For each dangling CNAME:
1. Verify the target is actually unclaimed (and not excluded, e.g. an
   AWS `-an` namespace bucket)
2. Determine the takeover method
3. Assess impact (cookie scope, same-origin policy implications) —
   downgrade confirmed-but-edge-case findings until manually verified
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

**Depth notes added this pass**
(`research_notes/Cloud pivot finder depth techniques/imdsv2_bypass_edge_cases.md`
and `container_orchestrator_metadata.md`) — no disclosed 2024-2026 case has
actually defeated EC2 IMDSv2's token mechanism itself, so the reference
table and pivot narrative now weight the surfaces that research found
real, current issues on instead:

- **AWS ECS/Fargate task metadata (v4, and the still-working-but-no-longer-
  maintained v2)**: reachable at `169.254.170.2`, with **no token/PUT step
  at all** — reachability alone yields task-role credentials. Hop-limit=1
  does *not* block this on `awsvpc`/`host` network mode (only `bridge`
  mode adds the extra hop); AWS's actual fix is `ECS_AWSVPC_BLOCK_IMDS=true`
  in `/etc/ecs/ecs.config`.
- **EKS Pod Identity** is architecturally stronger than plain ECS — it
  requires an `Authorization` token read from a local file
  (`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`), unlike the token-free ECS path.
- **"ECScape"** (Sweet Security, Black Hat USA 2025, no CVE — AWS calls it
  a design consideration): a container that can already reach host-level
  IMDS and whose instance role holds `ecs:DiscoverPollEndpoint`/`ecs:Poll`
  can impersonate the ECS agent and harvest *every other task's*
  credentials on the same host, not just its own.
- **Kubernetes kubelet** unauthenticated read-only port 10255 is
  deprecated but still found (CIS Benchmark 4.2.4); **CVE-2025-0426** is a
  node-disk-fill DoS via that same endpoint in kubelet 1.30.0-1.30.9 /
  1.31.0-1.31.5 / 1.32.0-1.32.1. `--anonymous-auth` still defaults to
  `true` on the main API server.
- **GKE/EKS pod-to-node-metadata**: Google now labels pod-level metadata
  concealment (`--workload-metadata=SECURE`) Beta/deprecated and directs
  operators to Workload Identity Federation instead; EKS's VPC-CNI
  NetworkPolicy block is not on by default and only covers Amazon Linux
  nodes. Legacy GCP `v0.1`/`v1beta1` metadata endpoints were fully shut
  down 2020-09-30 and should not respond.
- **DNS-rebinding TOCTOU** (clearest recent example: **CVE-2026-27127**,
  Craft CMS): an SSRF filter that re-resolves a hostname per-request
  instead of pinning the validated IP can be bypassed with a short-TTL
  domain that answers safely on the check and flips to the metadata IP at
  connect time. Noted as a manual technique in the pivot narrative — it
  needs attacker-controlled DNS infrastructure, which this external-recon
  tool doesn't provide.

These are documented in the pivot-path narrative (`depth_notes` field) and
the metadata-endpoint reference table rather than actively probed: the
container/orchestrator surfaces require either a confirmed SSRF primitive
reaching deep into the target's network or an existing foothold inside a
pod/container, which is outside this external-recon tool's position.

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
