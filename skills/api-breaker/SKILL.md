---
name: api-breaker
description: Automated API security testing starting from domains. Discovers REST, GraphQL, and SOAP APIs, reconstructs schemas, and tests for BOLA/IDOR, BFLA, mass assignment, JWT attacks, rate limiting bypass, and business logic flaws. Use when user asks to "test API security", "break API", "find API vulnerabilities", "test GraphQL", "test JWT", "API pentest", or provides domains with API endpoints. For authorized testing only.
metadata:
  author: orizon.one
  version: 1.0.0
---

# API Breaker

Intelligent API security testing. Discovers, maps, and exploits API vulnerabilities.

## Important

CRITICAL: Only test APIs you have explicit authorization to test.

## Instructions

### Step 1: API Discovery

```bash
python3 scripts/api_discovery.py --domain {target_domain}
```

Discovery methods:
1. **Path fuzzing**: /api/, /v1/, /v2/, /graphql, /rest/, /swagger.json, /openapi.json, /api-docs
2. **JavaScript analysis**: Fetch up to 20 same-origin script files from the target page and parse them for hardcoded API endpoints, base URLs, fetch/axios calls; off-origin scripts are skipped
3. **Wayback Machine**: Historical API endpoints that may still be active
4. **Common patterns**: /{resource}s, /{resource}/{id}, /{resource}/{id}/{subresource}
5. **GraphQL detection**: /graphql, /graphiql, /playground, /api/graphql
6. **Documentation endpoints**: Swagger, OpenAPI, WADL, WSDL

For each discovered API:
- Record base URL, authentication method, content type
- Detect API standard (REST, GraphQL, gRPC-web, SOAP)

`scripts/api_discovery.py` also runs a **legacy/deprecated API version
discovery** pass (research_notes/API breaker depth techniques/
rate_limit_versioning.md — real incidents: Optus's ~10M-record breach via
an undocumented leftover endpoint, St. Luke's Health System's deprecated
SOAP API exposing ~450K records for 6 months after the REST service was
patched): generates sibling candidate paths by substituting version/date
tokens (`v2`→`v1`/`v0`/`v3`/`beta`/`alpha`/`old`/`legacy`/`internal`/
`deprecated`; date tokens decremented), fingerprints `Sunset`/
`Deprecation`/`Link rel="deprecation"` response headers on every probed
endpoint, and enumerates the Wayback Machine's CDX API for additional
historically-crawled candidate paths re-probed against the **live** host
only. Finding a candidate alone is low-severity (`legacy_api_version_exists`);
the high-severity finding (`legacy_api_version_bypass`) requires the
actual exploit-confirmation step — a security control (auth requirement,
or a confirmed rate limit) demonstrably enforced on the current version
but absent on the candidate, bounded to 5 differential checks per run to
cap request volume.

### Step 2: Schema Reconstruction

```bash
python3 scripts/schema_builder.py --api-base {api_url}
```

When using `--input`, also pass an explicit trusted `--api-base`. Imported
metadata does not choose the target; off-origin endpoint URLs are skipped
before authenticated probes are sent. Discovery and schema reconstruction
still actively send the documented HTTP and GraphQL probes to that origin.

Even without documentation:
1. Send requests with varying parameters and observe responses
2. Analyze error messages for expected field names/types
3. Use OPTIONS/HEAD to discover allowed methods
4. Test content negotiation (JSON, XML, form-encoded)
5. GraphQL: Send introspection query to get full schema

Output: Reconstructed API schema in OpenAPI format.

**GraphQL gets a full depth pass beyond basic introspection**
(research_notes/API breaker depth techniques/graphql_techniques.md):
- **Introspection-disabled fallback chain** — when the standard query is
  blocked, retries transport variants (GET/form-urlencoded), a
  regex-evasion variant (whitespace/comment right after `__schema`
  defeats a naive literal-substring blocklist), and alternate GraphQL
  paths, before falling back to blind recovery: Clairvoyance-style
  field-suggestion harvesting ("Did you mean" errors confirm real field
  names even with introspection off), then a last-resort binary-oracle
  brute force. A bare `node()`/`nodes()` root field is always probed
  separately — a common Relay-style direct-object-access primitive
  OWASP calls out independent of the rest of the schema.
- **Depth/complexity DoS probe** — escalates nesting depth against a
  self-referencing field (from the reconstructed schema, or a fallback
  name-pair list) with a hard client timeout; classifies a depth-limit
  validation error (limiting present), non-linear latency growth with no
  error (a cost-growth candidate), or a timeout/5xx (an impact candidate,
  not proof of DoS). A fast transport failure is inconclusive. The bounded
  ladder still sends the active depth payloads by default. It also runs a
  fragment-cycle probe (two named fragments referencing each other — a
  spec-compliant validator must reject this) and, once a depth limiter is
  confirmed, a `__schema`-named-fragment retry for the graphql-armor-class
  `ignoreIntrospection` bypass (GHSA-hmfr-rx46-4jx2). Acceptance signals are
  candidates until resource impact is established.
- **Nested-field authorization bypass** — differential test: validate a
  candidate field set via a "self" field (`me`/`viewer`) under the
  caller's own session, then re-query the identical field set via a
  sibling by-ID field with a *different* ID using the *same* session. A
  field populated via the sibling but null via self (especially
  email/role/permissions-class fields) is an unverified candidate: target
  ID ownership and intended visibility must be established before confirming
  an authz issue. Schema names are validated and operator-supplied candidate
  IDs are bounded and JSON-quoted. The GraphQL CSRF probe
  submits a discovered mutation over GET and form-POST only when both
  `--cookie` and an operator-approved `--csrf-test-id` are supplied; these
  requests can change that object. Results are candidates until browser cookie
  policy and persisted state are verified. The separate mutation-BOLA write
  probe remains **opt-in-only** with `--allow-mutation-write` (off by default;
  it actively sends the selected write when enabled; an accepted response is
  a candidate until a controlled read-back confirms persisted unauthorized
  impact). `--delay` is bounded to 0–60 seconds and `--candidate-ids` accepts
  at most 50 IDs of 128 characters each.
- **Engine fingerprinting + version-aware CVE hypotheses** — best-effort
  Apollo/graphql-java/Hasura detection from headers/error-shape, then (if
  `--engine-version` is supplied) a static, **range-aware** table lookup
  for CVE-2025-31496 (apollo-compiler), CVE-2024-40094 (graphql-java —
  three independently-patched branches), and CVE-2026-54698 (Hasura —
  two disjoint patched ranges). Every hit is a presumptive hypothesis to
  confirm, never a black-box-confirmed CVE match.

### Step 3: Authentication Analysis

```bash
python3 scripts/auth_analyzer.py --api-base {api_url}
```

Detect and test:
- **JWT tokens**: Decode, test none algorithm, key confusion (RS256->HS256,
  plus RS256<->PS256 via pure header relabeling), weak secrets, claim
  tampering. Also tests edge cases beyond the classics
  (research_notes/API breaker depth techniques/jwt_edge_cases.md):
  **`kid` header injection** (path traversal to a predictable-content file,
  UNION-based SQLi against the key lookup, and a time-based SQLi probe
  independent of forgery success); **`crit` header non-enforcement**
  (RFC 7515 §4.1.11 — a differential test against the `none`-alg bypass,
  only reported when there's something real to compare against);
  **missing `aud`/`iss` claims** (zero new requests — lets a token minted
  for one service be accepted by a different one sharing the same signing
  key); and a static **CVE fingerprint table** for 14 named 2024-2026 JWT
  library CVEs, checked via `--library`/`--library-version` when the
  library is known from recon/error leakage. `jwk`-header injection and
  real-key JWKS extraction (building/signing with actual RSA key
  material) were designed and verified but deliberately not shipped —
  this skill is stdlib-only by design, and both need the `cryptography`
  package; see the research notes' own "jwk header injection" section if
  that tradeoff is revisited.
- **API keys**: Test in different positions (header, query, body), check for key leakage
- **OAuth flows**: Test for open redirect in callback, token leakage, PKCE bypass
- **Session tokens**: Predictability, fixation, rotation on privilege change
- **No auth**: Endpoints accessible without any authentication

Authentication analysis filters imported endpoint URLs against the supplied
API base origin before sending a token or cookie. When using `--input`, pass
`--api-base` explicitly; imported metadata never chooses the target.
Off-origin endpoints are skipped.

The JWT and API-key probes actively send their payloads by default. Before
classifying a 2xx response as accepted credentials, the analyzer sends a
malformed-token or unauthenticated control to the same endpoint; when that
control is also accepted, results stay INFO candidates instead of being
reported as confirmed bypasses. No-auth data remains a candidate until its
sensitivity and intended access are established. JWT header and payload values
written to the JSON result redact common credential and personal-data claim
keys. The inter-request delay is limited to 0-60 seconds, and the timing
injection sleep is limited to 1-10 seconds.

### Step 4: Authorization Testing (BOLA/BFLA)

```bash
python3 scripts/authz_tester.py --input {schema_file} --api-base {api_url} --token {user_a_token} --token-b {user_b_token}
```

**BOLA (Broken Object-Level Authorization):**
For every endpoint with an object ID:
1. Create resource as User A, note the ID
2. Access that ID as User B (different token)
3. If User B can read/modify/delete User A's resource = BOLA

**BFLA (Broken Function-Level Authorization):**
1. Map endpoints by intended role (user vs admin)
2. Test admin endpoints with regular user token
3. Test all HTTP methods (GET, POST, PUT, DELETE, PATCH) on each endpoint

`authz_tester.py` runs read-only GET probes by default. POST/PUT/PATCH/DELETE
checks, including method-override probes, require the explicit
`--allow-mutation-write` option because they can change or delete target data.
Supply `--api-base` explicitly as the trusted target origin. Imported file
metadata is not used to select a target. Endpoint URLs are restricted to the
exact scheme, host, and effective port in `--api-base`; off-origin entries are
skipped before credentials are sent.

For cross-user BOLA checks, `--cookie` belongs to User A and `--cookie-b`
belongs to User B. If `--cookie-b` is omitted, User B's requests do not inherit
User A's cookie; other shared custom headers still apply to both. The
inter-request `--delay` is bounded to a finite 0–60 seconds.

These are active requests to the authorized API, not passive observations.
OpenAPI-style object path parameters are replaced with a bounded seed ID
before the initial object read. A successful HTTP status alone is only a
candidate: a BOLA GET is confirmed only when the response contains the exact
object ID tested; successful mutations remain candidates until a controlled
read-back verifies persisted impact. BFLA status and method-override responses
are candidates until the returned data or action demonstrates privileged
impact. Review candidate evidence before treating it as a confirmed finding.

**N-role authorization matrix.** `--token`/`--token-b` test exactly two
identities. Real RBAC bugs often only show up between a *specific* pair of
roles in a larger hierarchy, not the two you happened to provision -- use
repeatable `--role NAME:TOKEN` instead, declared in ascending privilege order
(lowest first):

```bash
python3 scripts/authz_tester.py --input {schema_file} --api-base {api_url} \
  --role anonymous: --role viewer:{viewer_token} --role editor:{editor_token} --role admin:{admin_token}
```

An empty `TOKEN` (`anonymous:`) declares an explicit anonymous role at that
position instead of relying on a separate no-auth check. Needs at least 2
roles; mutually exclusive with `--token`/`--token-b`. For BOLA, every role's
own objects are cross-tested against every other role (not just a fixed
pair) -- a lower-ranked role reading a higher-ranked role's object is flagged
at `critical`. For BFLA, only a role ranked *below* the highest-declared role
succeeding at an admin-pattern endpoint is reported; the top role reaching
its own admin surface is expected and not flagged -- the single-token mode
has no way to make this distinction, since it doesn't know whether its one
token IS the admin. `--role-cookie NAME:COOKIE` supplies a session cookie for
one named role; a role never inherits another role's cookie.

### Step 5: Mass Assignment Testing

```bash
python3 scripts/mass_assignment.py --input {schema_file} --api-base {api_url} --token {token} --allow-mutation-write
```

This active probe can create or modify records, so the explicit write flag is
required. An echoed field is reported as an unverified candidate until a
follow-up read confirms the persisted value and its security impact.

For each creation/update endpoint:
1. Send normal request, note accepted fields
2. Add extra fields: `role`, `isAdmin`, `price`, `discount`, `verified`, `approved`, `permissions`
3. Check if extra fields are processed
4. Test with nested objects: `{"user": {"role": "admin"}}`

### Step 6: Rate Limiting and Resource Testing

```bash
python3 scripts/rate_limiter.py --api-base {api_url}
```

Use the same explicit `--api-base` with `--input`; imported URLs are scoped to
that exact origin before credentials or rate-limit probes are sent. The
default is 120 requests per endpoint; `--count` accepts 1–1000. This is active
traffic, including burst, path/method variation, and GraphQL batching probes.

Test:
- Send 100+ rapid requests to each endpoint
- Check for 429 responses or rate limit headers
- If rate limited: test bypass via IP rotation headers (X-Forwarded-For, X-Real-IP,
  plus `X-Host`/`X-Forwared-Host` — the literal misspelling is a real-world
  broken-but-still-parsed header name)
- Test resource-intensive endpoints for DoS potential (large pagination, deep queries)
- GraphQL: Test query batching, nested query depth, alias-based multiplication

`scripts/rate_limiter.py` also runs three depth passes (research_notes/API
breaker depth techniques/rate_limit_versioning.md):
- **Race-condition baseline-vs-burst comparator** — runs a request
  sequence sequentially first (recording the success count), then fires
  identical requests as a concurrent thread-pool burst; more
  successes in the burst is only a race candidate because response
  counts do not prove that a single-use action persisted twice. Confirm
  state with a controlled read-back before reporting impact (James
  Kettle's "Smashing the State Machine" class; same broad class as the Stripe fee-discount race —
  $600K exposure from a single $5K-bounty report). Auto-targeted at
  endpoints whose URL suggests a limited-use/financial-impact resource
  (`coupon`/`discount`/`invite`/`redeem`/`gift_card`/`credit`/`balance`/
  `voucher`/`offer`) rather than racing every endpoint blindly. A true
  HTTP/2 single-packet attack needs raw frame control this stdlib-only
  skill deliberately doesn't depend on — the thread-pool burst is the
  realistic, portable ceiling, and will miss narrower race windows a
  single-packet attack could still catch.
- **Path/method/casing mutation test** — for any endpoint already
  confirmed rate-limited, re-confirms the baseline 429 still fires, then
  bursts trailing-slash/doubled-slash/case/method-swap/junk-query-param
  variants and records a candidate when a mutation's response matches
  the *shape* (status + body-length band) of a pre-limit success. This
  does not prove the same application operation ran; review the target's
  response and confirm behavior before reporting. Direct reproduction of
  CVE-2023-38507 (Strapi, path case/slash bypassed its admin-login rate
  limiter) and CVE-2025-71399 (Better Auth, slash-padding bypassed a
  path-based rate limit).
- **GraphQL batching/aliasing** — sends a bounded baseline of at most 60
  side-effect-free `__typename` operations. Only a clean GraphQL result
  followed by 429 establishes a differential; the tool then sends an
  array and an alias query, each with at most 110 operations, and checks
  every returned result. Without a baseline 429, accepted batching is
  recorded only as an INFO candidate. These probes do not execute login,
  OTP, password-reset, or other sensitive resolvers, so even the
  differential is not proof of sensitive impact or backend execution
  count. Some servers deduplicate identical operations. Verify with an
  authorized, controlled test operation before assessing impact. Apply
  operation-count and query-cost limits at the GraphQL execution layer
  as well as at the HTTP edge ([OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html),
  [Checkmarx GraphQL batching research](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/)).

### Step 7: Business Logic Testing

```bash
python3 scripts/logic_tester.py --input {schema_file} --api-base {api_url} --token {token}
```

For a target with a known, authorized single-use test object and a read-only
same-origin state endpoint, add
`--race-state-url {state_url} --race-state-json-pointer /data/count`. The
pointer should identify a finite numeric value expected to change once for the
sequential control action. The script compares that one-request control with
the concurrent burst and only reports an excess state-change candidate when
the selected counter changes more than it did for the control. It does not
include the counter's raw value in findings. Choosing this mode sends one
additional sequential mutation per race payload; use disposable test data.
Choose a read-only GET route deliberately: HTTP GET is not guaranteed to be
side-effect-free.

`--race-request-budget` caps all race payload, sequential-control, and
read-back requests across the run (default and maximum: 840). The existing
three race payload cases and ten-request concurrent burst remain active by
default. If no comparable state baseline is available, multiple 2xx responses
remain INFO candidates only. The thread-pool burst is concurrent but does not
provide HTTP/2 single-packet synchronization; a negative result does not rule
out narrower timing windows. See
`research_notes/API breaker depth techniques/business_logic_races.md`.

`logic_tester.py` requires an explicit trusted `--api-base` and skips imported
off-origin endpoints. It actively sends price, quantity, privilege, coupon,
negative-amount, and concurrent race payloads using POST/PUT/PATCH. Use only
with explicit authorization and target-approved test accounts/data; the
script does not add a second write opt-in, so these probes run when selected.
Response echoes and successful negative-value requests remain low-confidence
candidates. Coupon-stacking candidates now require a JSON response with at
least two entries in an explicit
applied-coupon/discount collection; a generic success message or echo of the
submitted `coupons` field is not stack evidence. Verify the calculated total
and persisted state against a safe baseline before reporting impact. This
follows the business-specific impact model in
[OWASP API6](https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

Context-aware tests:
- **E-commerce**: Price manipulation, quantity overflow, currency confusion, coupon stacking
- **Financial**: Double spending via race conditions, negative amount transfer
- **User management**: Self-privilege escalation, email verification bypass, 2FA bypass
- **File handling**: Path traversal in file names, SSRF in URL fields, XXE in XML endpoints

### Step 8: Report Generation

```bash
python3 scripts/api_report.py --input {findings_dir}
```

Per-finding output:
- Vulnerability type and OWASP API Security Top 10 mapping
- Affected endpoint and method
- Request/response showing the issue
- curl command for reproduction
- Impact assessment
- Remediation recommendation

## Error Handling

### No API Documentation Found
If no Swagger/OpenAPI exists:
1. Schema reconstruction from observed behavior (Step 2)
2. Use error messages as hints for field discovery
3. Inform user of reduced coverage without docs

### Authentication Required
1. Ask user for API token/credentials
2. Support: Bearer token, API key, Basic auth, OAuth token
3. Usage: `--token "Bearer abc123"` or `--api-key "key123"`

### GraphQL Introspection Disabled
If introspection is blocked:
1. Use field suggestion: send partial queries, use error messages to discover fields
2. Use clairvoyance-style wordlist-based field discovery
3. Check for GraphQL Voyager/Playground on alternative paths

## Examples

### Example 1: Full API Assessment
User says: "Test the API at api.example.com"

Actions:
1. Discover all endpoints
2. Reconstruct schema
3. Test auth, BOLA, BFLA, mass assignment
4. Test rate limiting
5. Generate comprehensive report

### Example 2: GraphQL Security Audit
User says: "Audit the GraphQL API at example.com/graphql"

Actions:
1. Send introspection query
2. Map all queries and mutations
3. Test authorization on each mutation
4. Test query depth/complexity limits
5. Test batching attacks
6. Report findings

### Example 3: JWT Penetration Test
User says: "Test JWT security on the API"

Actions:
1. Capture JWT from auth flow
2. Decode and analyze claims
3. Test none algorithm
4. Test RS256->HS256 confusion
5. Brute-force weak secrets
6. Test claim manipulation (user ID, role, expiry)
