# Shared target knowledge — v1

`target_knowledge.py` is stdlib-only, cross-cutting infrastructure. It never
sends network requests or executes probes. SQLite transactions and a 10-second
busy timeout support independent processes sharing an engagement file. There
is no new dependency, service, or per-skill `_common.py` copy.

## Enable and query

Create an engagement directory outside source control (for example `targets/`
is already ignored). Pass `--knowledge-db <absolute SQLite path>` and
`--engagement <name>` to each supported CLI. The parent directory must exist.
Omitting `--knowledge-db` preserves the original standalone behavior and does
not import the shared module or create a database. Opting in requires the full
plugin checkout; a copied-out skill gives a clear error. There is no automatic
engagement inference, implicit global database, or environment fallback.

From the repository root, inspect fresh observations without issuing probes:

```bash
python3 scripts/target_knowledge.py --db targets/assessment/knowledge.sqlite --engagement assessment --target https://app.example.test --kind technology
python3 scripts/target_knowledge.py --db targets/assessment/knowledge.sqlite --engagement assessment --target https://app.example.test --include-expired
```

Targets must be credential-free HTTP(S) URLs. Scheme, IDNA hostname, and
effective port define an exact origin; subdomains and ports never inherit
facts. Engagement names partition records even within one database. Facts
also carry a resource path, kind, key, optional hashed request context, source,
confidence, observed-at time, and expires-at time (Unix seconds UTC). Queries
exclude expired records by default. `--include-expired` is inspection only.
The last observation of an identical key/context replaces that observation;
v1 does not maintain a historical event log. Unknown schema versions or
unreadable/corrupt databases fail explicitly instead of silently disabling
coordination or resetting state.

## Five integration points

1. `recon-dominator/scripts/tech_fingerprint.py`: publishes technologies,
   advertised component versions, and positive WAF fingerprints (1-hour TTL).
   Detection is marked `observed`, not confirmed exploitability. Empty/failed
   fingerprinting does not assert the absence of technologies or a WAF.
2. `webapp-exploit-hunter/scripts/sqli_tester.py`: queries shared recon facts
   for output context, records HTTP 401/403 access-denial and HTTP 429 signals,
   and records WAF block heuristics as hypotheses. Error-based probes reuse
   clean HTTP 2xx `no_new_error` outcomes for at most 15 minutes. Reuse requires
   identical URL/query, method, parameter, original value, all request headers,
   baseline status/body, and payload. A fresh baseline is still sent. Changed
   auth roles, baseline content, or query values invalidate reuse. Transport,
   auth, rate-limit, and server failures never become negative cache entries.
   `--knowledge-refresh` forces fresh probes and invalidates cached failures
   when a new result differs. `knowledge_reused_error_payloads` reports saved
   payload requests. No-new-error is a technique-specific observation, never
   a claim that a parameter is safe or that another probe should be skipped.
3. `vuln-chain-composer/scripts/import_findings.py`: attaches fresh same-origin
   knowledge to normalized findings without re-probing, changing severity,
   adding capabilities, or promoting evidence confidence. Payload-failure
   records are not included. Non-HTTP/host-only findings are left unenriched.
4. `cloud-pivot-finder/scripts/cloud_detector.py`: caches positive provider
   observations from CNAME, response-header, and IP-WHOIS evidence for one
   hour. It stores provider/service labels only, never resolved IP addresses.
   No-provider results are not cached. Reuse marks the result and leaves the
   IP field unknown because resolution was skipped. `--knowledge-refresh`
   deletes the exact host's prior provider observation before re-running
   detection.
5. `api-breaker/scripts/api_discovery.py`: caches a positive, sanitized
   endpoint inventory for 15 minutes, partitioned by exact origin, base path,
   engagement, and a digest of request headers. The cache omits response
   bodies, raw headers, query values, and endpoint URLs (paths are rebuilt
   against the operator-supplied base URL). A cache hit skips only repeated
   common-path and same-origin JavaScript discovery; GraphQL, OpenAPI, method,
   and legacy-version checks still run. Empty results are never cached.
   `--knowledge-refresh` deletes only that origin/base-path/auth-context
   inventory before fresh endpoint discovery.

Auth/rate observations expire after 15 minutes and store only status/path.
They do not establish the user's role, prove authentication is required, infer
a rate-limit window, or automatically change probing behavior.

## Reuse from another pipeline script

Load this shared module only when explicitly opted in, then use:

```python
store = KnowledgeStore(database_path, engagement_name)
store.observe("https://app.example.test", "technology", "verified-component",
              {"name": "example", "version": "1.2.3"},
              source="manual-version-verification", confidence="confirmed", ttl=3600)
observations = store.query("https://app.example.test", kind="technology")
```

Kinds are `technology`, `waf`, `auth`, `rate_limit`, `payload_failure`,
`cloud_provider`, and `api_inventory`.
Confidence is `observed`, `confirmed`, or `hypothesis`; provenance is retained.
Only intentionally selected non-secret metadata belongs in `observe()`.

## Data handling and limits

The integrations do not persist response bodies, raw headers, credentials,
query values, original parameter values, or payload strings. Exact request
contexts/payloads are SHA-256 digests; these are not encryption and can reveal
matches to guessed inputs. Resource paths and fingerprint metadata can still
contain sensitive engagement information. Keep the SQLite file private under
normal filesystem permissions and outside version control. Engagement names
isolate application queries; they are not a security boundary between users
who can read the same database file. Only trusted operators/processes should
write facts. There is no remote synchronization, encryption, purge/history UI,
export of secrets, or target authorization granted by the store.

Deliberately deferred: other SQLi modes and the other vulnerability testers;
a role-aware auth model;
Retry-After/reset-window modeling; active WAF auto-escalation (#6); executable
end-to-end chains (#7); business-context severity (#8); cross-origin inference;
a central decision-making orchestrator. The API inventory is endpoint
discovery metadata, not permission to skip vulnerability-specific tests; cloud
and API caches remain optional and have short TTLs. #4's N-role matrix and
these five explicit knowledge integrations are now in the main pipeline.
