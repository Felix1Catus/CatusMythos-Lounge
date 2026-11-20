# Assessment campaign v1

`assessment_campaign.py` provides planning, a registered core assessment runner,
bounded native adapters for an operator-authored workflow, single-origin
technology fingerprinting, anonymous API discovery, and result/coverage
evaluation. Planning and report evaluation never make network requests; `assess`
and the run commands do. An operator can review
exact scope,
roles, test order, state-change intent, cleanup, and request budget before
explicitly executing a supported step.

## Run the core assessment

Start from [`doctrine/templates/ASSESSMENT_CAMPAIGN.json`](../doctrine/templates/ASSESSMENT_CAMPAIGN.json),
edit the exact origins and test accounts, then put each credential in the named
environment variable. The profile executes only listed, registered steps in
dependency order; it does not invent scope or run unsupported tools. It writes
per-tool artifacts in a sibling `_artifacts` directory and a summary that
contains status/counts, not credential values or response bodies:

```powershell
python scripts/assessment_campaign.py assess `
  --manifest targets/assessment/campaign.json `
  --state-db targets/assessment/campaign.sqlite `
  --campaign-id assessment-2026-11 `
  --output targets/assessment/assessment.json
```

The default is OS network isolation. `--process-only` explicitly selects the
weaker process-level gate and is intended for local loopback fixtures. A
required step that is blocked, throttled, over budget, missing its input
artifact, or fails makes the assessment `incomplete` and returns a nonzero
status; this never means the target is safe. API authz uses `--role-env` so
tokens come from environment variables rather than argv. Browser checks use
their per-step request cap plus the campaign ledger and keep form writes off by
default. On Windows, the managed Playwright browser uses the browser auditor's
request-routing sandbox and is labeled `browser_context_route` in the summary;
other tools still use the OS namespace unless `--process-only` is selected.

## Plan a campaign

Create a JSON manifest with:

- `schema_version: 1` and an engagement label.
- Optional `assessment_profile: "core_web_api_v1"` enables the release-gated
  core web/API coverage contract. Each target must declare anonymous plus at
  least two credentialed roles; the profile requires crawl, exposure, API
  inventory, SQLi, XSS, LFI, SSRF, browser, and authorization stages, with anonymous
  and authenticated coverage for crawler/injection/browser stages. Missing
  roles, browser dependencies, discovery artifacts, or credentials produce
  `blocked`/`incomplete` results and a nonzero exit, never a clean result.
- `scope.origins`: exact credential-free HTTP(S) origins.
- `scope.request_budget`: sum of the maximum request allocations declared by
  the steps. `allow_state_changes` defaults to false.
- Optional `scope.network_endpoints`: explicit `{host, protocol, ports}` tuples
  for bounded TCP/UDP probes that do not use an HTTP origin, such as one DNS
  resolver or one Nmap port. These do not widen the HTTP origin list.
- `targets`: each target URL must resolve to one of the exact scoped origins.
  Optional roles use labels and environment-variable *names* only. Planning
  never reads credentials; `run-workflow` reads the selected role's named
  environment value as the complete value for its declared HTTP header and
  never stores it.
- `steps`: registered tool names, target, role, preceding dependencies, and a
  per-step request ceiling. Arbitrary commands are not accepted. Mutating
  `business_workflow` steps require the explicit state-change gate, a fixture
  note, a relative `scenario_file`, and cleanup actions or a manual cleanup
  note.
- Optional `authorization_matrices`: object IDs, owners, and allowed roles are
  explicit. The policy is never inferred from role names.
- Optional `business_context`: the existing versioned context document. Its
  hosts must match the explicitly scoped hostnames.

Start from [`doctrine/templates/ASSESSMENT_CAMPAIGN.json`](../doctrine/templates/ASSESSMENT_CAMPAIGN.json);
the coverage schema example is
[`doctrine/templates/ASSESSMENT_COVERAGE.json`](../doctrine/templates/ASSESSMENT_COVERAGE.json).

```powershell
python scripts/assessment_campaign.py plan `
  --manifest targets/fixture/campaign.json `
  --output targets/fixture/campaign-plan.json `
  --knowledge-db targets/fixture/knowledge.sqlite `
  --engagement fixture
```

The optional knowledge file must already exist in an existing parent directory.
Only allowlisted, sanitized facts are attached to the plan as advisory context;
the planner does not silently skip vulnerability-specific testing. Existing
tools retain their own exact-key cache/reuse rules.

## Execute supported steps

Three native adapters execute: `business_workflow`, `tech_fingerprint`, and
anonymous `api_discovery`. The `run-cli` command executes registered entrypoints
for `cloud_detector`, `api_authz`, `web_crawl`, `web_exposure`, `web_sqli`,
`web_xss`, `web_idor`, `web_dom_xss`, `web_cache`, four AI/LLM testers, and
`chain_execute`.
Shared-transport requests, direct `requests`/urllib clients, and upload tester
TCP connections reserve against the same ledger. API authz campaign runs require
the injected gate context and reject mutation-write mode. The runner invokes a fixed
Python entrypoint without a shell, requires the exact confirmed origin, and
fails closed on off-origin requests or exhausted budgets. It records no CLI
arguments, URLs, credentials, response bodies, or payloads. Fingerprinting checks only
the declared target host. API discovery runs serially, blocks off-origin URLs,
disables Wayback lookups and potentially state-changing method probes, and
reserves each in-scope request against the campaign ledger. Both scanner
adapters return allowlisted summaries without raw response headers or bodies.
`chain_analysis` and `report` remain operator-attested because they do not
perform target HTTP probing.

In campaign mode, `cloud_detector` is restricted to one scoped HTTP header
probe; DNS/CNAME and IP WHOIS lookups are skipped because those network paths
do not use the shared HTTP gate.

For external network tools, `run-external` supports a small set of bounded
single-operation adapters: one curl HTTP(S) request without URL globbing,
redirects, proxies, or retries; one `dig` query for the selected hostname
through one explicitly scoped resolver; or one Nmap TCP connect probe to a
literal IP and explicitly scoped port. Nmap is rewritten to `-sT -Pn -n` with
zero retries. Add the resolver and/or non-origin port to
`scope.network_endpoints`; each operation consumes one campaign request unit.
Other network executables and shell commands fail closed.

The workflow adapter validates the scenario and declared request budget before
reading credentials or sending a request. Execution also requires the
manifest's `allow_state_changes` gate and an exact-origin `--confirm-target`.
The transport disables redirects, verifies TLS, times out after 15 seconds per
request, caps response bodies at 2 MiB, and counts each outbound request
against the selected step's budget. A 429 or `Retry-After` stops follow-up
work; cleanup is then reported as skipped. The result contains
statuses/assertion booleans, never response bodies or auth values.
Scenarios may declare per-case `impact_assertions` with an unsafe `equals`
value and a `safe_value` already proven by the baseline. The case is
auto-validated only when its final GET/HEAD read-back matches the unsafe value
and differs from the baseline; un-oracled cases remain candidates.

For durable, resumable execution, pass a local SQLite state file and a stable
campaign ID. The first run binds that ID to the engagement, manifest hash, and
declared global request budget. Every outbound adapter request is atomically
reserved against both the step ceiling and aggregate campaign ceiling. A
completed step cannot be replayed. A crashed or failed step requires explicit
review and `--retry-interrupted`; retry can repeat side effects, so use only
after checking the target and prior result. The ledger records step states and
counts, never request URLs, credentials, response bodies, or payload values.
It also enforces declared step dependencies. For the registered scanner CLI
entrypoints, use `run-cli` or `run-external` so supported requests are charged
as they leave the adapted transport. Python helpers consult the gate only when
campaign environment is set. The campaign bootstrap also scopes ordinary
Python DNS lookups and TCP/UDP sockets, disables ambient urllib proxies, and
blocks shell, direct `os` process APIs, and unadapted child executables. It is
process-level defense in depth, not an OS firewall; native extensions and tools
launched outside this runner are not contained. A copied skill without the
central gate module is not a supported campaign execution environment. Other registered non-network tools can be marked complete with an
operator note; the ledger stores only a digest of that note, not its text, and
the attestation is not independent proof of the tool's outcome.

`run-cli`, `run-external`, `run-step`, and `run-workflow` use host-enforced
network containment by default. On Windows this requires a root-enabled WSL
distro with `iproute2`, `nftables`, and `setpriv`; on Linux it requires root
plus those tools. The runner creates a temporary network
namespace and veth, installs a temporary nftables allowlist for the selected
origin's resolved IPv4 addresses and explicitly declared network endpoints,
and drops the scan process to `nobody` with no Linux capabilities. Other
IPv4/IPv6 egress is dropped. The namespace, firewall table, and temporary host
IP-forwarding change are cleaned up after the command; a lock serializes these
temporary firewall changes. The Windows firewall is not changed. Hostnames are
resolved before entering the namespace and pinned to those addresses; IPv6-only
targets and loopback targets are not supported in this mode. If namespace setup
or firewall installation fails, the command fails rather than falling back to
the process-only gate.
Use `--process-only` only when you explicitly need the weaker process-level
gate, such as for a local loopback fixture that cannot be reached from a
separate namespace.

```powershell
python scripts/assessment_campaign.py run-step `
  --manifest targets/fixture/campaign.json `
  --step tech-recon `
  --confirm-target https://app.example.test `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11 `
  --output targets/fixture/tech-recon-result.json

python scripts/assessment_campaign.py run-step `
  --manifest targets/fixture/campaign.json `
  --step api-inventory `
  --confirm-target https://app.example.test `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11 `
  --output targets/fixture/api-inventory-result.json

python scripts/assessment_campaign.py run-workflow `
  --manifest targets/fixture/campaign.json `
  --step checkout-flow `
  --confirm-target https://app.example.test `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11 `
  --output targets/fixture/checkout-result.json

python scripts/assessment_campaign.py run-cli `
  --manifest targets/fixture/campaign.json `
  --step crawl `
  --confirm-target https://app.example.test `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11 `
  -- --target https://app.example.test --depth 1 --max-pages 25 `
  --output targets/fixture/crawl.json

python scripts/assessment_campaign.py campaign-status `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11

python scripts/assessment_campaign.py campaign-record-step `
  --manifest targets/fixture/campaign.json `
  --state-db targets/fixture/campaign-state.sqlite `
  --campaign-id assessment-2026-11 `
  --step crawl `
  --operator-note "Reviewed crawl result artifact"
```

Keep the SQLite file local to the engagement and protect it like assessment
metadata. The aggregate counter covers the three native adapters and the six
fixed CLI entrypoints above, provided their network traffic uses the shared
`_common.scoped_urlopen` transport. Directly launching a scanner, a copied skill
without the repository gate module, or a tool using a separate HTTP client or
external network executable is outside the counter; such CLIs still require
individual integration or operator attestation. The gate counts redirected
HTTP requests and rejects requests outside the selected step's origin.

```powershell
python scripts/assessment_campaign.py run-workflow `
  --manifest targets/fixture/campaign.json `
  --step checkout-flow `
  --confirm-target https://app.example.test `
  --output targets/fixture/checkout-result.json
```

For mutating scenarios, use a disposable fixture and review cleanup status.
Cleanup execution is recorded as attempted, not proven successful, because the
scenario contract deliberately does not return response bodies.

## Authorization results

The plan can expand role × object cases. Supply observations from the selected
authorization tester using role/object labels and normalized outcome fields:

```powershell
python scripts/assessment_campaign.py authorization `
  --plan targets/fixture/campaign-plan.json `
  --results targets/fixture/authorization-results.json `
  --output targets/fixture/authorization-review.json
```

A status-only cross-role success is a candidate. Confirmation requires
`role_identity_verified`, `owner_control_passed`, `object_identity_verified`,
and `unauthorized_data_proof` all set to true. The evaluator does not send
requests, inspect credentials, or infer ownership.

## Coverage and benchmark labels

Run the built-in offline benchmark against its loopback-only authz and
stateful-workflow fixture:

```powershell
python scripts/run_local_benchmark.py --output targets/benchmark/local-v2.json
```

It executes BOLA/BFLA role controls, a protected-admin negative control, and a
repeat-coupon baseline/misuse/read-back/cleanup scenario. The result uses the
same coverage evaluator below and includes benchmark-specific precision and
recall. The fixture is a regression baseline only; run separately provisioned
DVWA, Juice Shop, or crAPI builds for broader coverage. Do not treat this
fixture score as internet-wide accuracy.

The plan's `business_context` object remains in the existing
`context_severity.py` document format. It can be saved as a separate JSON file
and passed to `calculate_impact.py --business-context` for contextual scoring;
the campaign planner checks that each asset hostname is explicitly in scope.

Coverage manifests have `schema_version: 1` and a list of cases with stable
IDs, behavior, tool, role, configuration, preconditions, expected evidence, and optional
`expected` label (`vulnerable`, `not_vulnerable`, or `unknown`). Labeled cases
must include `gold_source`, such as a local fixture oracle. Results are a JSON
list of case results. A confirmed result must include the common review, for
example `{ "case_id": "...", "status": "confirmed", "evidence_review": {
"schema_version": 1, "assessment_state": "confirmed", "proof_checks": {
"complete": true } } }`; the evaluator downgrades unsupported confirmed claims
to candidates. Other statuses include `candidate`, `tested_negative`, `blocked`,
and `untested`. Only produce a complete review after the shared proof checks or
an equivalent independent domain-specific validation.

```powershell
python scripts/assessment_campaign.py coverage `
  --manifest targets/fixture/coverage.json `
  --results targets/fixture/coverage-results.json `
  --output targets/fixture/coverage-report.json
```

Coverage is execution coverage, not accuracy. Precision/recall are calculated
only when cases have explicit expected labels and a confirmed/negative result;
candidate, blocked, and untested cases remain unresolved. Metrics describe only
the labeled manifest and are not estimates of internet-wide accuracy. If the
same case has both a confirmed and negative result, it is marked `conflict`.
The report also includes `coverage_by_dimension` summaries for tool, role, and
configuration, so a high total can be checked for missing roles or test types.

Use `prioritize` to rank unresolved cases for follow-up. Candidate, blocked,
authorization, and stateful workflow cases receive transparent ranking reasons;
the command does not change case status or skip tests:

```powershell
python scripts/assessment_campaign.py prioritize `
  --manifest targets/fixture/coverage.json `
  --results targets/fixture/coverage-results.json `
  --output targets/fixture/next-tests.json
```

Import saved crawler, API discovery, or browser audit JSON into the shared
engagement knowledge store. The importer keeps same-origin route paths,
observed methods, and auth-required flags; it strips query strings and drops
off-origin routes. Facts expire after 15 minutes and remain test leads, not
confirmed findings:

```powershell
python scripts/target_knowledge.py `
  --db targets/fixture/knowledge.sqlite --engagement fixture `
  --target https://app.example.test `
  --ingest targets/fixture/browser-audit.json
```

Browser audit reports now retain same-origin links and form actions/methods
without field values or query strings. Workflow discovery can use these saved
reports with an explicit origin boundary:

```powershell
python skills/webapp-exploit-hunter/scripts/workflow_tester.py `
  --browser-audit targets/fixture/browser-audit.json `
  --api-base https://app.example.test
```

For authenticated skip-ahead coverage, repeat `--role NAME:HEADER:ENV_VAR`;
the tester reads each credential value from the named environment variable,
probes each role independently, and labels candidate results by role without
writing credential material to the report:

```powershell
python skills/webapp-exploit-hunter/scripts/workflow_tester.py `
  --browser-audit targets/fixture/browser-audit.json `
  --api-base https://app.example.test `
  --role member:Authorization:MEMBER_TOKEN `
  --role admin:Authorization:ADMIN_TOKEN
```

## Current v1 boundary

The planner validates and emits the ordered plan. The fingerprint, API
discovery, and workflow adapters use an opt-in SQLite ledger for durable step
state and an aggregate request cap across participating runs. Adapters for
remaining recon and vulnerability scanners, and universal cross-tool
request-budget enforcement remain deferred. External
step completion is operator-attested until native adapters are implemented.
Existing per-tool request limits remain in effect where a CLI exposes one. This boundary
is intentional because current tools expose different request controls, and a
campaign-wide ceiling cannot be claimed until the runner can enforce it across
all adapters. Browser-only proof, automatic workflow discovery, remote
knowledge synchronization, and fully automatic business-context inference are
also out of scope.
