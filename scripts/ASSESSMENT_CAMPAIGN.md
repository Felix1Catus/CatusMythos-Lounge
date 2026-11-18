# Assessment campaign v1

`assessment_campaign.py` provides an offline campaign planner/result evaluator
and bounded executors for an existing operator-authored business workflow,
single-origin technology fingerprinting, and anonymous API discovery.
Planning and reporting never make network requests. An operator can review
exact scope,
roles, test order, state-change intent, cleanup, and request budget before
explicitly executing a supported step.

## Plan a campaign

Create a JSON manifest with:

- `schema_version: 1` and an engagement label.
- `scope.origins`: exact credential-free HTTP(S) origins.
- `scope.request_budget`: sum of the maximum request allocations declared by
  the steps. `allow_state_changes` defaults to false.
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

Three native adapters currently execute: `business_workflow`,
`tech_fingerprint`, and anonymous `api_discovery`. Fingerprinting checks only
the declared target host. API discovery runs serially, blocks off-origin URLs,
disables Wayback lookups and potentially state-changing method probes, and
reserves each in-scope request against the campaign ledger. Both scanner
adapters return allowlisted summaries without raw response headers or bodies.
Other registered tool identifiers remain planned until native adapters exist.

The workflow adapter validates the scenario and declared request budget before
reading credentials or sending a request. Execution also requires the
manifest's `allow_state_changes` gate and an exact-origin `--confirm-target`.
The transport disables redirects, verifies TLS, times out after 15 seconds per
request, caps response bodies at 2 MiB, and counts each outbound request
against the selected step's budget. A 429 or `Retry-After` stops follow-up
work; cleanup is then reported as skipped. The result contains
statuses/assertion booleans, never response bodies or auth values.

For durable, resumable execution, pass a local SQLite state file and a stable
campaign ID. The first run binds that ID to the engagement, manifest hash, and
declared global request budget. Every outbound adapter request is atomically
reserved against both the step ceiling and aggregate campaign ceiling. A
completed step cannot be replayed. A crashed or failed step requires explicit
review and `--retry-interrupted`; retry can repeat side effects, so use only
after checking the target and prior result. The ledger records step states and
counts, never request URLs, credentials, response bodies, or payload values.
It also enforces declared step dependencies. Until a scanner has a native
campaign adapter, run that registered tool separately and record its completion
with an operator note; the ledger stores only a digest of that note, not its
text, and the attestation is not independent proof of the tool's outcome.

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
metadata. The aggregate counter covers runs that use the campaign ledger and
one of the three native adapters. Independent scanner CLIs do not currently
participate in it. Their operator attestation completes dependency tracking but
does not charge the campaign request counter.

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
