# Assessment campaign v1

`assessment_campaign.py` provides an offline campaign planner/result evaluator
and one bounded executor for the existing operator-authored business workflow
scenarios. Planning and reporting never make network requests. An operator can
review exact scope, roles, test order, state-change intent, cleanup, and request
budget before explicitly executing that workflow step.

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

## Execute one guided workflow

Only the `business_workflow` adapter currently executes. It validates the
scenario and declared request budget before reading credentials or sending a
request. Execution also requires the manifest's `allow_state_changes` gate and
an exact-origin `--confirm-target`. The transport disables redirects, verifies
TLS, times out after 15 seconds per request, caps response bodies at 2 MiB, and
counts each outbound request against the selected step's budget. A 429 or
`Retry-After` stops follow-up work; cleanup is then reported as skipped. The
result contains statuses/assertion booleans, never response bodies or auth
values.

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

## Current v1 boundary

The planner validates and emits the ordered plan. Execution adapters for
recon, API discovery, and vulnerability scanners, a durable campaign event
log/resume command, and universal cross-tool request-budget enforcement remain
deferred. Existing per-tool request limits remain in effect where a CLI exposes
one. This boundary is
intentional because current tools expose different request controls, and a
campaign-wide ceiling cannot be claimed until the runner can enforce it across
all adapters. Browser-only proof, automatic workflow discovery, remote
knowledge synchronization, and fully automatic business-context inference are
also out of scope.
