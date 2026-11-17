# Unattended Claude/Codex supervisor — v1

A stdlib Python controller for an **explicitly approved, finite task queue**.
It runs the installed Codex and Claude CLIs, with an author and the opposite
model as reviewer. One task executes at a time in v1; both models participate,
but this version does not run parallel authors. There is no API-key bridge,
new model API integration, desktop clicking, or implicit follow-on backlog.
Tasks #6–#8 are not queued by installing or running this tool.

## State and mailbox

`git rev-parse --git-common-dir` identifies shared repository metadata even
from linked worktrees. Runtime state lives in `agent-coordination/` below that
directory: `coordination.sqlite`, `mailbox.md`, and per-attempt `runs/` logs.
Worker/integration worktrees live in a sibling `.agent-supervisor-<repository-hash>/`
directory beside the common repository, outside `.git`; Claude appropriately
blocks file edits under Git metadata. Worktree paths are checkpointed.
All worktrees query the same queue. This is separate from #5's target knowledge.

SQLite transactions atomically record immutable approved task specs, their
SHA-256 approval hashes, exact file/directory claims, monotonically increasing
fencing tokens, leases, checkpoints, and append-only sequenced events. There
is one runner/integrator owner. Events and state commit in the same database;
no second cursor/sequence sidecar is needed for recovery. `mailbox.md` is an
atomically regenerated view of those events, not a second source of truth.
Historical `.agent-mailbox/claude-to-codex.md` and `codex-to-claude.md` are never
rewritten; the transcript command refuses those destination names.

The lounge's identifier validation, ownership, event sequencing, and explicit
approval concepts informed this implementation. Its HTTP-cell claims are not
reused as Git-file claims: the conflict/claim transaction and fencing semantics
are different. A task's `enqueue --approve` transaction is the durable approval
gate, tied to the whole immutable spec rather than a mutable marker file.

## First use (PowerShell, repository root)

Both CLIs must already be installed and authenticated. Check with
`codex login status` and `claude auth status`. The supervisor does not create,
read, or persist API keys. Existing CLI authentication is used.

```powershell
python3 tools/agent-supervisor/supervisor.py status
$coord = Join-Path (git rev-parse --path-format=absolute --git-common-dir) 'agent-coordination'
Copy-Item tools/agent-supervisor/supervisor.example.json (Join-Path $coord 'local-config.json')
```

The example starts with `enabled=false` and `push=false`. Edit the private
copy to enable execution. To allow integration, also set `push=true`; a run
must additionally specify `--push`. Keep the shipped example disabled.
Validation commands are trusted operator configuration expressed as argument
arrays. The example runs pytest, Ruff, compileall, CLI docs, helper sync and
diff checks. Override interpreter paths in the private copy if necessary.

Create a task JSON file in the runtime directory, for example:

```json
{
  "id": "approved-documentation-fix",
  "agent": "codex",
  "prompt": "Fix the explicitly described documentation issue. Acceptance: the example matches the CLI help. Do not start other work.",
  "files": ["path/to/the/approved-document.md"],
  "depends_on": []
}
```

Replace the prompt and exact paths with the work you actually approve.
Claims are exact files or directory prefixes ending in `/`, not globs.
Traversal, Git metadata, ambiguous Windows paths, and symlink changes are
rejected. Ownership overlap is conservatively case-insensitive on all OSes.
Dependencies must already be enqueued; this prevents forward-reference cycles.

```powershell
python3 tools/agent-supervisor/supervisor.py enqueue --spec "$coord/task.json" --approve
python3 tools/agent-supervisor/supervisor.py run --config "$coord/local-config.json" --execute --push --max-tasks 2 --max-seconds 1800
python3 tools/agent-supervisor/supervisor.py status
python3 tools/agent-supervisor/supervisor.py mailbox
```

A run stops when its finite limit is reached, the approved queue has no
eligible work, or an error requires attention. It does not poll forever or
invent new tasks. Run it in a persistent terminal or your own service runner
when unattended execution is wanted. Installing it does not schedule a job.
Status percentages represent checkpoint milestones, not estimated code quality:
claimed/creating 10%, implementing 20%, validating 45%, reviewing 65%,
integration validation 85%, pushed 100%. Batch percentages average task stages.

## Author, review, integration

Failed-check feedback includes bounded, best-effort-redacted stdout/stderr tails
as explicitly untrusted reference data, so authors can repair without needing
access to private Git-metadata log paths. Raw private logs still need careful
handling; redaction is not a general secret-detection guarantee.

Authors edit only. The supervisor checks the complete change set against the
approved file claims, commits as FelixCatus, and runs the configured checks.
A reviewer gets a separate local clone (with independent Git metadata),
the exact base/candidate SHAs, the complete bounded binary-capable diff,
and supervisor-recorded validation results. Review diffs are never filtered
by case-sensitive pathspecs; file claims are checked before and after commit
to catch hook-added files. The committed base-to-candidate diff also gets an
explicit whitespace/conflict-marker check. Reviews must return strict JSON
with `approved`, `candidate_sha`, `base_sha`, and a string-array `findings`.
A bare model claim or stale SHA cannot approve integration. Unresolved findings
or failed validation trigger bounded author repair; changed candidates get
fresh validation and a new opposite-model review. Diffs over 256 KiB are
quarantined for splitting rather than silently truncated for review.

A separate integration worktree checks the exact reviewed commit again.
If remote main has advanced since the approved review base, integration stops
for rebase/review instead of borrowing the stale approval. Push uses normal
fast-forward Git semantics, never a force push, then verifies the remote SHA.
The user's existing checkout and local main are not moved by the supervisor;
a later task starts from freshly fetched remote main. Pull main when you want
your interactive checkout to reflect the result.

Codex authors use `workspace-write`, reviewers use `read-only`, and both use
`approval_policy=never`. Claude authors get only Read/Glob/Grep/Edit/Write,
`acceptEdits`, safe mode, and no prompts; reviewers get Read/Glob/Grep and
`dontAsk`. Bash/PowerShell tools are not granted to Claude workers. Checks and
Git mutation run in the controller. Chosen permissions are checkpointed.
The npm Codex launcher is called through Node, not a shell-wrapper command.
No blanket approval-bypass flags are used. A denied permission becomes a
needs-attention result, not an automatic permissions escalation.

## Stop, crash, recovery

```powershell
python3 tools/agent-supervisor/supervisor.py stop
python3 tools/agent-supervisor/supervisor.py status
# After confirming old workers/descendants have stopped:
python3 tools/agent-supervisor/supervisor.py recover --confirm-workers-stopped
# Retry one quarantined task in a NEW fenced branch/worktree:
python3 tools/agent-supervisor/supervisor.py recover --confirm-workers-stopped --retry approved-documentation-fix
# Or release its claims without retrying:
python3 tools/agent-supervisor/supervisor.py cancel --task approved-documentation-fix --confirm-workers-stopped
```

Heartbeat/stop checks run while CLI/check subprocesses execute. Timeouts and
stop requests terminate process groups on POSIX and request process-tree
termination on Windows. POSIX session groups are cleaned even after a
successful parent exit. Stdout and stderr are captured separately so CLI
warnings cannot corrupt structured JSON results. Windows workers additionally join kill-on-close Job
Objects, so attached descendants are cleaned up when the supervisor exits.
Assignment is immediately after process launch, not an OS security sandbox
against an intentionally escaping program. Runtime `.process.json` files
record PID, random session token, start time, return code and cleanup status.
A PID or token file is diagnostic, not proof of OS process identity: recovery
never kills an unknown process just because its PID matches a stale record.

An expired runner cannot be silently replaced. Running/quarantined task claims
remain held until explicit recovery/cancellation; the operator must confirm old
processes stopped. This prevents lease expiry from causing two live authors on
the same files. Old worktrees, logs, SHAs and checkpoints are preserved; retry
starts a new attempt and does not delete prior work. Recovery does not pretend
to resume a killed model's hidden conversation. A reviewed candidate with push
disabled is retained in needs-attention for explicit operator handling.

Runtime/check deadlines, max task count, repair count, and Claude's per-call USD
limit bound runs. Codex does not expose a per-call USD cap here; elapsed time
is not a strict token/spend limit. Authentication failures, repeated validation
failures, conflicts, stale approvals, and unresolved review findings stop the
batch. Logs/prompts can contain proprietary code or task data: keep runtime
files private. Runtime state is not committed or cloud-synchronized.

## Trust and scope limits

Use only trusted local repositories, task specs, validation commands, and CLI
installations. Worktrees isolate edits; all worktrees still share Git metadata
and the OS user. File-claim enforcement is a post-edit check, not a hostile-code
security boundary. The supervisor does not run arbitrary target assessments,
change global permissions, grant network authorization, or replace CI/review
judgment. Test commands execute repository code as the current user. Normal
permission policies and sandbox boundaries still apply.

Offline regression tests use fake model adapters and disposable local Git
remotes. They prove lifecycle decisions without spending model credits or
pushing fixture changes to GitHub. Model CLI connectivity and real model output
must also be smoke-tested separately before relying on unattended operation.


## Diagnostics and push reconciliation

Stdout and stderr are separate private files. Failed-check feedback includes
bounded, best-effort-redacted tails as untrusted data, so an author can repair
without reading private `.git` paths. Ownership/stop failures are distinct from
validation failures and never trigger a repair attempt.

Git commands heartbeat and obey the remaining batch deadline. Network Git
commands use `network_timeout` (default 180 seconds). Git stdin/terminal prompts
and interactive credential-manager prompts are disabled; SSH defaults to
BatchMode unless an explicit environment SSH command is already configured.
The controller checks the committed base-to-candidate diff for whitespace and
conflict-marker problems, independently of configured check commands.

A failed/ambiguous push triggers remote-SHA inspection. The exact candidate
means applied; the unchanged base means not applied; any other SHA is treated
as ambiguous. Already-applied/ambiguous outcomes cannot be blindly retried.
After checking that prior workers stopped, reconcile an already-applied task:

```powershell
python3 tools/agent-supervisor/supervisor.py recover --mark-pushed approved-documentation-fix --confirm-workers-stopped
```

This verifies remote main exactly matches the validated and independently
approved candidate before marking the task done and releasing dependencies.
A different/unreviewed remote commit cannot be accepted. Investigate divergent
remote state manually; do not discard old checkpoints to force a retry.
