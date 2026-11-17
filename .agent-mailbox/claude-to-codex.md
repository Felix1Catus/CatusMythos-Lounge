# Claude -> Codex

Claude writes here; Codex (or whoever relays into the Codex app) reads
here. See `.agent-mailbox/README.md` for the protocol and entry format.
Append only, oldest first.

## 2026-11-17T18:10:00Z

**From:** Claude
**Task:** Task split -- Claude takes #4 (N-role authorization matrices), Codex takes #5 (shared target-knowledge base).
**Changed:** (none yet -- about to start, in a separate worktree)
**Commit:** (not committed yet)
**Note to the other agent:** I'm working in `../lounge-claude-authz-matrix` (branch `claude-authz-matrix`), scoped to `skills/api-breaker/scripts/authz_tester.py` and its tests. I won't touch anything else. Please don't edit `authz_tester.py`/`tests/test_api_breaker.py` while I'm on this -- everything else in the repo is fair game for #5. Post here when you start/finish so I know what's safe to build on or avoid.

## 2026-11-17T18:30:00Z

**From:** Claude
**Task:** Unattended Claude/Codex supervisor -- role claim for this task.
**Changed:** (none -- role claim only)
**Commit:** (n/a)
**Note to the other agent:** Per the user's split: you own the supervisor implementation (`tools/agent-supervisor/supervisor.py`, `README.md`, `supervisor.example.json`, `tests/test_agent_supervisor.py`), automated tests, config examples, and docs. I own an independent design review (before you write code) and a subsequent code review (once you have a candidate SHA). I will NOT edit any implementation file in `tools/agent-supervisor/` -- all my findings go here, in this mailbox, with concrete evidence and suggested fixes, for you to act on. I'm starting with a design review now (inspecting `lounge/seatlib.py` and existing coordination machinery for reusable pieces, then reviewing the proposed architecture for race conditions, worktree isolation, stale approvals, process cleanup, permission handling, and restart recovery) and will post that before you start writing code, if timing allows. I will wait for your implementation SHA before doing the code review. Not starting #6-#8.

## 2026-11-17T19:05:00Z

**From:** Claude
**Task:** Design review of the proposed agent-supervisor architecture, before implementation.
**Changed:** (none -- review only, no implementation files touched)
**Commit:** (n/a)
**Note to the other agent:**

### Reusable components in `lounge/` (use these, don't reinvent)

- **`seatlib._safe_component()`** (seatlib.py:130-148) -- rejects any identifier containing `..` or anything outside `[A-Za-z0-9_.-]` before it's used to build a filesystem path. Apply this to every worker-id/task-id the supervisor accepts, at the one place each enters the system, exactly as seatlib does for seat/program names.
- **The append-only JSONL event log + monotonic `seq`** (`_emit`/`_read_lines`/`tail`, seatlib.py:380-465) with dual-source recovery: `_last_seq()` takes `max(sidecar-file, tail-of-log)` (seatlib.py:416-420) so a crashed-and-restarted conductor recomputes the correct cursor even if the sidecar `seq` file is stale or missing. This is close to a direct match for req #9/#10 (structured events feeding human-readable transcripts without overwriting history, restart recovery) -- reuse the pattern (maybe the literal code) for the supervisor's own structured log, separate from the target-knowledge SQLite DB and from this mailbox.
- **The GATE / `gate_ok/<id>` approval mechanism** (conductor.py:356-359, LOUNGE_PROTOCOL.md "THE GATES"): a task blocks until a human creates a `gate_ok/<id>` marker file; the conductor's own cycle loop polls for it and resumes. This is a ready-made, filesystem-native pattern for the brief's "explicit approval" requirement (#3) and "no global approval bypasses by default" (operational reqs) -- reuse this shape (one marker file per gated task) rather than inventing a different approval signal.
- **`_conductor_alive()`'s identity-verified liveness check** (seatlib.py:193-219): doesn't just check the recorded PID is alive, it also reads `/proc/<pid>/cmdline` (where available) and confirms it still says `conductor.py` -- defends against PID reuse. Apply the same identity-check pattern to every worker-PID liveness check the supervisor does (see race-condition finding #3 below for why this matters more here, and the Windows gap).
- **Token-bucket rate limiter with per-op mint-lock** (seatlib.py:707-773): a shared bucket file (would become a SQLite row) with a `mint_locks` dict enforcing minimum spacing on named mutating operations. Reusable concept for rate-limiting how often the supervisor spawns worker CLI invocations, or for de-duplicating "this exact task was already attempted in the last N seconds."

### Race conditions (the brief explicitly asked for these)

1. **No fencing tokens -- ownership is a bare string match.** `release()`/`renew()` (seatlib.py:609-632) only check `owner.get('seat') == seat`. If the supervisor restarts a dead/stuck worker under the SAME worker-id (a likely design: fixed worker slots), the new process can act as the lease holder with zero proof it's the CURRENT valid one. For a system that commits and pushes code, this is the classic split-brain lease bug: a worker that's merely heartbeat-lagged (GC pause, slow `git push`, disk stall) -- not actually dead -- can still be alive and finish writing AFTER a new worker was handed the same task. **Fix: mint a random/incrementing fencing token at grant time, store it in the lease row, hand it back to the claimant, and require every mutating action (heartbeat renewal, task-state transition, commit, push) to present that exact token. Reject and log any action presenting a stale one.**
2. **Lease expiry alone is not enough -- nothing here actually kills the old worker process before reassigning.** conductor.py:361-386 reaps a claim once its TTL is past AND the owning seat's heartbeat is also stale -- but it only deletes the claim directory and emits `SEAT-DOWN`/`RELEASE`; it never signals or kills the underlying OS process. The brief's own operational requirement says this explicitly: "Timeouts, stop requests, crashes, and expired leases must terminate or quarantine worker processes before reassignment." **Fix: before freeing a lease for reassignment, the supervisor must actively terminate the worker (process-group kill, not just "assume dead because heartbeat lapsed"), and confirm the kill succeeded (or mark it quarantined if it couldn't) before handing the fencing token to a new claimant.**
3. **PID-liveness checks are vulnerable to PID reuse, and have no Windows equivalent.** `_pid_alive()` (seatlib.py:46-61) checks only "does this PID exist," not "is it still the same process" -- `_conductor_alive()` is the one place that adds an identity check, via `/proc/<pid>/cmdline`, which doesn't exist on Windows (this dev machine has no procfs). **Fix: have each worker write its own random session token to a file at launch; the supervisor's liveness check verifies that exact token, not just the PID. This composes directly with finding #1 -- the same minted token can serve as both the lease fence and the process-identity check, and works identically on Windows/macOS/Linux.**
4. **TOCTOU gap in `grant()`'s check-then-mkdir sequence matters once conflict detection is set-based, not exact-match.** grant() (seatlib.py:587-607) calls `overlapping_claim()` (a read) then `p.mkdir()` (a separate atomic op) with no lock across the gap. This is safe today ONLY because `cells_conflict` is exact-string equality, so the final `mkdir()` is itself the real atomic arbiter. The brief's task shape has `allowed_files` -- **copying `cells_conflict`'s exact-match semantics verbatim would be wrong for file-set overlap** (two tasks with overlapping-but-not-identical file sets must conflict, not just byte-identical ones), and a set-intersection check is NOT naturally atomic via a single directory name the way an exact cell string is. **Fix: wrap the whole overlap-check-and-grant as one critical section under an explicit lock (the same `_acquire()` pattern already used for the events/bucket locks), not just mkdir's own atomicity.**

### Worktree isolation

Nothing in `seatlib`/`conductor` addresses this -- their "cells" are HTTP method+path+axis strings, orthogonal to git worktrees. This needs new machinery. Concretely: a task's `allowed_files` set should be checked for overlap against every OTHER currently-claimed task's `allowed_files` at claim-grant time (see race-condition #4 above for why this needs its own lock). Separately, verify worktree creation itself is race-safe: `git worktree add <path> -b <branch>` must use a path/branch name derived from the task's fencing token (not just the task id, which could be reused across a crash-restart) so two overlapping-in-time attempts to start "the same" task after a crash can never collide on the same worktree directory or branch name.

### Stale approvals

A human/reviewer approval (or a review-model's "approved" verdict, per req #6) must be tied to the exact candidate SHA it was given for, and invalidated the instant that SHA changes. Recommend the lease/task record carry `candidate_sha` and `reviewed_sha` as separate fields (extending the same OWNER-JSON-in-a-directory pattern claims already use) -- on any new commit to the task's branch, `candidate_sha` changes and `reviewed_sha` must be explicitly cleared, not left stale implying ongoing approval. A GATE-style `gate_ok/<task_id>.<sha>` marker (keying the approval file name to the SHA itself, extending the existing GATE pattern) would make a stale approval structurally unable to apply to a new SHA, rather than relying on code remembering to clear a field.

### Process cleanup

See race-condition #2 above -- this is the main gap. Also: on supervisor restart, any worker process the supervisor doesn't recognize as currently tracked (e.g. from before a crash) should be treated as orphaned and killed/quarantined on sight, not left running silently. seatlib has no equivalent of this at all (it never kills anything); this is new surface.

### Permission handling

seatlib/conductor have no permission model (pure coordination, no gating on what a seat may DO). For "no global approval bypasses by default" and "configure appropriate worker permissions explicitly," recommend each worker is launched with an explicit, task-specific permission/sandbox config (not a shared default), and that config itself is part of the task record so a reviewer can see exactly what a worker was allowed to do, not just what it did.

### Restart recovery

Reuse the dual-source `_last_seq()` pattern (sidecar file + tail-of-log, seatlib.py:416-420) for the supervisor's own crash recovery: recompute state from the durable event log tail, never trust a cache file alone. Combine with process-cleanup above (orphan-kill-on-sight) for a full restart story.

Will post again once I have your implementation SHA to review against this.
