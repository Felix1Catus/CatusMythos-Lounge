# MYTHOS Continuous-Resume System

Built 2026-07-14. Kills the "agent dies mid-work on tokens → resumes badly or not at all" failure.
Two layers of disk state per program under `~/targets/<program>/STATE/`:

| Layer | File | Who writes it | What it answers |
|-------|------|---------------|-----------------|
| **Action trail** | `JOURNAL.ndjson` | **automatic** (PostToolUse hook) | *what physically ran* — every tool call, its result-class, output gist. Survives abrupt token-death because the hook writes it, not the agent. |
| **Intent head** | `CHECKPOINT.md` | the agent (cheap, merge-update) | *where am I / heading / how* — NOW, GOAL, APPROACH, PROVEN, NEXT, BLOCKERS, FILES. |
| Narrative | `RESUME.md` | the agent (as before) | the full story. Unchanged; still the deep record. |

Global safety-net copy of every action: `~/.claude/mythos/journal/<date>.ndjson`.

## Parts
- `journal.py` — PostToolUse hook. Appends one NDJSON line per tool call. Routes to a program by
  (1) a `targets/<prog>/` path in the tool input, else (2) the `active_target` marker. Fail-open, <30ms.
- `checkpoint.py` — writes/merges `CHECKPOINT.md`. Unspecified `--flags` keep prior values, so updating
  just `--next` is a one-liner. `python3 ~/.claude/mythos/checkpoint.py <prog> --now .. --next .. ...`
- `resume.sh <prog> [N]` — cold-boot reader: CHECKPOINT + last N actions + RESUME pointer + live infra.
  Bare `resume.sh` lists resumable programs by last-action time.
- `mtarget.sh <prog>` — sets `active_target` so path-less commands (raw curl to a live host) still file
  to the right program. Set it once when you start on a target.
- `session_resume.sh` — SessionStart hook; if an active target is set, prints its CHECKPOINT on boot.
- Agents: `~/.claude/agents/target-hunter.md` (Opus, attacks + checkpoints), `warm-boot.md` (Fable,
  reconstructs a dead session and re-verifies the last proven fact before continuing).

## Wiring (in `~/.claude/settings.json`, backup at `settings.json.bak.2026-07-14`)
- PostToolUse: `journal.py` added BEFORE `persist_nudge.sh` (both run; nothing removed).
- SessionStart: `session_resume.sh` added AFTER `resume_brief.sh`.
- `persist_nudge.sh`: now also counts a `CHECKPOINT.md` touch as persistence (stops nagging once you checkpoint).
- **Hooks load at session start** — the journal goes live on the NEXT session, not the one that edited settings.

## Suggested shell aliases (add to ~/.bashrc yourself)
    alias mtarget='bash ~/.claude/mythos/mtarget.sh'
    alias mck='python3 ~/.claude/mythos/checkpoint.py'
    alias mresume='bash ~/.claude/mythos/resume.sh'

## Discipline (baked into the agents; do it in the main session too)
1. Start on a target → `mtarget <prog>` → read `resume.sh <prog>` → write opening CHECKPOINT.
2. Each work item / each probe that proves or kills something → update the relevant CHECKPOINT field.
3. Resuming → run `warm-boot` agent or `resume.sh`, and RE-VERIFY the last PROVEN line with a fresh
   probe before building on it (stored state was true when written; a target may be fixed / infra dead).
