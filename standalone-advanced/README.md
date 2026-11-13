# Standalone-advanced material

This directory is **archived documentation and scripts, not part of
CatusMythos-Lounge's own runtime.** Nothing under `skills/`, `agents/`,
`hooks/hooks.json`, or `lounge/` loads or invokes anything here — the plugin
works completely without this folder.

It documents a separate, more elaborate multi-account/multi-CLI coordination
system: `SUPERVISOR`/`HUNTER`/`OPERATOR`/`SKEPTIC` seat roles communicating
through a `TASK_QUEUE.json`/`FINDINGS_INBOX.json`/`SEAT_STATUS.json` bus under
`~/claude-shared/`, with hardcoded paths like `~/.claude/mythos/`,
`~/targets/<program>/`, and `~/research/`, spanning multiple Claude accounts
plus other model CLIs (Grok, Kimi). It predates this plugin and was never
ported into either of the plugin's actual multi-agent mechanisms:
`lounge/` (a real, implemented multi-process coordination system, still used
as-is) and `agents/swarm-operator.md`'s native in-process multi-agent mode
(added alongside lounge in this refactor).

Kept for reference because it has real, battle-tested ideas — a `selfprod.sh`
self-audit discipline, a `rquery.sh` retrieval layer over a large research
corpus, strict human-approval gates — that someone running a personal,
standalone, multi-account setup outside this plugin may want to replicate by
hand. Nothing here is installed, wired, or required; treat it as worked
examples, not a feature of this plugin.

## Contents

- `bootkit/boot/{SUPERVISOR,HUNTER,OPERATOR,SKEPTIC}.md` — per-role identity
  cards for the bus-based roster (`swarm-supervisor`, `swarm-skeptic`,
  `swarm-dataflow`, `swarm-recon`, `swarm-chain`, `swarm-kimi`).
- `bootkit/seat_boot.sh` — a `SessionStart` hook dispatcher that `cat`s the
  matching boot card for a given `SEAT_KEY`.
- `hooks/*.py`, `hooks/*.sh` — the standalone install's own hook scripts
  (persistence, target scaffolding, rate/instrument discipline, a
  pre-file-authorization gate, a dangerous-Bash-primitive guard, status line,
  and the seat-aware stop/supervisor-lane guards), all written against
  `~/.claude/mythos/...` and sibling paths outside this repository.
- `RESUME_SYSTEM.md` — documents the standalone install's two-layer
  persistence design (`JOURNAL.ndjson` + `CHECKPOINT.md`), wired to a
  `~/.claude/settings.json` outside this repo.
