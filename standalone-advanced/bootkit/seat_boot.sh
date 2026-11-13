#!/usr/bin/env bash
# seat_boot.sh <SEAT_KEY> — SessionStart hook for Claude seats.
# Prints the seat's boot block to stdout (hook injects stdout into context).
# ALWAYS exit 0 — a boot hook must never break a session. Fast: no network,
# no heavy reads — the block only POINTS at disk; the seat reads disk itself.
set -u

SEAT="${1:-SUPERVISOR}"
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOT="$KIT/boot"

hunter_seat() {
  case "$1" in
    DATAFLOW_GROK|RECON_GROK|CHAIN_GROK|KIMI|DATAFLOW|RECON|CHAIN|HUNTER) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -f "$BOOT/$SEAT.md" ]; then
  cat "$BOOT/$SEAT.md"
elif hunter_seat "$SEAT"; then
  # pure-bash substitution, not sed — a seat key containing '/' or '&' would
  # corrupt the sed replacement; ${var//@SEAT@/$SEAT} has no delimiter hazards
  template="$(cat "$BOOT/HUNTER.md")"
  printf '%s\n' "${template//@SEAT@/$SEAT}"
else
  # fallback: unknown seat — print the universal minimum, never nothing
  cat <<'FB'
# MYTHOS SEAT BOOT — FALLBACK (seat block not found on disk)
You are a seat of the mythos swarm. Before ANY action:
1. Read ~/claude-shared/SWARM_PROTOCOL.md — your identity and lane are there.
2. Read ~/claude-shared/active_target, then ~/targets/<t>/STATE/SEAT_STATUS.json and ~/claude-shared/agents/TASK_QUEUE.json.
3. Disk is the source of truth. Missing doctrine → find it on disk or STOP.
4. Report in one breath: identity, live seats, board state, next action.
FB
fi

printf '\n[boot: %s loaded %s]\n' "$SEAT" "$(date -Is)"
exit 0
