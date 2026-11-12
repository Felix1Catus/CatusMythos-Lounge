#!/usr/bin/env bash
# stop.sh — halt conductor + hb-loops for one program lounge.
# Usage: bash stop.sh --program PROGRAM_71
# Does not kill the agent terminals. Ctrl-C those (or tmux kill-session -t lounge-<seat>).
set -euo pipefail
PROGRAM=""; STATE_ROOT="$HOME/targets"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --program) PROGRAM="$2"; shift 2 ;;
    --state-root) STATE_ROOT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PROGRAM" ]] || { echo "FATAL: --program required" >&2; exit 2; }
RUNTIME="$STATE_ROOT/$PROGRAM/LOUNGE"
[[ -d "$RUNTIME" ]] || { echo "no lounge at $RUNTIME" >&2; exit 1; }

kill_if_ours() {
  local pid="$1" needle="$2"
  [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  local cmd
  cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
  [[ "$cmd" == *"$needle"* ]] || return 0
  kill "$pid" 2>/dev/null || true
  sleep 0.1
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  echo "killed $pid ($needle)"
}

PIDFILE="$RUNTIME/conductor.pid"
if [[ -f "$PIDFILE" ]]; then
  kill_if_ours "$(cat "$PIDFILE")" "conductor.py"
  rm -f "$PIDFILE"
fi

# hb-loop processes whose pidfile lives in this lounge
for pf in "$RUNTIME"/seats/*.pid; do
  [[ -f "$pf" ]] || continue
  # hb-loop watches this pidfile; find python hb-loop with this path
  while read -r pid; do
    kill_if_ours "$pid" "hb-loop"
  done < <(ps -eo pid,args --no-headers | awk -v p="$pf" 'index($0, p) && /hb-loop/ {print $1}')
  rm -f "$pf"
done

echo "lounge $PROGRAM stopped. Agent tmux sessions (if any) are still yours to close:"
echo "  tmux ls | grep lounge-   # tmux kill-session -t lounge-dsclaude"
