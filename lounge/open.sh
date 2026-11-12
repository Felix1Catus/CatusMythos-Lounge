#!/usr/bin/env bash
# Open a lounge seat in its own tmux session. Attach with:
#   tmux attach -t lounge-grok3
#   tmux attach -t lounge-dsclaude
# Usage: bash open.sh grok3 prober [PROGRAM_68]
set -euo pipefail
SEAT="${1:-}"
ROLE="${2:-}"
PROG="${3:-}"
[[ -n "$SEAT" && -n "$ROLE" ]] || { echo "usage: $0 <seat> <role> [program]" >&2; exit 2; }
NAME="lounge-${SEAT}"
TOOLKIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmux has-session -t "$NAME" 2>/dev/null && tmux kill-session -t "$NAME"
CMD="bash $TOOLKIT/go.sh $SEAT $ROLE ${PROG}"
tmux new-session -d -s "$NAME" -c "$HOME"
tmux send-keys -t "$NAME" "$CMD" C-m
echo "started $NAME"
echo "attach: tmux attach -t $NAME"
echo "detach: Ctrl-b d"
