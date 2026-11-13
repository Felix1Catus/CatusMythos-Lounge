#!/usr/bin/env bash
# MYTHOS PostToolUse — mechanical PERSIST nudge (Claude edition; advisory, never blocks)
# Fires after work-producing tools (Bash|Write|Edit matcher). If RESUME.md/GAP_PLAN.md were
# NOT updated in the last 120s, nudges on stdout (PostToolUse is observation-only; stdout may
# be appended to context — keep it to ONE line).
# LOCATION: ~/.claude/mythos/persist_nudge.sh
set -uo pipefail

source "$HOME/targets/_shared/lounge/mythos_gate.sh"

INPUT=$(cat || true)
LOG="$HOME/.claude/mythos/persist_nudge.log"
mkdir -p "$(dirname "$LOG")"

# Hunt-context gate: nudging during ordinary coding (no active target, cwd outside ~/targets)
# is spam that trains the agent to ignore the nudge. Only hunt work earns the nudge.
CWD=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("cwd") or "")
except Exception:
    print("")
' 2>/dev/null || echo "")
if [[ ! -s "$HOME/.claude/mythos/active_target" && "$CWD" != "$HOME/targets/"* ]]; then
  exit 0
fi

TOOL_NAME=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("tool_name") or d.get("toolName") or (d.get("tool") or {}).get("name", "") or "")
except Exception:
    print("")
' 2>/dev/null || echo "")

case "$TOOL_NAME" in
  Bash|Write|Edit) ;;
  *) exit 0 ;;
esac

# Skip pure noise commands (ls, pwd, echo, type, which, true)
if [[ "$TOOL_NAME" == "Bash" ]]; then
  CMD=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    tin = d.get("tool_input") or d.get("toolInput") or {}
    print((tin.get("command") or "")[:200])
except Exception:
    print("")
' 2>/dev/null || echo "")
  case "$CMD" in
    ls\ *|ls|pwd|echo\ *|type\ *|which\ *|true|false|date|whoami|id|uname*|cat\ *)
      exit 0
      ;;
  esac
fi

PERSISTED="false"
WINDOW_SEC=120
NOW=$(date +%s)
for marker in $(find "$HOME/targets" -maxdepth 4 \( -name RESUME.md -o -name GAP_PLAN.md -o -name CHECKPOINT.md \) 2>/dev/null) \
              "$HOME/RESUME.md" "$HOME/GAP_PLAN.md"; do
  [[ -f "$marker" ]] || continue
  MTIME=$(stat -c %Y "$marker" 2>/dev/null || echo 0)
  AGE=$((NOW - MTIME))
  if [[ $AGE -lt $WINDOW_SEC ]]; then
    PERSISTED="true"
    break
  fi
done

if [[ "$PERSISTED" == "true" ]]; then
  exit 0
fi

TIMESTAMP=$(date -Iseconds)
echo "[$TIMESTAMP] nudge: tool=$TOOL_NAME persisted=false" >> "$LOG"

echo "⚠️ MYTHOS PERSIST NUDGE: $TOOL_NAME ran but RESUME/GAP_PLAN/CHECKPOINT untouched in ${WINDOW_SEC}s. PERSIST to disk before the next item (trivial probes: ignore)."
exit 0
