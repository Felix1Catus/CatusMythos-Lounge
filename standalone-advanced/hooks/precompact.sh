#!/usr/bin/env bash
# MYTHOS PreCompact — checkpoint + auto-flush un-persisted state (Claude edition)
# Fires before Kimi compacts context (matcher: manual|auto). Logs + marks RESUME.md if any
# target notes are newer than it. Return values are ignored by Kimi on PreCompact — disk is
# the only channel, so the marker goes INTO the file the next session reads.
# LOCATION: ~/.claude/mythos/precompact.sh
set -uo pipefail

LOG="$HOME/.claude/mythos/compaction.log"
mkdir -p "$(dirname "$LOG")"
TIMESTAMP=$(date -Iseconds)

INPUT=$(cat || true)
CWD=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(str(d.get("cwd") or "").replace("\\", "/"))
except Exception:
    print("")
' 2>/dev/null || echo "")
TRIGGER=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("trigger") or d.get("matcher") or "")
except Exception:
    print("")
' 2>/dev/null || echo "")

FLUSHED=""
LATEST_NOTE=""
LATEST_MTIME=0

for note in $(find "$HOME/targets" -maxdepth 4 -name "*.md" -mmin -5 2>/dev/null | head -20); do
  MTIME=$(stat -c %Y "$note" 2>/dev/null || echo 0)
  if [[ $MTIME -gt $LATEST_MTIME ]]; then
    LATEST_MTIME=$MTIME
    LATEST_NOTE=$note
  fi
done 2>/dev/null || true

if [[ -n "$LATEST_NOTE" ]]; then
  RESUME_DIR=$(dirname "$LATEST_NOTE")
  while [[ "$RESUME_DIR" != "$HOME" && "$RESUME_DIR" != "/" ]]; do
    if [[ -f "$RESUME_DIR/RESUME.md" ]]; then
      R_MTIME=$(stat -c %Y "$RESUME_DIR/RESUME.md" 2>/dev/null || echo 0)
      if [[ $LATEST_MTIME -gt $R_MTIME ]]; then
        FLUSH_MARKER="[$TIMESTAMP] AUTO-FLUSH (Kimi PreCompact ${TRIGGER:-?}): un-persisted work at ${LATEST_NOTE} (newer than RESUME.md). PERSIST before context is lost."
        echo "" >> "$RESUME_DIR/RESUME.md"
        echo "$FLUSH_MARKER" >> "$RESUME_DIR/RESUME.md"
        FLUSHED="yes"
      fi
      break
    fi
    RESUME_DIR=$(dirname "$RESUME_DIR")
  done
fi

# ── P07 CHECKPOINT POINTER (unified audit 2026-07-31) ─────────────────────────
# P07 BOARD_DISCIPLINE: "Before compaction/restart: checkpoint pointer written."
# This hook previously only appended a marker to RESUME.md, and only when a note happened
# to be <5 min old — so a compaction during a long analysis stretch left NO trace of where
# the thread was. Post-resume, session_start.sh cats CHECKPOINT.md, so stamping the
# compaction into CHECKPOINT.md is what actually gets read on the way back in.
CKPT_NOTE=""
AT="$HOME/.claude/mythos/active_target"
if [[ -f "$AT" ]]; then
  PROG=$(head -1 "$AT" 2>/dev/null | tr -d '[:space:]')
  CK="$HOME/targets/$PROG/STATE/CHECKPOINT.md"
  if [[ -n "$PROG" && -f "$CK" ]]; then
    # Append-only, read-before-write safe: never rewrites existing fields.
    {
      echo ""
      echo "<!-- COMPACTION ${TIMESTAMP} (${TRIGGER:-?}) — context was compacted here."
      echo "     P07: read this board in the same pass as the shot. A status-only dead line is reopened."
      echo "     Re-verify the PROVEN line with ONE fresh probe before building on it. -->"
    } >> "$CK"
    CKPT_NOTE="stamped $CK"
  fi
fi

{
  echo "[$TIMESTAMP] PreCompact fired (${TRIGGER:-?}) | cwd: ${CWD:-?}"
  if [[ -n "$FLUSHED" ]]; then
    echo "  AUTO-FLUSH: appended marker to RESUME.md"
  else
    echo "  No un-persisted work detected."
  fi
  if [[ -n "$CKPT_NOTE" ]]; then
    echo "  CHECKPOINT: $CKPT_NOTE"
  else
    echo "  CHECKPOINT: no active target set (mtarget.sh <prog>) — nothing stamped."
  fi
  echo "---"
} >> "$LOG"

exit 0
