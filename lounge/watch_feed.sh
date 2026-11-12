#!/usr/bin/env bash
# watch_feed.sh - operator's live view of the lounge transcript.
# Usage: bash watch_feed.sh --program <slug> [--state-root ~/targets]
set -uo pipefail
PROGRAM=""; STATE_ROOT="$HOME/targets"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --program) PROGRAM="$2"; shift 2 ;;
    --state-root) STATE_ROOT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PROGRAM" ]] || { echo "FATAL: --program required" >&2; exit 2; }
FEED="$STATE_ROOT/$PROGRAM/LOUNGE/feed.md"
[[ -f "$FEED" ]] || { echo "no feed yet at $FEED (conductor not running?)" >&2; exit 1; }
echo "LIVE FEED: $FEED  (Ctrl-C to leave)"
tail -n 60 -f "$FEED"
