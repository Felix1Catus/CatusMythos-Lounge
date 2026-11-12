#!/usr/bin/env bash
# seat_launcher.sh - start one PROJECT LOUNGE seat.
# Usage: bash seat_launcher.sh --program <slug> --seat <id> --role <ROLE>
#        [--doctrine-dir <path>] [--launch] [--grok-home <dir>]
#
# Seat id -> agent + account (matches your shell aliases):
#   grok / grok2 / grok3 / grok4   -> grok binary, GROK_HOME = ~/.grok / .grok2 / .grok3 / .grok4
#   claude / claude2 / claude3     -> claude binary, CLAUDE_CONFIG_DIR = ~/.claude / .claude-account2 / .claude-account3
#   dsclaude                       -> claude binary + DeepSeek backend (~/.claude-deepseek)
#
# Emits SEAT, writes the role card, ties the heartbeat to the agent process
# (hb-loop exits when the agent dies, so failover fires honestly).
# Default: prints the manual commands. --launch: runs the agent in the foreground.
set -uo pipefail

TOOLKIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRAM=""; SEAT_ID=""; ROLE="PROBER"; STATE_ROOT="$HOME/targets"; DOCTRINE_DIR=""; LAUNCH=0
GROK_HOME_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program) PROGRAM="$2"; shift 2 ;;
    --seat) SEAT_ID="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --state-root) STATE_ROOT="$2"; shift 2 ;;
    --doctrine-dir) DOCTRINE_DIR="$2"; shift 2 ;;
    --grok-home) GROK_HOME_ARG="$2"; shift 2 ;;
    --launch) LAUNCH=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$PROGRAM" && -n "$SEAT_ID" ]] || { echo "FATAL: --program and --seat required" >&2; exit 2; }
# wrappers once passed --role PROBER--launch; strip a glued --launch suffix
if [[ "$ROLE" == *"--launch" ]]; then ROLE="${ROLE%%--launch}"; LAUNCH=1; fi
ROLE="${ROLE%%--*}"
case "$ROLE" in
  RECON|PROBER|ANALYST|SKEPTIC) ;;
  *) echo "FATAL: --role must be RECON|PROBER|ANALYST|SKEPTIC (got '$ROLE')" >&2; exit 2 ;;
esac

RUNTIME="$STATE_ROOT/$PROGRAM/LOUNGE"
[[ -f "$RUNTIME/lounge.json" ]] || { echo "FATAL: lounge not installed for $PROGRAM. Run install.sh first." >&2; exit 1; }
export LOUNGE_DIR="$RUNTIME" SEAT_ID="$SEAT_ID" LOUNGE_JOINED=1
PY="$(command -v python3)"

# role card for this seat
"$PY" - "$RUNTIME" "$SEAT_ID" "$ROLE" "$TOOLKIT" <<'PYEOF'
import sys
rt, seat, role, toolkit = sys.argv[1:5]
card = f"""# SEAT {seat} - role {role}
lounge runtime: {rt}
protocol: {toolkit}/LOUNGE_PROTOCOL.md  (READ IT)
FIRST commands (do these before a 10-minute STATE read):
  export LOUNGE_DIR={rt} SEAT_ID={seat}
  python3 {toolkit}/seatlib.py status
  python3 {toolkit}/seatlib.py tail --since 0
  python3 {toolkit}/seatlib.py claim --cell 'METHOD /path AXIS'
  python3 {toolkit}/seatlib.py follow --since 0 --wait 8
  python3 {toolkit}/seatlib.py push --cell '<cell>' --note '<different axis the other seat should fire now>'
  python3 {toolkit}/seatlib.py inbox
  python3 {toolkit}/seatlib.py token
Exact cell is mutex. Sibling axes on the same path run together. A peer KILL is not a close.
Scripts: targets/<prog>/scripts/  (never /tmp)
"""
open(f'{rt}/seats/{seat}.md', 'w').write(card)
print(f'wrote role card {rt}/seats/{seat}.md')
PYEOF

# SEAT join event
# Drop stale inbox so the seat does not chase a sibling from an old run.
rm -f "$RUNTIME/inbox/$SEAT_ID.jsonl"
"$PY" - "$RUNTIME" "$SEAT_ID" << 'PY'
import sys
from pathlib import Path
rt, seat = sys.argv[1], sys.argv[2]
seq = Path(rt, "seq")
n = seq.read_text().strip() if seq.exists() else "0"
home = Path.home() / ".lounge"
home.mkdir(parents=True, exist_ok=True)
prog = Path(rt).parent.name
(home / f"{seat}.{prog}.seen").write_text(n or "0")
(home / f"{seat}.program").write_text(Path(rt).parent.name)
PY
"$PY" "$TOOLKIT/seatlib.py" --seat "$SEAT_ID" seat --role "$ROLE" --doctrine "$DOCTRINE_DIR"

# ---- agent selection + account mapping (grok AND claude/dsclaude) ----
GROK="$(command -v grok || true)"
CLAUDE="$(command -v claude || true)"
case "$SEAT_ID" in
  grok|grok2|grok3|grok4) AGENT=grok ;;
  claude|claude2|claude3|dsclaude) AGENT=claude ;;
  *) AGENT=grok ;;
esac

if [[ -z "$GROK_HOME_ARG" ]]; then
  case "$SEAT_ID" in
    grok) GROK_HOME_ARG="$HOME/.grok";; grok2) GROK_HOME_ARG="$HOME/.grok2";;
    grok3) GROK_HOME_ARG="$HOME/.grok3";; grok4) GROK_HOME_ARG="$HOME/.grok4";;
  esac
fi

CONFIG_DIR=""
case "$SEAT_ID" in
  claude) CONFIG_DIR="$HOME/.claude";;
  claude2) CONFIG_DIR="$HOME/.claude-account2";;
  claude3) CONFIG_DIR="$HOME/.claude-account3";;
  dsclaude) CONFIG_DIR="$HOME/.claude-deepseek";;
esac

# Every grok home starts in /home/RESEARCHER. go.sh idle path already passes --cwd.
GROK_CWD=(--cwd /home/RESEARCHER)
PIDFILE="$RUNTIME/seats/$SEAT_ID.pid"

launch_agent() {
  case "$AGENT" in
    grok)
      [[ -n "$GROK_HOME_ARG" ]] && export GROK_HOME="$GROK_HOME_ARG"
      "$GROK" "${GROK_CWD[@]}" "$@"
      ;;
    claude)
      if [[ "$SEAT_ID" == dsclaude ]]; then
        env CLAUDE_CONFIG_DIR="$CONFIG_DIR" \
            ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
            ANTHROPIC_AUTH_TOKEN="$(cat "$HOME/.deepseek-key")" \
            ANTHROPIC_MODEL="deepseek-v4-pro" \
            ANTHROPIC_SMALL_FAST_MODEL="deepseek-flash" \
            ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash" \
            CLAUDE_CODE_MAX_CONTEXT_TOKENS="1048576" \
            CLAUDE_CODE_AUTO_COMPACT_WINDOW="1000000" \
            CLAUDE_CODE_MAX_OUTPUT_TOKENS="393216" \
            "$CLAUDE" --effort high --dangerously-skip-permissions "$@"
      else
        env -u ANTHROPIC_BASE_URL -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_MODEL \
            -u ANTHROPIC_SMALL_FAST_MODEL -u ANTHROPIC_DEFAULT_HAIKU_MODEL \
            -u DEEPSEEK_API_KEY \
            CLAUDE_CONFIG_DIR="$CONFIG_DIR" "$CLAUDE" --dangerously-skip-permissions "$@"
      fi
      ;;
  esac
}

if [[ "$LAUNCH" == "1" ]]; then
  PROMPT="You are seat $SEAT_ID ($ROLE) on the PROJECT LOUNGE for program $PROGRAM.
READ these three files first, then begin:
  $TOOLKIT/MACHINE.md
  $TOOLKIT/LOUNGE_PROTOCOL.md
  $RUNTIME/seats/$SEAT_ID.md
LOUNGE_DIR=$RUNTIME and SEAT_ID=$SEAT_ID are already set in your environment.
You are one seat of a machine that finds criticals by collaboration.
Solo law is ~/.grok/rules/HUNTER_V5.md. On this table the other seat is your critic and your variant hunter. You still fire. They rerun and try to kill it.
Loop: GROUND -> hypo -> one shot -> reflect the class -> name the next chain.
The other seat is in another terminal. Do not repeat their cell. Do not hunt alone and stop.
First call: python3 $TOOLKIT/seatlib.py next
If next exits 2, that line is your shot. Then: python3 $TOOLKIT/seatlib.py follow --wait 2
Claim METHOD /path AXIS. claim exits 1 if denied: claim && hypo && shot.
reflect --sibling must be a full cell, for example POST /graphql DOCUMENT count.
A prose sibling is rejected. After every probe: reflect, then follow. A LIVE line is an interrupt.
token (no --op) before reads; it exits 1 if grant is false. A custom --op is a 60s mint lock.
Scripts under targets/$PROGRAM/scripts/.

When a peer KILLs an axis: that shape is dead. Immediately push a different chain
(sibling route, other type, nested field, second path, the check the fix missed).
Do not agree the surface is closed.

When you or they get 400, 401, 403, 404, or any block: push one structural bypass
this turn (omit the field, other type, sibling key, encoding, method). Same class
twice is not a close. Deepen until the class flips or you name the unfired check.

When one seat confirms a floor (class flip or a real object): both verify.
One reruns the one command. The other climbs ceiling (read, write, chain).
Do not persist and sit. Do not wait on a human-gated action (prod write, OTP,
submit, a key you do not have, mass other-tenant). Do not fire that action.
Chain a path that does not need it.

A same-app medium, a griefing flip, or a rerun of a report is not the ceiling. The other seat fires a different boundary: another app, no app secret, a sign the owner key did not make, or the sibling object that check forgot. A 401 or 404 on the same app does not finish it.
When that climb has a class: draft the report under targets/$PROGRAM/reports/
with the one command, the expected output, and what that output proves.
Pass the path with: emit --type REPORT --cell '<cell>' --note 'path=... poc=...'
The other seat reruns the PoC and answers REPORT-OK or REPORT-FIX.
Then both stop and wait. The operator is the only one who submits."
  if [[ "$PROGRAM" == PROGRAM_68 ]]; then
    PROMPT="$PROMPT
Header on every request: X-BB-Researcher: HackerOne-RESEARCHER."
  fi
  PROMPT="$PROMPT"
  echo "$$" > "$PIDFILE"
  "$PY" "$TOOLKIT/seatlib.py" --seat "$SEAT_ID" hb-loop --interval 5 --pidfile "$PIDFILE" >/dev/null 2>&1 &
  HB_PID=$!
  trap 'kill "$HB_PID" 2>/dev/null' EXIT
  if [[ "$AGENT" == grok ]]; then ACCT="account $GROK_HOME_ARG"; else ACCT="config $CONFIG_DIR"; fi
  echo "seat $SEAT_ID ($ROLE) launching ($ACCT). This terminal IS the seat; Ctrl-C ends it."
  launch_agent "$PROMPT"
else
  echo ""
  echo "WARNING: launched WITHOUT --launch. Conductor marks this seat dead in hb_dead_s"
  echo "(default 90s) unless hb-loop is running. Start it NOW, then start the agent:"
  echo "  echo \$\$ > $PIDFILE"
  echo "  python3 $TOOLKIT/seatlib.py --seat $SEAT_ID hb-loop --interval 5 --pidfile $PIDFILE &"
  echo "Preferred: bash $TOOLKIT/seat_launcher.sh --program $PROGRAM --seat $SEAT_ID --role $ROLE --launch"
fi
