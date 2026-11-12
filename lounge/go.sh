#!/usr/bin/env bash
# One command per seat.
#   grok3 prober                 launch the role and WAIT. No target, no probes.
#   grok3 prober PROGRAM_68          you named the target: join that lounge and attack.
#   dsclaude prober
#   grok analyst
set -euo pipefail
TOOLKIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEAT="${1:-}"
ROLE_RAW="${2:-}"
PROG="${3:-}"

ROLE="${ROLE_RAW,,}"
case "$ROLE" in
  recon) ROLE=RECON ;;
  prober) ROLE=PROBER ;;
  analyst) ROLE=ANALYST ;;
  skeptic) ROLE=SKEPTIC ;;
  *)
    echo "usage: $SEAT <recon|prober|analyst|skeptic> [program]" >&2
    exit 2
    ;;
esac

# No program: start the agent idle. The operator names the target in the first message.
if [[ -z "$PROG" ]]; then
  export LOUNGE_SEAT="$SEAT" LOUNGE_ROLE="$ROLE"
  unset LOUNGE_DIR || true
  PROMPT="You are seat $SEAT ($ROLE) on the PROJECT LOUNGE.
No target is loaded. Do not guess one. Do not read STATE, do not join a lounge, do not probe, do not open a program directory.
Wait. The operator will name the program in a message (example: PROGRAM_68).
When they do, and only then, run:
  bash $TOOLKIT/go.sh $SEAT ${ROLE,,} <program>
That joins ~/targets/<program>/LOUNGE with the other seats. Then read
  $TOOLKIT/MACHINE.md
  $TOOLKIT/LOUNGE_PROTOCOL.md
and attack with them: GROUND, hypo, one shot, reflect. A peer HYPO or REFLECT is your next shot.
Until that name arrives, your only reply is that you are waiting for the target."
  echo "seat $SEAT role $ROLE — waiting for a target"
  case "$SEAT" in
    grok) GROK_HOME="$HOME/.grok" ;;
    grok2) GROK_HOME="$HOME/.grok2" ;;
    grok3) GROK_HOME="$HOME/.grok3" ;;
    grok4) GROK_HOME="$HOME/.grok4" ;;
    *) GROK_HOME="" ;;
  esac
  if [[ "$SEAT" == dsclaude ]]; then
    exec env CLAUDE_CONFIG_DIR="$HOME/.claude-deepseek" \
      ANTHROPIC_BASE_URL="https://api.deepseek.com/anthropic" \
      ANTHROPIC_AUTH_TOKEN="$(cat "$HOME/.deepseek-key")" \
      ANTHROPIC_MODEL="deepseek-v4-pro" \
      ANTHROPIC_SMALL_FAST_MODEL="deepseek-flash" \
      ANTHROPIC_DEFAULT_HAIKU_MODEL="deepseek-flash" \
      CLAUDE_CODE_MAX_CONTEXT_TOKENS="1048576" \
      CLAUDE_CODE_AUTO_COMPACT_WINDOW="1000000" \
      CLAUDE_CODE_MAX_OUTPUT_TOKENS="393216" \
      claude --effort high --dangerously-skip-permissions "$PROMPT"
  elif [[ "$SEAT" == claude || "$SEAT" == claude2 || "$SEAT" == claude3 ]]; then
    case "$SEAT" in
      claude) CFG="$HOME/.claude" ;;
      claude2) CFG="$HOME/.claude-account2" ;;
      claude3) CFG="$HOME/.claude-account3" ;;
    esac
    exec env CLAUDE_CONFIG_DIR="$CFG" claude "$PROMPT"
  else
    export GROK_HOME
    exec grok --cwd /home/RESEARCHER "$PROMPT"
  fi
fi

RUNTIME="$HOME/targets/$PROG/LOUNGE"
if [[ ! -f "$RUNTIME/lounge.json" ]]; then
  echo "no lounge at $RUNTIME" >&2
  echo "install: bash $TOOLKIT/install.sh --program $PROG" >&2
  exit 1
fi

PIDFILE="$RUNTIME/conductor.pid"
_conductor_alive() {
  local pf="$1" pid cmd
  [[ -f "$pf" ]] || return 1
  pid=$(tr -d ' \n' < "$pf" 2>/dev/null) || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
  [[ "$cmd" == *conductor.py* ]]
}
if ! _conductor_alive "$PIDFILE"; then
  nohup python3 "$TOOLKIT/conductor.py" --lounge "$RUNTIME" >> "$RUNTIME/conductor.log" 2>&1 &
  echo $! > "$PIDFILE"
  for _i in 1 2 3 4 5; do
    _conductor_alive "$PIDFILE" && break
    sleep 0.2
  done
fi

echo "seat $SEAT role $ROLE program $PROG"
exec bash "$TOOLKIT/seat_launcher.sh" --program "$PROG" --seat "$SEAT" --role "$ROLE" --launch
