#!/usr/bin/env bash
# install.sh - PROJECT LOUNGE installer. Idempotent: safe to run twice.
# Usage: bash install.sh --program <slug> [--seats 3] [--state-root ~/targets] [--doctrine-dir <path>]
set -uo pipefail

TOOLKIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRAM=""
SEATS=3
STATE_ROOT="$HOME/targets"
DOCTRINE_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --program) PROGRAM="$2"; shift 2 ;;
    --seats) SEATS="$2"; shift 2 ;;
    --state-root) STATE_ROOT="$2"; shift 2 ;;
    --doctrine-dir) DOCTRINE_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$PROGRAM" ]] || { echo "FATAL: --program required" >&2; exit 2; }

echo "== discover =="
PY="$(command -v python3)" || { echo "FATAL: python3 absent" >&2; exit 1; }
PYVER="$("$PY" -c 'import sys; print("%d.%d" % (sys.version_info[0], sys.version_info[1]))')"
[[ "$( "$PY" -c 'import sys; print(1 if sys.version_info >= (3,8) else 0)' )" == "1" ]] || { echo "FATAL: python3 >= 3.8 required (got $PYVER)" >&2; exit 1; }
BASH_BIN="$(command -v bash)"
FLOCK_BIN="$(command -v flock)" || FLOCK_BIN="(absent)"
INOTIFY="$(command -v inotifywait)" || INOTIFY="(absent - poll fallback)"
echo "python3=$PY ($PYVER)  bash=$BASH_BIN  flock=$FLOCK_BIN  inotifywait=$INOTIFY"

RUNTIME="$STATE_ROOT/$PROGRAM/LOUNGE"
echo "== runtime = $RUNTIME =="

mkdir -p "$RUNTIME"/{lock,claims,hb,inbox,archive,seats,state,gate_ok}
chmod 700 "$RUNTIME"

CFG="$RUNTIME/lounge.json"
if [[ -f "$CFG" ]]; then
  echo "lounge.json exists - verifying, not clobbering (merge hb_dead_s if missing)"
  "$PY" - "$CFG" "$PROGRAM" <<'PY' || { echo "FATAL: existing lounge.json invalid or mismatched" >&2; exit 1; }
import json, sys
p, prog = sys.argv[1], sys.argv[2]
c = json.load(open(p))
assert c['program']==prog
c.setdefault('hb_dead_s', 90)
json.dump(c, open(p,'w'), indent=2)
print('config ok:', c['seats'], 'seats, rate', c['rate_per_s'], '/s, hb_dead_s', c['hb_dead_s'])
PY
else
  "$PY" - "$CFG" "$PROGRAM" "$SEATS" "$STATE_ROOT" "$DOCTRINE_DIR" "$TOOLKIT" <<'PYEOF'
import json, sys
cfg_path, program, seats, state_root, doctrine, toolkit = sys.argv[1:7]
cfg = {
  "program": program, "seats": int(seats), "state_root": state_root,
  "rate_per_s": 0.5, "hb_dead_s": 90, "toolkit": toolkit, "doctrine_dir": doctrine or "",
}
json.dump(cfg, open(cfg_path, 'w'), indent=2)
print("wrote", cfg_path)
PYEOF
fi

# start conductor (idempotent: reuse pid if it is actually conductor.py)
_conductor_alive() {
  local pf="$1" pid cmd
  [[ -f "$pf" ]] || return 1
  pid=$(tr -d ' \n' < "$pf" 2>/dev/null) || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
  [[ "$cmd" == *conductor.py* ]]
}
PIDFILE="$RUNTIME/conductor.pid"
CLOG="$RUNTIME/conductor.log"
if _conductor_alive "$PIDFILE"; then
  echo "conductor already running (pid $(cat "$PIDFILE"))"
else
  nohup "$PY" "$TOOLKIT/conductor.py" --lounge "$RUNTIME" > "$CLOG" 2>&1 &
  echo $! > "$PIDFILE"
  sleep 1
  _conductor_alive "$PIDFILE" && echo "conductor started (pid $(cat "$PIDFILE"))" || { echo "FATAL: conductor failed to start; log:" >&2; tail -5 "$CLOG" >&2; exit 1; }
fi

echo "== smoke: 2 fake seats, same cell -> one GRANT one DENY =="
S1="smoke-1"; S2="smoke-2"; CELL="SMOKE /probe $(date +%s)"
export LOUNGE_DIR="$RUNTIME"
R1=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S1" seat --role RECON)
R2=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S2" seat --role PROBER)
sleep 1
V1=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S1" claim --cell "$CELL")
V2=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S2" claim --cell "$CELL")
echo "S1 verdict: $(echo "$V1" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')"
echo "S2 verdict: $(echo "$V2" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')"
"$PY" "$TOOLKIT/seatlib.py" --seat "$S1" release --cell "$CELL" >/dev/null

T1=$(echo "$V1" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')
T2=$(echo "$V2" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')
if [[ "$T1 $T2" == "CLAIM-GRANTED CLAIM-DENIED" || "$T1 $T2" == "CLAIM-DENIED CLAIM-GRANTED" ]]; then
  echo "SMOKE PASS: one GRANT, one DENY"
else
  echo "SMOKE FAIL: got $T1 / $T2" >&2
  exit 1
fi

echo "== smoke: sibling axes GRANT, coarse DENY =="
A1="POST /graphql smoke$$ fields"
A2="POST /graphql smoke$$ count"
COARSE="POST /graphql"
VA=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S1" claim --cell "$A1")
sleep 1
VB=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S2" claim --cell "$A2")
VC=$("$PY" "$TOOLKIT/seatlib.py" --seat "$S1" claim --cell "$COARSE")
TA=$(echo "$VA" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')
TB=$(echo "$VB" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')
TC=$(echo "$VC" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("type"))')
echo "axis1 $TA axis2 $TB coarse $TC"
"$PY" "$TOOLKIT/seatlib.py" --seat "$S1" release --cell "$A1" >/dev/null
"$PY" "$TOOLKIT/seatlib.py" --seat "$S2" release --cell "$A2" >/dev/null
if [[ "$TA" == "CLAIM-GRANTED" && "$TB" == "CLAIM-GRANTED" && "$TC" == "CLAIM-DENIED" ]]; then
  echo "SMOKE PASS: sibling axes together, coarse denied"
else
  echo "SMOKE FAIL axes: $TA $TB coarse=$TC" >&2
  exit 1
fi

echo "== smoke: token CLI exits 1 when grant is false =="
"$PY" "$TOOLKIT/seatlib.py" --seat "$S1" token >/dev/null
set +e
"$PY" "$TOOLKIT/seatlib.py" --seat "$S1" token >/dev/null
TE=$?
set -e
if [[ "$TE" -ne 0 ]]; then
  echo "SMOKE PASS: token exit $TE on empty bucket"
else
  echo "SMOKE FAIL: token exited 0 on empty bucket" >&2
  exit 1
fi

echo ""
echo "LOUNGE ready for program '$PROGRAM' ($SEATS seats)."
echo "  toolkit : $TOOLKIT"
echo "  runtime : $RUNTIME"
echo "  feed    : tail -f $RUNTIME/feed.md"
echo "  start   : bash $TOOLKIT/seat_launcher.sh --program $PROGRAM --seat grok3 --role PROBER --launch"
echo "  watch   : bash $TOOLKIT/watch_feed.sh --program $PROGRAM"
echo "  stop    : bash $TOOLKIT/stop.sh --program $PROGRAM"
