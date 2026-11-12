#!/usr/bin/env bash
# MYTHOS WARM-BOOT reader (Claude edition) — reconstruct exactly where a dead session was.
# Prints, for a program: the CHECKPOINT intent head, the last N mechanical JOURNAL actions
# (what actually ran + result class), a pointer to the narrative RESUME.md, and live infra.
#
#   resume.sh <program> [N]     # default N=30 actions
#   resume.sh                    # uses active_target, else lists resumable programs
#
# LOCATION: ~/.claude/mythos/resume.sh   Writers: journal.py (auto), checkpoint.py (intent)
set -uo pipefail
TROOT="$HOME/targets"
ACTIVE_FILE="$HOME/.claude/mythos/active_target"

PROG="${1:-}"
N="${2:-30}"

if [[ -z "$PROG" && -f "$ACTIVE_FILE" ]]; then
    PROG=$(head -1 "$ACTIVE_FILE" 2>/dev/null | tr -d '[:space:]')
fi

if [[ -z "$PROG" ]]; then
    echo "═══════════ MYTHOS WARM-BOOT — no program given ═══════════"
    echo "Resumable programs (most-recent action first):"
    for j in $(ls -t "$TROOT"/*/STATE/JOURNAL.ndjson 2>/dev/null); do
        p=$(basename "$(dirname "$(dirname "$j")")")
        last=$(tail -1 "$j" 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("ts",""),"|",d.get("sum","")[:70])' 2>/dev/null)
        n=$(wc -l < "$j" 2>/dev/null | tr -d " ")
        printf "  %-16s %4s actions   last: %s\n" "$p" "$n" "$last"
    done
    echo
    echo "Run:  resume.sh <program>   to reconstruct that one."
    exit 0
fi

SDIR="$TROOT/$PROG/STATE"
echo "═══════════ MYTHOS WARM-BOOT — $PROG ═══════════"
echo "> Trust the JOURNAL + a fresh probe over any stale narrative. Re-verify the last PROVEN line before building on it."
echo

# 1) intent head
if [[ -f "$SDIR/CHECKPOINT.md" ]]; then
    echo "──────── CHECKPOINT (intent: where / heading / what / how) ────────"
    cat "$SDIR/CHECKPOINT.md"
    echo
else
    echo "──────── CHECKPOINT: (none yet — dead session never wrote one) ────────"
    echo
fi

# 2) mechanical action trail
if [[ -f "$SDIR/JOURNAL.ndjson" ]]; then
    TOTAL=$(wc -l < "$SDIR/JOURNAL.ndjson" | tr -d " ")
    echo "──────── LAST $N of $TOTAL ACTIONS (auto-journal — what actually ran) ────────"
    tail -n "$N" "$SDIR/JOURNAL.ndjson" | python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    ts = d.get("ts", "")[11:19]
    tool = d.get("tool", "")[:6]
    ok = d.get("ok")
    flag = "  " if ok is None else ("ok" if ok else "XX")
    sm = d.get("sum", "")[:96]
    out = d.get("out", "")
    tail = f"   -> {out[:60]}" if out else ""
    print(f"  {ts} {flag} {tool:<6} {sm}{tail}")
'
    echo
else
    echo "──────── JOURNAL: (none — no actions recorded for $PROG) ────────"
    echo
fi

# 3) narrative pointer + live infra
if [[ -f "$SDIR/RESUME.md" ]]; then
    MT=$(date -r "$SDIR/RESUME.md" '+%Y-%m-%d %H:%M' 2>/dev/null || echo unknown)
    echo "──────── NARRATIVE ────────"
    echo "  full story: $SDIR/RESUME.md   (last updated $MT — READ it if the checkpoint is thin)"
fi

# 3b) COVERAGE + QUEUE — read these BEFORE probing. RESUME.md is narrative; these are the
# anti-duplication record. Skipping them cost two full rounds on PROGRAM_81 (2026-07-30).
echo "──────── COVERAGE / QUEUE (read before probing) ────────"
for A in LEADS.md CHAIN_LEDGER.md TARGET_MODEL.md GAP_PLAN.md; do
    if [[ -s "$SDIR/$A" ]]; then
        printf '  %-17s %s\n' "$A" "$(date -r "$SDIR/$A" '+%Y-%m-%d %H:%M')"
        [[ "$A" == "LEADS.md" ]] && grep -iE '^- |DONE|NEGATIVE|STATUS:' "$SDIR/$A" 2>/dev/null | head -8 | sed 's/^/      /'
    else
        printf '  %-17s MISSING — scaffold it (bash ~/.claude/mythos/newtarget.sh %s)\n' "$A" "$PROG"
    fi
done
# Work newer than RESUME.md = another session that did not fold in. Fold it in FIRST.
if [[ -f "$SDIR/RESUME.md" ]]; then
    NEWER=$(find "$HOME/targets/$PROG" -newer "$SDIR/RESUME.md" -type f \
            \( -name '*.md' -o -name '*.json' \) 2>/dev/null | grep -v '/STATE/' | head -8)
    if [[ -n "$NEWER" ]]; then
        echo "  ⚠⚠ FILES NEWER THAN RESUME.md — another session's work, FOLD IN BEFORE PROBING:"
        echo "$NEWER" | sed 's/^/      /'
    fi
fi
INFRA=$(pgrep -af 'remote-debugging-port=922|canary_server|interactsh-client|mitmproxy|mitmdump' 2>/dev/null \
    | grep -vE 'pgrep|type=renderer|crashpad' | sed -E 's/ +/ /g' | cut -c1-90)
echo "  live infra now: ${INFRA:-none}"
echo "═══════════════════════════════════════════════════════════════"
