#!/usr/bin/env bash
# MYTHOS active-target marker (Claude edition) — tells the auto-journal which program the
# current session is attacking, so actions that DON'T reference a targets/<prog>/ path
# (e.g. raw curl to a live host) still get filed to the right program's JOURNAL.
# Set this once when you start on a target. UNSET it when you stop hunting
# (path-less probes else misfile to a stale target):
#
#   mtarget.sh <program>     # set active target
#   mtarget.sh --clear       # unset (not hunting anymore)
#   mtarget.sh               # show current
#
# LOCATION: ~/.claude/mythos/mtarget.sh
set -uo pipefail
F="$HOME/.claude/mythos/active_target"
if [[ "${1:-}" == "--clear" ]]; then
    rm -f "$F"
    echo "active target cleared (journal now files only by explicit targets/<prog>/ paths)"
elif [[ -n "${1:-}" ]]; then
    prog="$1"
    if [[ ! -d "$HOME/targets/$prog" ]]; then
        echo "warn: ~/targets/$prog does not exist yet (will be created on first journal write)"
    fi
    printf '%s\n' "$prog" > "$F"
    echo "active target -> $prog   (journal + checkpoint now default to ~/targets/$prog/STATE/)"
else
    if [[ -f "$F" ]]; then echo "active target: $(cat "$F")"; else echo "active target: (none set)"; fi
fi
