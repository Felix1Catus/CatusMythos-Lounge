#!/usr/bin/env bash
# MYTHOS newtarget — scaffold ~/targets/<prog>/ with the full STATE structure and templates.
# Idempotent: never overwrites an existing file (skips with a note).
#   newtarget.sh <program>
# LOCATION: ~/.claude/mythos/newtarget.sh
set -uo pipefail

PROG="${1:-}"
if [[ -z "$PROG" ]]; then
    echo "usage: newtarget.sh <program>" >&2
    exit 2
fi

TROOT="$HOME/targets/$PROG"
SDIR="$TROOT/STATE"
TPL="$HOME/.claude/mythos/templates"

mkdir -p "$SDIR" "$TROOT"/{scripts,notes,results,evidence,recon}
chmod 700 "$TROOT/evidence" 2>/dev/null || true

# COVERAGE.md added by the unified audit 2026-07-31: P12 had ZERO instances across all 46
# programs with a STATE/ dir, because no template existed and nothing provisioned one.
for t in SCOPE.md TARGET_MODEL.md LEADS.md CHAIN_LEDGER.md COVERAGE.md RESUME.md GAP_PLAN.md; do
    if [[ -f "$SDIR/$t" ]]; then
        echo "skip (exists): $SDIR/$t"
    elif [[ -f "$TPL/$t" ]]; then
        sed "s/{PROG}/$PROG/g" "$TPL/$t" > "$SDIR/$t"
        echo "created: $SDIR/$t"
    else
        echo "warn: template missing: $TPL/$t" >&2
    fi
done

echo "dirs: $TROOT/{STATE,scripts,notes,results,evidence,recon}"
echo "next: bash ~/.claude/mythos/mtarget.sh $PROG  — then ground, then hunt."
