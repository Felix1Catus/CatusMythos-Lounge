#!/usr/bin/env bash
# selfprod.sh — the SELF-PROD PROTOCOL, mechanised (CL-B).  Audit 2026-07-31.
#
# WHY: measured 2026-07-31 across ~/targets — 869 of 886 self-flagged items (98.1%) were
# bare "logged" with NO disposition. Every prod-dependence incident (issuer wall, PROGRAM_78,
# APK/dex RE, passkey surface, bypass matrix, X-Forwarded/CORS matrices, Hermes disasm)
# was self-flagged BEFORE the user asked for it. This script produces the "what did u miss"
# list so RESEARCHER never has to.
#
# RUN: at every phase end, and MANDATORY before writing "blocked" / "closed" / "done".
#   bash ~/.claude/mythos/selfprod.sh <program>
set -uo pipefail
PROG="${1:-}"
[[ -n "$PROG" ]] || { echo "usage: selfprod.sh <program>   (dir under ~/targets)"; exit 2; }
D="$HOME/targets/$PROG"
[[ -d "$D" ]] || { echo "no such target: $D"; exit 2; }

SKIP='/(\.venv|site-packages|node_modules|src_dump|decompile|__pycache__|apk_[a-z]*)/'
FLAG='untested|not tested|never (tested|swept|run|tried|fired)|TODO|parked|worth revisiting|not yet|would pull|unfired|to test|should test|need to test|next probe|next step'
WHYNOT='WHY-?NOT|blocked by|needs? (a )?(credential|hardware|account|device|second account|human|scope)|out of scope|human-gated|\[STATUS: BLOCKED\]'

# SCAFFOLD: a gate that flags its own paperwork gets ignored. Excludes GAP_PLAN template
# checkboxes, markdown headings/bold-only labels, the 'Classes NOT fired' disclosure (that
# line IS the disposition), and '___' stubs. (PROGRAM_101 2026-07-31: 16/16 'bare' = scaffolding.)
SCAFFOLD='___|^[0-9]+:#{1,6} |^[0-9]+:\*\*[A-Za-z][^*]*\*\*:?$|Classes NOT fired|A BLOCKED without its|^[0-9]+:- \[ \] \[STATUS: TODO\] (SCOPE\.md|verticals|passive asset|live-client RE|TARGET_MODEL\.md|LEADS\.md|active chain|R5 narrative|report drafted|lead:)'

prose(){ command find "$D" -maxdepth 3 -type f -name '*.md' 2>/dev/null | command grep -vE "$SKIP"; }

echo "════════ SELF-PROD — $PROG — $(date -u +%Y-%m-%dT%H:%MZ) ════════"

echo
echo "── 1. SELF-FLAGGED ITEMS: fire now, or write WHY-NOT + the exact unblock ──"
echo "   ('logged' is NOT a disposition)"
n=0; nb=0
while IFS= read -r f; do
  while IFS= read -r line; do
    n=$((n+1))
    if command grep -qiE "$WHYNOT" <<<"$line"; then d="WHY-NOT ok"; else d="** BARE — DISPOSE **"; nb=$((nb+1)); fi
    printf '   [%s] %s\n        %.160s\n' "$d" "${f#$D/}" "$(sed 's/^[[:space:]]*//' <<<"$line")"
  done < <(command grep -inE "$FLAG" "$f" 2>/dev/null | command grep -viE '\[STATUS: DONE' \
           | command grep -vE "$SCAFFOLD" | head -12)
done < <(prose)
echo "   ── $n flagged · $nb BARE (each bare item = fire it or justify it, now)"

echo
echo "── 2. COVERAGE MATH (fractions, not adjectives) ──"
for pat in 'hosts' 'httpx' 'subdomain' 'paths' 'endpoint'; do
  hits=$(command find "$D" -maxdepth 3 -type f \( -name "*${pat}*" -o -name "*${pat^}*" \) 2>/dev/null | command grep -vE "$SKIP" | head -6)
  [[ -n "$hits" ]] && while IFS= read -r h; do
      printf '   %-58s %8s lines\n' "${h#$D/}" "$(wc -l <"$h" 2>/dev/null||echo ?)"
    done <<<"$hits"
done
echo "   -> state probed/discovered, tested/extracted, layers read/present OUT LOUD."

echo
echo "── 3. ON-DISK FILES NEVER OPENED THIS SESSION ──"
J="$HOME/.claude/mythos/journal/$(date +%F).ndjson"
TOUCHED=$(mktemp); : > "$TOUCHED"
[[ -f "$J" ]] && command grep -oE '/home/RESEARCHER/targets/[^"'"'"' ,)]+' "$J" 2>/dev/null | sort -u > "$TOUCHED"
un=0
while IFS= read -r f; do
  command grep -qxF "$f" "$TOUCHED" 2>/dev/null || { printf '   UNOPENED  %10s  %s\n' "$(du -h "$f" 2>/dev/null|cut -f1)" "${f#$D/}"; un=$((un+1)); }
done < <(command find "$D"/recon "$D"/notes "$D"/evidence -maxdepth 2 -type f -size +2k 2>/dev/null | command grep -vE "$SKIP" | head -40)
echo "   ── $un candidate files on disk not touched today. Open them or say why not."
rm -f "$TOUCHED"

echo
echo "── 4. CLASS ROTATION — which classes were NOT fired on this target? ──"
for c in SQLi NoSQL command-injection LDAP XPath XSS SSRF IDOR BOLA authn-bypass JWT session \
         RBAC tenant-isolation CSRF deserialization SSTI XXE file-upload path-traversal \
         open-redirect race TOCTOU mass-assignment type-juggling parser-differential \
         business-logic secrets dependency-CVE cache-deception request-smuggling; do
  h=$(prose | xargs -r command grep -ilE "\b${c//-/[ -]}\b" 2>/dev/null | wc -l)
  [[ "$h" -eq 0 ]] && printf '   NOT FIRED: %s\n' "$c"
done
echo "   -> name each NOT-FIRED class in the ledger with a reason, or fire it."

echo
echo "── 5. GATE ──"
echo "   A phase may close only when 1 has zero BARE items, 2 is stated as fractions,"
echo "   3 is empty or justified, and 4 is named in the ledger."
echo "   Bar: RESEARCHER must never be able to produce a 'what did u miss' list I didn't produce first."
