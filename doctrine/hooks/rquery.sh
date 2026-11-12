#!/usr/bin/env bash
# rquery.sh — retrieval layer for ~/research (CL-F).  Audit 2026-07-31.
#
# WHY: ~/research holds 14,060 files / 217 MB. INDEX.md curated only 40 of them (0.3%);
# the 14,016-file vuln-study/ corpus had NO top-level index. 217 MB with no retrieval
# layer is the same as not having it — the passkey surface was found there only after a
# user prod. RULE: at every wall, query by wall type, read the top 2, fire the variant.
#
#   rquery.sh <term> [more terms]     # rank files by filename + heading matches
#   rquery.sh --cats                  # list corpus categories
set -uo pipefail
R="$HOME/research"
[[ -d "$R" ]] || { echo "no ~/research"; exit 2; }

if [[ "${1:-}" == "--cats" ]]; then
  echo "── curated (INDEX.md) ──"; ls -d "$R"/[0-9]* 2>/dev/null | xargs -r -n1 basename
  echo "── vuln-study ($(command find "$R/vuln-study" -type f | wc -l) files) ──"
  ls -d "$R"/vuln-study/*/ 2>/dev/null | xargs -r -n1 basename | column -c 100
  exit 0
fi
[[ $# -gt 0 ]] || { echo "usage: rquery.sh <term> [term...]   |   rquery.sh --cats"; exit 2; }

Q=$(printf '%s|' "$@"); Q="${Q%|}"

echo "════ rquery: '$*' ════"
echo
echo "── A. CURATED (~/research/INDEX.md — read these first, they carry PoC status) ──"
command grep -inE "$Q" "$R/INDEX.md" 2>/dev/null | head -12 | sed 's/^/   /'

echo
echo "── B. FILENAME MATCHES across the 14k corpus ──"
command find "$R" -type f -name '*.md' 2>/dev/null \
  | command grep -iE "$Q" | head -20 | sed "s|$HOME/research/|   |"

echo
echo "── C. CONTENT MATCHES (FULL corpus, top 15 by hit count) ──"
# Single pass over every .md — no sampling cap. An earlier version capped at 400 files
# (~3% of the corpus), which would have manufactured false negatives on exactly the
# queries this tool exists to answer.
command grep -rcE --include='*.md' -i "$Q" "$R" 2>/dev/null \
  | command grep -vE ':0$' \
  | awk -F: '{c=$NF; sub(/:[0-9]+$/,"",$0); printf "%6s %s\n", c, $0}' \
  | sort -rn | head -15 | sed "s|$HOME/research/|   |"

echo
echo "── NEXT: read the top 2, then fire the variant tailored to THIS target's stack. ──"
