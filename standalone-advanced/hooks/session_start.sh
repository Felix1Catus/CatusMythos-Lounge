#!/usr/bin/env bash
# MYTHOS SessionStart — creed + feedback queue + warm-boot pointer (Claude edition)
# Stdout is injected into context on SessionStart — keep it lean (~35 lines max).
# RESUME.md stays on-demand (read when resuming), never auto-dumped.
# LOCATION: ~/.claude/mythos/session_start.sh
set -uo pipefail

source "$HOME/targets/_shared/lounge/mythos_gate.sh"

LOG="$HOME/.claude/mythos/session_start.log"
mkdir -p "$(dirname "$LOG")"
TS=$(date -Iseconds)
echo "[$TS] SessionStart cwd=${PWD:-?}" >> "$LOG"

echo "◆ LOUNGE seat on $LOUNGE_PROG. Mythos serves this table. Error CLASS, not status. hypo, one shot, reflect, hand the sibling to the other seat. follow after the shot. OS: ~/.claude/CLAUDE.md. Machine: ~/targets/_shared/lounge/MACHINE.md"
echo "🎯 CRITICAL HUNTER — default goal = Critical path (ATO/RCE/cross-tenant/auth/money/mass). Not critical enough ⇒ chain or escalate. Every block: floor / ceiling / missing link. Proof ladder R0→R5: report at highest PROVEN rung."

# ── DOCTRINE FRESHNESS GUARD (audit 2026-07-31) ────────────────────────────────
# The CLI reads ~/.claude/CLAUDE.md ONCE at process start and freezes it; /clear does not
# re-read it. On 2026-07-31 the running process (started 07-26) was serving a 07-26 core
# while disk held a 07-30 rewrite — every fix from that audit was on disk and NOT in effect.
# This compares the core's mtime against the owning CLI process's start time and screams.
CORE="$HOME/.claude/CLAUDE.md"
if [[ -f "$CORE" ]]; then
  _p=$$; _cpid=""
  while [[ -n "$_p" && "$_p" -gt 1 ]]; do
    if [[ "$(ps -o comm= -p "$_p" 2>/dev/null | tr -d ' ')" == "claude" ]]; then _cpid="$_p"; break; fi
    _p=$(ps -o ppid= -p "$_p" 2>/dev/null | tr -d ' ')
  done
  if [[ -n "$_cpid" ]]; then
    _et=$(ps -o etimes= -p "$_cpid" 2>/dev/null | tr -d ' ')
    if [[ -n "$_et" ]]; then
      _start=$(( $(date +%s) - _et ))
      _cm=$(stat -c %Y "$CORE" 2>/dev/null || echo 0)
      if (( _cm > _start )); then
        echo "🚨 STALE CORE — ~/.claude/CLAUDE.md was modified $(( (_cm-_start)/3600 ))h AFTER this CLI started (pid $_cpid, up $(( _et/3600 ))h)."
        echo "   The doctrine in my context is NOT the doctrine on disk. READ $CORE NOW before trusting any core rule, and tell RESEARCHER to restart the CLI to load it properly."
      fi
    fi
  fi
fi

# ── CLAUDE ENFORCEMENT CONTRACT (live channel; survives sync_mirrors.sh clobber) ──
# sync_mirrors.sh:51 `cp "$tmp" "$dest"` overwrites CLAUDE.md wholesale from Kimi's canonical,
# so Claude-specific doctrine cannot live there. It lives in the file below and is echoed here.
if [[ -f "$HOME/.claude/mythos/CLAUDE_ENFORCEMENT.md" ]]; then
  echo "── CLAUDE ENFORCEMENT (full: ~/.claude/mythos/CLAUDE_ENFORCEMENT.md) ──"
  echo "CL-A CLOSED needs all 3, stated with the verdict: coverage fraction X/Y · ≥8 structural bypasses OR stage map w/ unreached stages named · lead ledger empty. VERDICT LINT: hardened/solid/blocked/swept/RE'd/closed BANNED without stage map + fraction — stage not reached ⇒ the word is 'untested'. TWO-ARM CONTROL: any 'this difference MEANS X' claim needs a known-POSITIVE arm AND a known-NEGATIVE arm — one arm is an anecdote, not a control. RE ladder: manifest·dex·JS·disasm·natives·config (jadx --no-res is never the only pass)."
  echo "CL-B SELF-PROD before ANY blocked/closed/done: run ~/.claude/mythos/selfprod.sh <prog> → every self-flagged item FIRES NOW or gets WHY-NOT+unblock ('logged' is not a disposition) · coverage math out loud · list recon/notes/evidence files never opened · name the classes NOT fired. Bar: RESEARCHER can never produce a 'what did u miss' list I didn't produce first."
  echo "CL-C RATE: prod fintech/bank/critical-infra = single-threaded, 1–2s spacing, NO parallelism. First WAF/bot signal = stop + cooldown + resume single-threaded. Derive wordlists from target intel FIRST (env configs/app paths) — 2386→174 is the standard, not the recovery. BRAVERY: read-only GETs are ALWAYS in bounds, never hedge them; volume is regulated, reads are not."
  echo "CL-D INSTRUMENT: use ~/targets/_shared/probe.sh (truncate+mktemp+SNI+explicit -k). A 000 is a CONNECTION result — never store it beside a body. Absolute paths only (httpx=/home/RESEARCHER/go/bin/httpx; bare httpx is the decoy that burned 2 runs). Positive control PRE-flight, not post-surprise. Never pkill -f self-matchable."
  echo "CL-E CHAIN: primitive → boundary crossed → end-state. Missing rung IS the next work item, named. 'Needs one credential' ⇒ enumerate what IS autonomously obtainable BEFORE declaring blocked; run the research query at BLOCKED, not on request."
  echo "CL-F RESEARCH: at every wall query the index — bash ~/.claude/mythos/rquery.sh <wall-type> (~/research/INDEX.md + VULN_STUDY_INDEX.md, 14k files) — read top 2, fire the tailored variant."
  echo "── end enforcement ──"
fi

# ── PROTOCOLS P01–P14 + TRAPS (unified audit 2026-07-31) ──────────────────────
# Boot order is deliberate: doctrine (above) → protocols (here) → traps → reference.
# Full texts are Claude-OWNED at ~/.claude/mythos/doctrine/protocols/ (NOT Kimi's home —
# the core's BLOCK F used to point across to a sibling's tree). Reinstall after any
# clobber with: bash ~/.claude/mythos/install_protocols.sh
PROTO="$HOME/.claude/mythos/doctrine/protocols"
if [[ -d "$PROTO" ]]; then
  _pn=$(ls "$PROTO"/P*.md 2>/dev/null | wc -l)
  echo "── PROTOCOLS P01–P14 ($_pn/14 on disk: $PROTO — full text on demand) ──"
  echo "P01 EVIDENCE_FIRST: grep evidence/+scripts/ BEFORE any wave; name the file that justifies it — no line, no wave. Truth: live capture>client JS>own artifacts>docs>memory>guess. · P02 NEW_PRIMITIVE: name the new primitive or don't run the set; identical class on the same shape is not a new primitive; loosen one axis before leaving. Stop only on an infra identity gate with no class flip. · P03 SELFTEST: known-answer two-arm test before consuming ANY instrument output; instrument contradicting client ground truth is WRONG until exonerated; 3rd fix ⇒ rebuild. · P04 LIVENESS: liveness call per wave/~25 authed reqs; first 401 ⇒ HALT, never analyse post-401 corpses. · P05 CEILING_BAN: exhausted/blocked/hardened/step-up is banned. Name the next request. A list of surfaces does not run before it."
  echo "P06 PROBE_BUDGET: money/state-mutating = 1 per mint, ≥60s, 429⇒2min cool, board entry BEFORE next; prod fintech single-threaded. Read-only GETs always in bounds. · P07 BOARD: STATE after EVERY wave (negatives are ASSETS); checkpoint before compaction; read the board in the same pass as the shot after resume; <2min warm-boot. · P08 SERVER_MODEL: maintain TARGET_MODEL = how the server thinks; hunt the delta — client-trusted values, parser diffs, out-of-order states, business trust, unentered error branches. · P09 DIVERGENCE: mutate STRUCTURE (type·sign·encoding·nesting/HPP·method·version-param·coercion), never iterate payloads; unpredicted behaviour IS the target. · P10 ERROR_ORACLE: every distinct error = one mapped branch; the UNMAPPED branch is where the 0day is; 5xx are leads, logged."
  echo "P11 CHAIN: every finding ⇒ floor·ceiling·missing-link, escalate to ceiling BEFORE celebrating the floor; class hit ⇒ horizontal sweep + second-order. · P12 COVERAGE_MAP: surface×class×status, timestamped; the map exists to find EMPTY cells — claim coverage only with empty cells listed. · P13 SELF_CATCH: T1–T16 after EVERY tool batch (T1 ceiling-word⇒P05 · T2 no-primitive⇒P02 · T3 grep-able⇒P01 · T4 401⇒P04 · T5 contradiction⇒P03 · T7 finding⇒P11 · T8 correction-words⇒stop+evidence-not-apology · T10 automate before asking · T11 praise⇒stricter not looser · T12 don't defend a model the evidence killed · T14 complete chain⇒draft SAME session · T15 horizontal sweep · T16 second-order). · P14 REPORT_WHEN_REAL: complete reproducible chain ⇒ draft same session; opener leads with the boundary that IS crossed."
  [[ -f "$HOME/targets/_shared/TRAPS.md" ]] && echo "TRAPS: ~/targets/_shared/TRAPS.md — machine-shared registry (httpx PATH decoy · stale /tmp · pkill self-match · SNI/-k · post=0 DevTools bodies · parse_qs '+' · CF GET-vs-POST + egress IP · frozen core). Read at first instrument surprise; APPEND when you find a new one."
fi

# ── DOCTRINE-INTEGRITY GUARD: did sync_mirrors.sh drop the user's verbatim law? ──
# sync_mirrors.sh's REQUIRED[] anchor list (lines 14-31) enforces BLOCK A-D only. BLOCK E
# (user-installed doctrine, verbatim) and BLOCK F (P01-P14) are NOT protected — a sync from a
# canonical missing them would report "SYNC OK" while silently deleting the user's own words.
if [[ -f "$CORE" ]]; then
  _missing=""
  grep -qF "BLOCK E — CANONICAL DOCTRINE" "$CORE" || _missing="${_missing} BLOCK-E(user-verbatim-doctrine)"
  grep -qF "WALL-AS-TARGET"               "$CORE" || _missing="${_missing} WALL-AS-TARGET"
  grep -qF "ERROR PROTOCOL"               "$CORE" || _missing="${_missing} ERROR-PROTOCOL"
  grep -qF "BLOCK F — PROTOCOLS"          "$CORE" || _missing="${_missing} BLOCK-F(P01-P14)"
  if [[ -n "$_missing" ]]; then
    echo "🚨 DOCTRINE GAP — ~/.claude/CLAUDE.md is missing:${_missing}"
    echo "   sync_mirrors.sh does NOT protect these anchors. The protocol texts above are still"
    echo "   authoritative ($PROTO). Tell RESEARCHER the canonical core lost the user-installed doctrine."
  fi
fi

# Feedback priority queue (last mistakes — do not repeat). Head only.
if [[ -f "$HOME/.claude/feedback/priority.md" ]]; then
  # Head trimmed 25→12 lines (audit 2026-07-31) to pay for the enforcement contract above.
  # Lines 1-8 are maintenance boilerplate re-read every session for no benefit; the pinned
  # #1 entry starts at the "## #1" heading. Full queue stays one Read away.
  echo "── FEEDBACK PRIORITY #1 PINNED (full: ~/.claude/feedback/priority.md) ──"
  sed -n '/^## #1/,/^## #2/p' "$HOME/.claude/feedback/priority.md" | head -n 12
  echo "── end feedback head ──"
fi
if [[ -f "$HOME/.claude/feedback/hunt_doctrine.md" ]]; then
  # FULL, not head -n 15 (fixed 2026-10-15). The file is 66 lines / 9 rules; head -n 15
  # delivered rules 1, 2 and the top of 3 — rules 4-9 (validate the instrument · don't
  # burn the proof channel · dig to the ceiling · attack what the target processes ·
  # NEVER REFRAIN FROM FIRING · THE WALL IS THE TARGET) never reached a session.
  echo "── HUNT DOCTRINE (full — 9 rules) ──"
  cat "$HOME/.claude/feedback/hunt_doctrine.md"
  echo "── end hunt doctrine ──"
fi

# Warm-boot is the lounge program, not active_target.
PROG="$LOUNGE_PROG"
CK="$HOME/targets/$PROG/STATE/CHECKPOINT.md"
if [[ -n "$PROG" ]]; then
  :
  if [[ -n "$PROG" && -f "$CK" ]]; then
    echo "════════ WARM-BOOT — active target: $PROG ════════"
    echo "Full trail: bash ~/.claude/mythos/resume.sh $PROG  (re-verify PROVEN with a fresh probe)"
    cat "$CK"
    # Coverage/queue artifacts — MUST be read before probing, or you WILL re-derive
    # work another session already did. (2026-07-30: two full rounds duplicated on PROGRAM_81
    # because LEADS.md's coverage ledger already said DONE--NEGATIVE and was never opened.)
    SD="$HOME/targets/$PROG/STATE"
    for A in LEADS.md CHAIN_LEDGER.md TARGET_MODEL.md; do
      [[ -s "$SD/$A" ]] && echo "  ⚠ READ BEFORE PROBING: $SD/$A  ($(date -r "$SD/$A" '+%m-%d %H:%M'))"
    done
    # Anything on disk newer than RESUME.md = another session's work not folded in yet.
    if [[ -f "$SD/RESUME.md" ]]; then
      NEW=$(find "$HOME/targets/$PROG" -newer "$SD/RESUME.md" -type f \
            \( -name '*.md' -o -name '*.json' \) 2>/dev/null | grep -v '/STATE/' | head -5)
      [[ -n "$NEW" ]] && { echo "  ⚠ NEWER THAN RESUME.md (fold in FIRST):"; echo "$NEW" | sed 's/^/      /'; }
    fi
  fi
fi

exit 0
