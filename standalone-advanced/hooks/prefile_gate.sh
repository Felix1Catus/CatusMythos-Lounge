#!/usr/bin/env bash
# prefile_gate.sh - MANDATORY pre-file gate for any authorization/policy BYPASS report.
# Built 2026-10-13 after two PROGRAM_95 raw-sign reports (fc15102d, 0e1f2489) closed P5/Not-applicable
# as WAI - the lesson existed in memory (feedback_check_closed_history_before_filing_bypass) and did
# NOT fire. A memory is advisory; this is the forcing function. Run it, SAVE the output beside the
# report, and HOLD on any WAI-RISK until every gate is cleared WITH EVIDENCE (doc quote / probe id),
# not opinion.
#
# Usage:  prefile_gate.sh <report.md>
# Exit:   0 = no bypass-WAI tells OR a cleared-evidence file exists; 2 = WAI-RISK, HOLD.

set -uo pipefail
R="${1:-}"
[[ -z "$R" || ! -f "$R" ]] && { echo "usage: prefile_gate.sh <report.md>"; exit 3; }

G="command grep -niE"   # line-numbered, case-insensitive
hit() { $G "$1" "$R" 2>/dev/null; }
any() { $G "$1" "$R" >/dev/null 2>&1; }

echo "=================================================================="
echo " PRE-FILE GATE  :  $R"
echo " (bypass-vs-WAI gate - clear EVERY flag with EVIDENCE before filing)"
echo "=================================================================="

RISK=0

echo; echo "-- TELL 1: 'the policy/DSL cannot express a rule to stop X' (= the WAI rationale, not a strength)"
if any 'no (destination )?field|cannot restrict|can.?t restrict|DSL has no|no (policy )?(field|condition|operand)|unrestrictable|ungovernable|no correct (dest|config)|not what a .* expresses'; then
  hit 'no (destination )?field|cannot restrict|can.?t restrict|DSL has no|no (policy )?(field|condition|operand)|unrestrictable|ungovernable|no correct (dest|config)|not what a .* expresses'
  echo "  >> FLAG: this phrasing IS the WAI rationale. Survives ONLY via 'no correct DOCUMENTED config exists'."
  RISK=1
else echo "  (none)"; fi

echo; echo "-- TELL 2: report CONCEDES a secure config exists (self-defeating)"
if any 'only complete control|banning all|ban all|deny (the )?(activity|kind)|would stop this|is the only'; then
  hit 'only complete control|banning all|ban all|deny (the )?(activity|kind)|would stop this|is the only'
  echo "  >> FLAG: a secure config is conceded => expressiveness gripe, not a bypass, UNLESS the vendor"
  echo "          DOCUMENTS the bypassable config as the protection for the legit-use scenario. Attach that doc quote or HOLD."
  RISK=1
else echo "  (none)"; fi

echo; echo "-- TELL 3: unnameable/raw signing primitive or permissive-config precondition (cross-program dead vein)"
if any 'raw.?sign|sign_raw|secp256k1|rides ALLOW|ALLOW \*|unnameable|eip_7702|personal_sign|eth_signtypeddata'; then
  hit 'raw.?sign|sign_raw|secp256k1|rides ALLOW|ALLOW \*|unnameable|eip_7702|personal_sign|eth_signtypeddata'
  echo "  >> FLAG: matches the PROGRAM_71 #3755650 / PROGRAM_95 raw-sign WAI family. A raw/unnameable primitive is"
  echo "          not governed by content/transaction-level clauses BY DESIGN. Near-certain WAI."
  RISK=1
else echo "  (none)"; fi

echo; echo "-- TELL 4: 'OUTCOME_ERROR / control could not evaluate -> skipped' framed as fail-open"
if any 'OUTCOME_ERROR|fails? open|fail-open|skipped|errors? out|could not (be )?evaluat'; then
  hit 'OUTCOME_ERROR|fails? open|fail-open|skipped|errors? out|could not (be )?evaluat'
  echo "  >> FLAG: an eval-error is NOT a fail-open unless the operand is DESIGNED to bind that path."
  echo "          REQUIRED to survive: (a) a vendor-doc line that the operand binds this path, OR"
  echo "          (b) a CORRECTLY-SCOPED policy where the operand IS populated+evaluated and still errors-open."
  RISK=1
else echo "  (none)"; fi

echo
echo "=================================================================="
echo " MANDATORY GATES - answer each with EVIDENCE (doc quote / probe id / closed-ticket id), not opinion:"
echo "  G1 DUP/CLOSED-HISTORY: grepped this target's KILL_LOG + FILED_REPORTS + the cross-program WAI"
echo "     families (PROGRAM_71 #3755650, PROGRAM_95 raw-sign)? {same primitive + same discriminator + same"
echo "     'can't restrict' framing} = dup-risk. ALSO dedup by SHARED DOWNSTREAM BEHAVIOR / SAME FIX, not just"
echo "     trigger: vendors bundle every finding whose remediation is identical (e.g. all OUTCOME_ERROR-fails-open"
echo "     triggers = one bucket - PROGRAM_95 pre-rejected a distinct, verified trigger on 2026-10-13). A new trigger"
echo "     for an already-submitted behavior is a dup. Evidence: ____"
echo "  G2 INTENT: for any OUTCOME_ERROR/skip finding, is the operand DESIGNED to bind this path? Doc line: ____"
echo "  G3 SECURE-CONFIG: does a correct config exist (even if it also blocks legit use)? If yes, does the"
echo "     vendor DOCUMENT the bypassable config as the protection? Doc quote or DOWNGRADE: ____"
echo "  G4 BYPASS-vs-WAI recorded BEFORE severity? (impact must not carry severity past this gate) y/n: ____"
echo "  G5 PROVEN FLOOR: strongest arm that is NOT WAI (e.g. correctly-scoped fail-open w/ executable impact): ____"
echo "=================================================================="

CLEARED="${R%.md}.prefile_cleared.md"
if [[ $RISK -eq 1 ]]; then
  if [[ -f "$CLEARED" ]]; then
    echo " WAI-RISK detected, but cleared-evidence file exists: $CLEARED"
    echo " VERDICT: proceed only if that file answers G1-G5 with evidence."
    exit 0
  fi
  echo " VERDICT: *** HOLD *** - WAI-RISK tells present and no cleared-evidence file."
  echo " To clear: write $CLEARED answering G1-G5 with evidence, then re-run. Do NOT file until this passes."
  exit 2
fi
echo " VERDICT: no bypass-WAI tells detected. Still answer G1-G5 if this is an authz/policy finding."
exit 0
