# P03 — INSTRUMENT_SELFTEST
**Kills:** U2 (instrument-trust)
**Trigger:** before consuming ANY instrument output, and before handing any instrument to the user.

No instrument output is consumed until it passes a **logged known-answer self-test**:
- capture hook fetches a known URL → `hook active=ok`
- parser round-trips a known sample
- browser driver produces a screenshot as proof
- probe tooling: `~/targets/_shared/probe.sh --selftest`, `bypass_matrix.sh --selftest`,
  `python3 ~/targets/_shared/probelib.py` (3 arms, PASS required)

**An instrument whose output contradicts client ground truth is WRONG until exonerated.**
**Third fix on the same instrument in one session → stop patching. Rebuild the self-test from scratch.**

**TWO ARMS OR IT IS AN ANECDOTE.** A self-test needs a known-POSITIVE arm *and* a
known-NEGATIVE arm. A control arm returning `000` makes the control INCONCLUSIVE, not passing.

*Claude receipt (2026-07-31, this audit):* a literal-string grep for the receipt phrase
`"didnt miss anything"` returned 0. The real utterance was *"you sure you did not miss anything"*.
The instrument, not the corpus, was wrong — 4 categories moved 0 → non-zero after the fix.
