# P13 — SELF_CATCH
**Kills:** all U-classes (this is the runtime enforcement layer)
**Trigger:** after EVERY tool batch, and before EVERY response.

## Tripwires — check after every tool batch
- **T1** About to write *exhausted / only X remains / blocked / hardened / step-up*?
  → **P05 fires**: under-dug list of ≥5 + next probe each, or the word does not ship.
- **T2** Mutation set with no named new primitive? → **P02 fires**: do not run it.
- **T3** About to probe something that is grep-able in `evidence/`? → **P01 fires**.
- **T4** First 401 of a wave? → **P04 fires**: halt; do not analyse corpses.
- **T5** Instrument output contradicts client ground truth? → **P03 fires**: the instrument is
  wrong until exonerated.
- **T6** Third consecutive fix on the same instrument? → rebuild the self-test from scratch.
- **T7** Finding just logged? → **P11 fires**: floor / ceiling / missing-link NOW.
- **T8** User message contains correction words? → stop the current thread, re-read the board,
  answer the correction **with evidence, not apology**.
- **T9** About to claim coverage? → **P12**: cells timestamped? empty cells listed? Else it is a
  claim, not coverage.
- **T10** About to ask the user for anything automatable? → automate it first. The torch is
  **only** headed-browser capture, and only with a self-tested instrument.

## Pre-response checklist
Every claim has a receipt? · severity honest (floor=floor, candidate=candidate)? · board updated? ·
next probe named? · negative results logged?

## Proactive tripwires (no receipt yet — do not wait for one)
- **T11 Praise-inflation.** After praise, severity claims get *stricter*, not looser.
- **T12 Sunk-cost theory defence.** Evidence contradicts the model → **update the model**, do not
  explain the evidence away.
- **T13 Coverage-map decay.** A map written once and never maintained is a lie with a timestamp.
- **T14 Report procrastination.** A COMPLETE reproducible chain gets drafted the same session.
  Dig-not-file never means sitting on a finished Critical.
- **T15 Horizontal-sweep omission.** Found a class on one endpoint and never swept the surface?
- **T16 Second-order amnesia.** First-order clean ⇒ stored / reflected / deferred variants still
  untested.
