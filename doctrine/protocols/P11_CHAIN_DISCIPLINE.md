# P11 — CHAIN_DISCIPLINE
**Kills:** U3 (premature closure) · U6 (overrotation/narrowness)
**Trigger:** the instant any finding is confirmed.

Every finding gets three lines, written immediately:
- **FLOOR** — what is proven, at the proven rung, no inflation.
- **CEILING** — the highest impact this primitive could reach.
- **MISSING-LINK** — the single next probe that closes floor → ceiling.

**Escalate every primitive to its ceiling before celebrating the floor.**

**First hit of any vuln class → horizontal sweep of that class across the whole mapped surface**,
then second-order variants (stored / reflected / deferred) before the cell is closed.

*"Not critical enough — chain or escalate"* is the default response to your own findings, not a
verdict handed down by the user.

Proof ladder: R0 hypothesis → R1 anomaly → R2 primitive → R3 boundary crossed → R4 end-state
impact → R5 report-ready narrative. Report at the highest **PROVEN** rung; name the gap, never
claim the next rung.
