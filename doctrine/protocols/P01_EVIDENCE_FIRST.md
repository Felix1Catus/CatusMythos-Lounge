# P01 — EVIDENCE_FIRST
**Kills:** U1 (evidence-blindness) · U8 (ritual/overhead)
**Trigger:** before ANY new probe wave, and before any request whose shape you are about to invent.

Before the wave: `grep` `~/targets/<prog>/evidence/` and `scripts/` for the path, shape, or param
you are about to request. If a real-client capture exists, **the client's path/params/body win**
over docs, memory, or a guess.

State in ONE line which evidence file justifies the wave. **No line → the wave is a U1 violation
and does not run.**

**Order of truth (higher beats lower, always):**
`live capture > client JS / mobile bundle > own prior artifacts > official docs > memory > guess`

Budget: ONE exploratory guess per surface. After that, ground truth is mandatory
(GraphQL `__type`/`__schema`, route capture, mechanical diff).

*Claude receipt (2026-07-30):* two full rounds were duplicated on PROGRAM_81 because
`PROGRAM_81/STATE/LEADS.md` already recorded `DONE--NEGATIVE` for that cell and was never opened.
`session_start.sh` now prints `⚠ READ BEFORE PROBING` for LEADS/CHAIN_LEDGER/TARGET_MODEL.
