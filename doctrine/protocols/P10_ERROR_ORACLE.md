# P10 — ERROR_ORACLE
**Kills:** U12 (checklist-trap) · U2 (instrument-trust)
**Trigger:** every distinct error string, every 5xx, every status you have not seen on this surface.

**Every distinct error class = one mapped internal branch.** Maintain the ladder, e.g.
`opaque 400 → promotion_evaluation_mismatch → needs_engineering_work → use_alternate →
malformed_payment → 201 + action`.

For each branch record:
- what input shape **selects** it,
- what it **reveals** about the pipeline,
- which **adjacent branch is unprobed**.

**The UNMAPPED branch is where the 0day is.**

5xx / crash oracles are **leads**, logged with a repro — never discarded.

**ERROR PROTOCOL (user doctrine, verbatim law):** for any 4xx ask *"what does this server want?"*
before *"is this blocked?"* — replicate the real client's request byte-for-byte from its own JS;
vary **method first** (405 vs 400 vs 404 separates routing from parsing); test whether **omitting**
the param changes the error — if not, the fault is **upstream** of that param; only then sweep
values. Same for all 5xx.
