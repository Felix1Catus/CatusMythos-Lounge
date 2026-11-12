# P07 — BOARD_DISCIPLINE
**Kills:** U11 (context-amnesia) · U6 (overrotation)
**Trigger:** after every wave; before every compaction/restart; after every resume.

STATE files updated **after every wave**:
- floor / ceiling / missing-link
- active track
- next probe
- **negative results — disproven hypotheses are ASSETS.** Log them so they are never re-run.

Before compaction/restart: **checkpoint pointer written.**
After resume: **read the board in the same pass as the shot.**

**A hunt that cannot warm-boot from disk in under 2 minutes is misconfigured.**

Read-before-persist is a hard rule: read the state file, merge into current truth, then write.
Never append against a stale copy. `CHECKPOINT.md` carries a `_by:` marker — a cross-agent
marker means another agent's thread; reconcile, never clobber.
