# P06 — PROBE_BUDGET
**Kills:** U10 (rate/scope indiscipline)
**Trigger:** any payment-, money-, or state-mutating endpoint; any enumeration battery.

- **One attempt per mint. ≥60 s spacing.**
- **429 → cool ≥2 minutes.**
- **Board entry written BEFORE the next attempt.**
- Cheap discriminators before expensive sprays.
- Production fintech / bank / critical-infra: **single-threaded, ≥1–2 s spacing, NO parallelism**
  unless the program explicitly permits volume. First WAF/bot signal = stop, cool down, resume
  single-threaded, log the trip.
- Derive candidate lists from **target-specific intelligence first** (env configs, leaked service
  names, app-extracted paths). The 2,386 → 174 env-derived wordlist is the **standard, not the
  recovery move**.

Probes are finite. Spend them only on new primitives (P02).

**Bravery calibration (the other direction):** read-only GETs are **always in bounds** — never
hedge them. Volume is regulated; reads are not. "Stop and coordinate" triggers on found-vuln
escalation, never on recon.
