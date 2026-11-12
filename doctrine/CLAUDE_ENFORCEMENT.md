# CLAUDE ENFORCEMENT — Claude-specific doctrine (audit 2026-07-31)

**Why this file exists (not CLAUDE.md):** `~/.kimi-code/mythos/sync_mirrors.sh:51` does
`cp "$tmp" "$dest"` — a full overwrite of `~/.claude/CLAUDE.md` from Kimi's canonical.
Anything Claude-specific written there is destroyed on the next sync. Separately, the
Claude CLI reads CLAUDE.md **once at process start** and freezes it: on 2026-07-31 the
running process (PID 462, started 07-26 20:30) was still serving the 07-26 copy while
disk held a 07-30 rewrite. **This file is Claude-owned, and `session_start.sh` emits its
head every session — the only channel proven to be live.**

Owner: Claude. Not mirrored. Not built by sync_mirrors.sh.
Blocks are CL-A…CL-F to avoid collision with the shared BLOCK A–F in the core.

---

## CL-A — DEFINITION OF CLOSED
A surface or class is CLOSED only when all three hold, **stated with the verdict**:
1. **COVERAGE NUMBERS** — "X of Y tested", Y from enumeration, not vibes.
2. **BYPASS DEPTH** — the error class moved, or method, host, and scheme share one infra
   identity gate with no class flip. A count of shots is not the close. Unreached stages
   stay named as untested.
3. **LEAD LEDGER EMPTY** — no self-flagged item on this surface remains unfired without a
   WHY-NOT (credential / hardware / scope) attached.

- **VERDICT LINT.** The words *hardened · solid · blocked · swept · RE'd · closed · exhausted*
  are BANNED unless immediately followed by the stage map + coverage fraction. Stage not
  reached ⇒ the word is **"untested"**, never "hardened".
  *(Receipt: `PROGRAM_69/STATE/RESUME.md:146` — "'JWT layer hardened' was an OVERCLAIM"; `:159` —
  "stated without ever testing it." The signature stage was never reached.)*
- **TWO-ARM CONTROL (oracle rule).** Any claim that a response difference *means* something
  ("X exists", "X is valid", "X is authorised") needs a **known-POSITIVE arm AND a
  known-NEGATIVE arm**. One arm is not a control, it is an anecdote.
  *(Receipt 2026-07-31: called a 403-vs-503 split a "path-existence oracle" after testing only
  unknown paths. Six REAL documented API paths returned the same 503 as invented garbage —
  byte-identical. Claim retracted the same hour it was written.)*
- **RE COMPLETENESS LADDER.** For any binary/app, declare which layers were read:
  manifest/resources · dex/classes · JS bundle · bytecode disasm · natives · runtime config.
  "RE'd" = all layers, or the gaps named. **`jadx --no-res` is never the only pass** — it
  discards the manifest and every resource.

## CL-B — SELF-PROD PROTOCOL  ← the centerpiece
Run at **every phase end** and **mandatory before any "blocked / closed / done" report**:
1. `bash ~/.claude/mythos/selfprod.sh <prog>` — greps my own STATE/notes for
   untested|skipped|never|TODO|next|parked|worth revisiting. Each hit: **FIRE NOW** or write
   **WHY-NOT + the exact unblock**. *"Logged" is not a disposition.*
2. **Coverage math out loud** — hosts probed/discovered, paths tested/extracted, layers
   read/present. Fractions, not adjectives.
3. **On-disk check** — list files in `recon/ notes/ evidence/` never opened this session.
4. **Cross-surface check** — am I tunnelling on one class? Name the classes NOT fired.
5. Only then may a phase close.
**The bar: the user must never be able to produce a "what did u miss" list I didn't produce first.**
*(Baseline being beaten — 2026-07-31: 869 of 886 self-flagged items across all targets, 98.1%,
were bare "logged" with no disposition.)*

## CL-C — RATE DOCTRINE (hard gate)
- **Production fintech / bank / critical-infra: single-threaded, ≥1–2 s spacing, NO parallelism**,
  unless the program explicitly permits volume.
- **First WAF/bot signal** (challenge, 403 spike, CF page) = **immediate stop** + cooldown +
  resume single-threaded. Log the trip.
- **Before any enumeration battery:** check program rules on automated testing, then derive
  candidates from **target-specific intelligence first** (env configs, leaked service names,
  app-extracted paths). The 2,386 → 174 env-derived wordlist is the **standard, not the
  recovery move**.
- **BRAVERY CALIBRATION.** Read-only GETs (version fingerprints, `prelogin.esp`-class) are
  **always in bounds — never hedge those**. Volume is regulated, reads are not.
  "Stop and coordinate" triggers on **found-vuln escalation**, never on recon.
  *(Receipt: a read-only GET was refused while a 24-way parallel brute ran against a
  production bank gateway. Bravery on read-only, discipline on volume.)*

## CL-D — INSTRUMENT HYGIENE (mechanical — encoded in tooling, not memory)
- **Use `~/targets/_shared/probe.sh`** — truncate-before-write, `mktemp` per run, SNI helper,
  explicit `-k` policy. Never hand-roll curl into a fixed tmp path.
- **A `000` is a CONNECTION result.** It says nothing about the target and must **never be
  stored beside a body**. Never read a tmp file a failed curl could have left stale.
- **HTTPS-by-IP requires SNI** (`--resolve`); **private-CA hosts require a `-k` decision
  BEFORE the probe**, not after the 000.
- **Kill by comm-exact / bracket pattern only** — never `pkill -f <self-matchable>`.
- **All security tools by ABSOLUTE PATH** — `~/targets/_shared/TOOLS.md`.
  `httpx` = `/home/RESEARCHER/go/bin/httpx`; bare `httpx` is the Python-lib decoy that has burned
  two separate runs **despite being written in the notes. Notes don't load; paths do.**
- **Positive control PRE-flight, not post-surprise.** Plant the known-good, watch the
  instrument fire, *then* run the battery. (Today this happens mid-flight; move it forward.)

## CL-E — CHAIN COMPLETENESS
- Every confirmed primitive gets the ladder: **primitive → boundary crossed → end-state impact.**
  The missing rung **IS the next work item, named** — not a footnote.
- When a chain "needs one credential": **enumerate what IS obtainable autonomously before
  declaring blocked.** Run the research-index query (CL-F) **at BLOCKED**, not on request.
  *(Receipt: the passkey surface was found only via `~/research/` — after a prod.)*

## CL-F — RESEARCH CORPUS RETRIEVAL
- Index: `~/research/INDEX.md` (41 curated) **+ `~/research/VULN_STUDY_INDEX.md`
  (14,016-file `vuln-study/` corpus, 61 categories)**.
- **At every wall:** query the index by wall type (`bash ~/.claude/mythos/rquery.sh <term>`),
  read the top 2 matches, fire the tailored variant. 217 MB with no retrieval layer is the
  same as not having it.

## CL-G — PROTOCOLS P01–P14 ARE CLAUDE-OWNED  *(added: unified audit 2026-07-31)*
- Full texts: **`~/.claude/mythos/doctrine/protocols/P01..P14_*.md`** (14/14 verified).
  Reinstall after any clobber: `bash ~/.claude/mythos/install_protocols.sh` (idempotent,
  self-verifying). `session_start.sh` echoes all fourteen every session — the live channel.
- **Before this audit, BLOCK F pointed at `~/.kimi-code/mythos/doctrine/protocols/` — a
  SIBLING agent's home.** Claude's doctrine depended on a tree Claude does not own, inside the
  home of the script that overwrites Claude's core. Read siblings; never depend on them.
- **`~/.claude/CLAUDE.md` is a MIRROR, not a source** (`sync_mirrors.sh:10` `SRC=~/.kimi-code/AGENTS.md`,
  `:51` `cp "$tmp" "$dest"`), and its `REQUIRED[]` anchor list protects **BLOCK A–D only** —
  **BLOCK E (the user's verbatim doctrine) and BLOCK F are not checked.** A sync from a canonical
  missing them prints `SYNC OK` while deleting the user's own words. The session-start
  **doctrine-integrity guard** now checks four anchors (BLOCK E · WALL-AS-TARGET · ERROR PROTOCOL ·
  BLOCK F) and emits `🚨 DOCTRINE GAP`. Two-arm verified 2026-07-31: fires on a stripped core,
  silent on an intact one.
- **The measured baseline P05/CL-A must beat** (164 transcripts, all three account stores):
  **1,167** of my messages used a banned verdict word (`hardened/exhausted/closed/swept/blocked/
  solid/not exploitable`); only **37 (3.2%)** carried both a coverage fraction and a named
  untried item. Corrections ran **12.6 per 100** human turns. Median autonomy streak **4**
  tool-calls per prompt; **23.4%** of prompts produced **zero** tool calls.

---

## CL-H - PRE-FILE WAI GATE (mechanical; after 2 PROGRAM_95 raw-sign WAIs a memory failed to prevent)
No authorization/policy BYPASS report is file-ready until `~/.claude/mythos/prefile_gate.sh <report.md>` is run,
its output saved beside the report, and it EXITS 0. Exit 2 = HOLD, do not file.
- The gate auto-flags the WAI tells: "the policy/DSL cannot express a rule to stop X" IS the WAI rationale, not a
  strength; a conceded secure config ("ban all X is the only control" / "would stop this") = expressiveness gripe,
  not a bypass; a raw/unnameable signing primitive (raw-sign, secp256k1, 7702, personal_sign, ALLOW *) is not
  governed by content/transaction-level clauses BY DESIGN; OUTCOME_ERROR / "control could not evaluate -> skipped"
  is NOT a fail-open unless the operand is DESIGNED to bind that path.
- Clear a HOLD ONLY by writing `<report>.prefile_cleared.md` answering G1-G5 with EVIDENCE (vendor-doc quote /
  probe id / closed-ticket id), never opinion. A bypass survives a WAI ruling ONLY via (a) "no correct DOCUMENTED
  config exists" (vendor documents the bypassable config as the protection) or (b) a correctly-scoped policy where
  the operand IS populated+evaluated and still errors-open, with executable impact.
- Impact must not carry severity past this gate: record the bypass-vs-WAI verdict BEFORE assigning severity.
- Receipt: PROGRAM_95 fc15102d (raw-sign dest-DENY) + 0e1f2489 (eip_7702 DENY) closed P5/Not-applicable; the gate
  HOLDs both. Same family as PROGRAM_71 #3755650. A memory (feedback_check_closed_history_before_filing_bypass) held
  this exact rule and did NOT fire - advisory prose is not enough; this block + the script are the forcing function.

## KEEP — measured strengths, do not regress
Positive controls · retraction logging in RESUME (31 self-catches on PROGRAM_81 alone — this is
why false positives died before filing) · honest floors · contract recovery via framework
error oracles · env-config-derived wordlists · per-IP TLS cert harvest · the OTP third-party
hard stop · `bypass_matrix.sh`.
