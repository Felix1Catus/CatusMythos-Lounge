#!/usr/bin/env bash
# install_protocols.sh — (re)install P01–P14 into Claude's OWN doctrine tree.
#
# WHY THIS IS A SCRIPT AND NOT 14 HAND-WRITTEN FILES:
#   This machine destroys doctrine two ways — sync_mirrors.sh:51 overwrites ~/.claude/CLAUDE.md
#   wholesale from Kimi's canonical, and the CLI freezes the core at process start. Doctrine
#   that cannot be re-materialised on demand is doctrine that will silently disappear.
#   Run this after any clobber:  bash ~/.claude/mythos/install_protocols.sh
#
# Idempotent. Verifies after writing. Exit 1 if any file failed to land.
# Owner: Claude. Not mirrored, not built by sync_mirrors.sh.
# Installed by the unified hunter self-audit, 2026-07-31.
set -uo pipefail

D="$HOME/.claude/mythos/doctrine/protocols"
mkdir -p "$D"

w() { cat > "$D/$1"; }

w P01_EVIDENCE_FIRST.md <<'EOF'
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
EOF

w P02_NEW_PRIMITIVE.md <<'EOF'
# P02 — NEW_PRIMITIVE
**Kills:** U5 (circle) · U8 (ritual/overhead)
**Trigger:** before running any mutation set / battery / sweep.

Name the **NEW PRIMITIVE** the set tests — a class, field, rail, oracle, or behavioural anomaly
never before observed on this surface. **No named new primitive → do not run the set.** Update
the board instead and take the next lead.

- ONE active track at a time.
- After every wave: write **class-counts** to the board.
- Class-counts identical to the previous wave → **STOP the thread**, take the next P1.

A battery that re-proves an error ladder you already mapped is not evidence, it is spend.
EOF

w P03_INSTRUMENT_SELFTEST.md <<'EOF'
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
EOF

w P04_STATE_LIVENESS.md <<'EOF'
# P04 — STATE_LIVENESS
**Kills:** U7 (state-blindness)
**Trigger:** before every authed wave, and every ~25 authed requests.

One cheap liveness call. On **401**:
1. **HALT IMMEDIATELY.**
2. Mark every artifact after that point **"post-token-death"**.
3. Re-auth.
4. Resume only with fresh state.

**Never analyse responses received after the first 401.** They are corpses; reading them
manufactures false negatives.

Same discipline for every other piece of mutable state: **egress IP** (log it — a sudden wall of
429/000 is your own burn until proven otherwise), file locks, browser profile dirs, cookie jars.
Verify before assuming.
EOF

w P05_CEILING_BAN.md <<'EOF'
# P05 — CEILING_BAN
**Kills:** U3 (premature closure)
**Trigger:** the moment you are about to write or say *exhausted · only X remains · blocked ·
hardened · closed · swept · needs human step-up · not exploitable*.

Those words are **BANNED** unless the SAME message contains:
1. a written **under-dug list of ≥5 untried surfaces**, each with why it is Critical-shaped, AND
2. the **single next probe** for each.

A wall report without an under-dug list is a U3 violation. **Walls are maps.**

Reinforced by CL-A (verdict lint): the banned word additionally requires the **stage map** and a
**coverage fraction X/Y** from enumeration, not vibes. Stage not reached ⇒ the word is
**"untested"**, never "hardened".

*Claude receipt (measured 2026-07-31 over 164 transcripts):* **1,167** of my messages used a
banned verdict word; only **37 (3.2%)** carried both a coverage fraction and a named untried
item. User receipts: *"NO I BELIEVE YOU JUST DIDNT TRY HARD ENOUGH"* (07-24),
*"these negatives does not mean it's blcoked ... it's just says you are not smart enough"* (07-26),
*"see i got an sqli at PROGRAM_94 :) told you u didnt try hard enough"* (07-20) — the user found a
Critical on a surface I had closed.
EOF

w P06_PROBE_BUDGET.md <<'EOF'
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
EOF

w P07_BOARD_DISCIPLINE.md <<'EOF'
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
EOF

w P08_SERVER_MODEL.md <<'EOF'
# P08 — SERVER_MODEL
**Kills:** U12 (checklist-trap)
**Trigger:** before the first probe of every session; after every response that surprises you.

Per program maintain `STATE/TARGET_MODEL.md` — **how the server thinks**, inferred from its own
client and its own responses: trust boundaries · where identity is established and where it is
(or is not) re-checked · what is recomputed server-side vs trusted from the client · state
machines · enum maps · error branches.

**Every response either confirms or UPDATES the model.**

0days live in the **delta between the model and the implementation**. Hunt:
- **(a) values the server trusts from the client without recomputation.**
  *(The canonical find: `promotionEvaluation` recomputed the apps but NOT `totalDelta` — located
  by discriminator probes, not by luck. That is the method.)*
- **(b) two code paths validating the same input differently** — parser/normaliser differentials.
- **(c) states reachable out of order** — race/TOCTOU, step-skips.
- **(d) business-model trust** — invitation, deposit, non-pay, enterprise flows.
- **(e) branches your error ladder mapped but never entered.**

Review the model before the session's first probe.
EOF

w P09_DIVERGENCE_ENGINE.md <<'EOF'
# P09 — DIVERGENCE_ENGINE
**Kills:** U12 (checklist-trap) · U5 (circle)
**Trigger:** any interesting endpoint; any time you are about to iterate payloads.

**Mutation is STRUCTURAL, not payload iteration.** Generate across every axis:

| axis | mutations |
|---|---|
| type | int → string → bool → null → array → object |
| sign / magnitude | 0, negative, overflow, float, scientific notation |
| encoding | URL, double-URL, unicode, normalisation, case, whitespace/control chars |
| structure | nesting, duplicate keys / HPP, array ↔ object, content-type swap |
| method | full method matrix (405 vs 400 vs 404 separates routing from parsing) |
| version params | `source` → `sourceV2` — an ignored-looking enum was the load-bearing differential |
| coercion boundaries | `"08"`, `"8.0"`, `"+8"`, tab, trailing bytes |

**LOOSEN (user doctrine, verbatim law):** *"you are too strict in your bypasses and payloads and
attacks — loosen a bit; the server behaves unpredictably, and that is how the most novel bugs are
found."* **Unpredicted behaviour is the TARGET, not noise.**

Known-payload wordlists are the floor, never the ceiling. `' OR 1=1` is a confession you did not
look — fingerprint the stack first, then craft for that exact implementation.
EOF

w P10_ERROR_ORACLE.md <<'EOF'
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
EOF

w P11_CHAIN_DISCIPLINE.md <<'EOF'
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
EOF

w P12_COVERAGE_MAP.md <<'EOF'
# P12 — COVERAGE_MAP
**Kills:** U12 (checklist-trap) · U6 (overrotation/narrowness)
**Trigger:** before claiming any form of coverage; at every phase end.

Per program keep a living ledger:

**surface** (endpoints × params) × **class** × **status**

Classes: idor · mutation · injection · xss · rce · xxe · lfi · sqli · ssti · ssrf · race · logic ·
authz · authn · upload · deserialization · parser-diff · business-logic · leak.
Status: `untested` · `tested-held` · `tested-weak` · `oracle-open`.

**Never leave a tiny detail untested. Never assume.**

Checklisting = filling cells mechanically. **The map exists to find the EMPTY cells and the
ANOMALOUS ones**, not to feel complete.

**Stale maps are lies — timestamp every cell.** Claim coverage only with the empty cells listed;
otherwise it is a claim, not coverage.
EOF

w P13_SELF_CATCH.md <<'EOF'
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
EOF

w P14_REPORT_WHEN_REAL.md <<'EOF'
# P14 — REPORT_WHEN_REAL
**Kills:** U4 (overclaim oscillation)
**Trigger:** a chain is complete and reproducible.

**Draft the report the SAME SESSION**: steps, evidence paths, honest severity, scope statement.

*"Dig not file"* means **do not file junk and do not stop digging**. It never means sitting on a
finished Critical, and it never means polishing Mediums to feel productive.

**Opener leads with the trust boundary that IS crossed.** ZERO concession language in the
severity line. All disclaimers go in a *"What this report does NOT claim"* section **below** the
findings.
*(Receipt: VRP 515695470 and 515754412 both opened by naming what was NOT crossed. Both Won't Fix —
the triager quoted the report's own opener back as the rejection, and four strong cross-boundary
arguments below were never read.)*

Independent bugs file **separately**; one report = one chain. Bundling lets a dupe eat the novel
finding.

**Only the human submits.**
EOF

# ── verify ────────────────────────────────────────────────────────────────────
fail=0
for n in P01_EVIDENCE_FIRST P02_NEW_PRIMITIVE P03_INSTRUMENT_SELFTEST P04_STATE_LIVENESS \
         P05_CEILING_BAN P06_PROBE_BUDGET P07_BOARD_DISCIPLINE P08_SERVER_MODEL \
         P09_DIVERGENCE_ENGINE P10_ERROR_ORACLE P11_CHAIN_DISCIPLINE P12_COVERAGE_MAP \
         P13_SELF_CATCH P14_REPORT_WHEN_REAL; do
  f="$D/$n.md"
  if [[ -s "$f" ]] && grep -q '^\*\*Kills:\*\*' "$f" && grep -q '^\*\*Trigger:\*\*' "$f"; then
    printf '  OK   %-28s %5d B\n' "$n" "$(wc -c < "$f")"
  else
    printf '  FAIL %-28s\n' "$n"; fail=1
  fi
done
if [[ $fail -eq 0 ]]; then
  echo "PROTOCOLS OK — 14/14 installed at $D"
else
  echo "PROTOCOL INSTALL FAILED"; exit 1
fi
