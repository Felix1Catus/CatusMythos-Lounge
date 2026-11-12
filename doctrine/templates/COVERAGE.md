# COVERAGE MAP — {PROG}   (P12)
_Created by newtarget.sh. **Timestamp every cell you touch — a stale map is a lie.**_

> **This map exists to find the EMPTY cells and the ANOMALOUS ones, not to feel complete.**
> Filling cells mechanically is checklisting (U12). Claim coverage ONLY with the empty cells
> listed — otherwise it is a claim, not coverage (P12/CL-A).
> Status vocabulary — use ONLY these: `untested` · `tested-held` · `tested-weak` · `oracle-open`
> `tested-weak` = the defence bent (interesting error / timing / partial). `oracle-open` = a
> distinguishable signal exists and is unexploited — **these are the leads, work them first.**

## Enumeration denominator (fill this FIRST — it is the Y in "X of Y")
- surfaces discovered: ____   · how enumerated: ____________________
- endpoints extracted: ____   · from: (client JS / mobile bundle / docs / capture) ____
- params extracted:    ____
- **Coverage fraction may never be quoted without this block filled.**

## Matrix
One row per surface (host/route group). Mark the cell, then date it `status@MM-DD`.

| surface | idor | authz | authn | mutation/mass-assign | injection (sqli/nosql/cmd) | xss | ssti | xxe | lfi/traversal | rce/deser | ssrf | race/TOCTOU | business-logic | parser-diff | upload | leak/disclosure |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| _(surface)_ | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested |

## EMPTY CELLS — the actual work queue
List every `untested` cell that is Critical-shaped, newest first. This is what P05 demands when
any closure word is used.

| surface × class | why Critical-shaped | next probe (exact) |
|---|---|---|
| | | |

## ORACLE-OPEN — distinguishable signals not yet exploited
| surface × class | the signal | what it would prove | next probe |
|---|---|---|---|
| | | | |

## Classes NOT fired this phase (and why)
_Rotation check — name them, don't silently skip them._
