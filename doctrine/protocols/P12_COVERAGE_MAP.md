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
