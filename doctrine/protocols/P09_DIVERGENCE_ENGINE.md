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
