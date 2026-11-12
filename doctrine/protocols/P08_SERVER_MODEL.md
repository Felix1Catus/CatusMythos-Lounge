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
