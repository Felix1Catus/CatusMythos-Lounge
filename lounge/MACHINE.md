# MACHINE — how this table finds criticals (2026)

Read this with the protocol. The board is the shared brain. A story is not a bug.

## What actually produced 0days

Pulled 2026-10-17 from the public record. These are the methods. Payload lists are not.

- **FuzzingBrain V2** (arXiv:2605.21779, May 2026). Multi-agent on OSS-Fuzz. 36/40 of the AIxCC 2025 C/C++ set. 29 zero-days in 12 projects, all maintainer-confirmed. The rule they proved: a report that is not reproducible is a false positive. Localize one suspicious point in the control flow, not a whole function and not a single line. Then fuzz that point.
- **A2** (arXiv:2508.21579, Aug 2025). Android. Discovery agent and validation agent are different jobs. 104 production zero-days; 57 carried a generated PoC. A finding without a PoC stayed speculative.
- **SmartFuzz** (arXiv:2511.12164, Nov 2025). Smart-contract fuzzing. Coverage-chasing lost to a team that reflected on the runtime trace and split the transaction sequence across agents. Continuous reflection beat a bigger seed list.
- **Web reproduction** (arXiv:2510.04689, Oct 2025). Twenty agents, 80 real CVEs. They reproduced library bugs and failed on multi-component services when they guessed the environment or the auth. Grounding in the real client is the difference.
- **Agent failure modes** (arXiv:2512.07497, Dec 2025). The recurring deaths: acting before the bytes are in hand, inventing a missing field, and trusting a distractor. Scale did not fix that.
- **HackerOne, last 30 days before 2026-10-16** (`targets/_shared/HUNTING_METHODOLOGY_SOURCE_FIRST.md`). About 65 of 90 paid bugs were a deep read of one codebase. The web wins were a second path that skipped a check, a forgotten auth, or a secret landing in telemetry. Project Zero: half of 2022 in-the-wild 0days were variants; vendors patch the PoC path.

## The loop (every seat, every shot)

1. **GROUND.** One source, in the same pass as the shot: the client's real bytes, the vendor spec for that check, or the server's last error class. If those bytes are not in hand, the next action is to get them.
2. **HYPO.** One suspicious point: the field the check does not read, the sibling route, the patch that fixed one path. Emit it before the request.
   `seatlib.py hypo --cell 'METHOD /path AXIS' --source '...' --oracle '...' --shot '...'`
   Oracle is the output that proves it (a later error class, a 200 with the other tenant's object, a crash). "Maybe interesting" is not an oracle.
3. **SHOT.** One structural variant. Claim that axis. `token` (no `--op` on a read). Fire. Quote the class that came back.
4. **REFLECT.** Name the class. If it is the class you predicted, that axis is dead. Name the sibling the author did not patch.
   `seatlib.py reflect --cell '...' --klass '...' --sibling 'the other request'`
   (`--class` is an alias of `--klass`.)
   The conductor pushes that sibling to every other live seat. Their next action is to fire it or name a better one. A KILL is that one shape. It is not permission to stop.
5. **PROVE.** `RESULT` only when a second seat can rerun one command and see the same class flip or the same object. No PoC, no result. Then both climb: floor, ceiling, the next shot. Do not persist and sit down.
6. **KILL / 4xx.** A killed axis or a 400/401/403/404 is the next chain, not the end. The other seat names a different chain in the same turn: sibling route, other type, nested field, second path. Same class twice means the check between them did not move. Loosen one axis.
7. **NO HUMAN WAIT MID-HUNT.** A missing key, an OTP, a prod write, or a submit is not a place to stop. Do not fire that action. Fire the chain that does not need it. The only wait is the operator's verdict on a finished report.
8. **REPORT.** At the ceiling, draft under `targets/<prog>/reports/`. One command, the expected output, what that output proves. `emit --type REPORT`. The other seat reruns the PoC and answers `REPORT-OK` or `REPORT-FIX`. Then both stop. The operator submits.

## Live board (do not skip)

```
python3 ~/targets/_shared/lounge/seatlib.py board   # claims + last peer events + TAKE
python3 ~/targets/_shared/lounge/seatlib.py take    # claim the sibling the other seat named
python3 ~/targets/_shared/lounge/seatlib.py follow --wait 2
```

`claim` and `take` exit 1 if denied. `reflect --sibling` must be `METHOD /path AXIS`. A prose sibling is rejected.

## V5 on this table
Solo contract is `~/.grok/rules/HUNTER_V5.md`. Each seat can do that whole loop alone. Together you do it better: the seat that did not fire the shot is the critic and the variant hunter. You rerun their command, try to kill the claim, and if it holds you climb one ceiling. You do not open a second recon, and you do not spray a class matrix.

## Who does what, at the same time

- **PROBER** fires the shot and the peer's sibling.
- **ANALYST** reads the source or the client and emits the next HYPO. Pushes the suspicious point.
- **SKEPTIC** tries to kill a RESULT: negative control, wrong host, the documented shape. A confirm that does not name the missing link is unfinished.
- **RECON** only when the bytes are not on disk. One source, then hand it to a HYPO. No hour of mapping.

Two seats on one path is the point. `POST /graphql DOCUMENT fields` and `POST /graphql DOCUMENT count` run together. The same cell does not.

## What this table refuses

A ten-angle list before a request. A payload spray on a hardened parser. Treating a peer KILL as a closed surface. Ending a turn on "human-gated" or "no reachable critical" while an unfired sibling still exists. A RESULT whose only evidence is the writer's confidence. A report the other seat has not rerun. Guessing a request shape when the client or the last error already named it.
