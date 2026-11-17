# Business-logic race testing

Research review: 2026-11-16. This note informs `skills/api-breaker/scripts/logic_tester.py`.

## Primary sources

- James Kettle, PortSwigger Research, [Smashing the State Machine: The True Potential of Web Race Conditions](https://portswigger.net/research/smashing-the-state-machine). The methodology starts by predicting collisions around shared persistent state and related endpoints, then examines the resulting state rather than assuming requests are atomic.
- PortSwigger Web Security Academy, [Race conditions](https://portswigger.net/web-security/race-conditions). The material covers limit overruns, hidden multi-step state, single- and multi-endpoint races, and the effect of network/server timing on alignment.
- OWASP Web Security Testing Guide, [Payment Functionality](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/10-Payment_Functionality/). It identifies one-time actions and shared balances, inventory, and coupons as targets; useful indicators include excess allocation, duplicate side effects, and state values outside the expected limits.

## Implementation guidance

1. Select an operation whose business rule is known and whose requests touch the same test object or one-time resource. A generic 2xx response is only a lead; this script's fixed payloads cannot infer an application's intended transaction semantics.
2. Compare a one-request sequential control with the concurrent batch. If a controlled state counter is available, use it to test whether the batch produces more than the sequential action. The numeric value is never written to findings; only the measured effect ratio is reported.
3. Use a disposable, authorized object and a same-origin, read-only state endpoint. Supplying `--race-state-url` and `--race-state-json-pointer` causes one sequential mutation control per payload, so it is an active test option with additional writes. An HTTP GET is not automatically harmless; confirm the selected read-back route has no side effects.
4. The standard-library thread pool makes requests concurrently but does not implement PortSwigger's HTTP/2 single-packet synchronization. Responses may be affected by network jitter, server scheduling, duplicate-request suppression, or idempotency behavior. A negative result does not rule out a narrower race window.
5. The CLI has a run-wide budget for race payload, control, and read-back requests. The default ceiling of 840 covers the existing upper bound of 20 candidate endpoints, 3 payload cases, and 10 concurrent requests, plus the optional state-control/read-back requests. Lower it for a smaller authorized test window.

## Verification limits

Regression fixtures use a local HTTP server only. They demonstrate suppression when a server returns 2xx for retries but applies the state change once, and candidate reporting when the selected numeric counter changes more during the burst than during the sequential control. Neither fixture contacts a live API or establishes that generic payloads match a real application's business rules.
