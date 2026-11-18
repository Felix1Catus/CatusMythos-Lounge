# Assessment benchmark fixtures

`assessment_benchmark_app.py` binds only to `127.0.0.1` on an ephemeral port.
It deliberately contains three labeled behaviors for regression testing:

| Case | Fixture behavior | Expected scanner result |
| --- | --- | --- |
| BOLA | `/api/orders/101` discloses the same owner-tagged object to lower roles | Validated BOLA when the returned object ID is reproduced across roles |
| BFLA positive | `/api/reports` returns the same structured privileged data to member-level and admin roles | Validated when the low role's JSON response matches the successful admin control |
| BFLA negative control | `/api/admin` returns 403 to lower roles and protected JSON to admin | No lower-role finding |
| Workflow skip | `/checkout/review` and `/checkout/confirm` answer without prior steps | Workflow step-skip candidate; a bare 200 is not confirmed impact |

`tests/test_assessment_benchmark_app.py` executes the repository's N-role authz
and workflow-discovery code against this app. BOLA and BFLA positive cases
auto-validate from object identity / same-JSON privileged controls; the
workflow-skip remains a candidate because successful page reachability does
not prove that a protected state transition occurred. These cases test
regression behavior, not broad scanner recall: the fixture is intentionally
small and does not stand in for DVWA, Juice Shop, or a production-like app.
