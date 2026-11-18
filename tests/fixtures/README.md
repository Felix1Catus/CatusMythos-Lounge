# Assessment benchmark fixtures

`assessment_benchmark_app.py` binds only to `127.0.0.1` on an ephemeral port.
It deliberately contains three labeled behaviors for regression testing:

| Case | Fixture behavior | Expected scanner result |
| --- | --- | --- |
| BOLA | `/api/orders/101` discloses the same owner-tagged object to lower roles | Validated BOLA when the returned object ID is reproduced across roles |
| BFLA | `/api/reports` returns a response to member-level roles | Candidate only; access is observed but privileged impact needs human verification |
| Workflow skip | `/checkout/review` and `/checkout/confirm` answer without prior steps | Workflow step-skip candidate; a bare 200 is not confirmed impact |

`tests/test_assessment_benchmark_app.py` executes the repository's N-role authz
and workflow-discovery code against this app. These cases test regression
behavior, not broad scanner recall: the fixture is intentionally small and
does not stand in for DVWA, Juice Shop, or a production-like application.
