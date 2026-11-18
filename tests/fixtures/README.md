# Assessment benchmark fixtures

`assessment_benchmark_app.py` binds only to `127.0.0.1` on an ephemeral port.
It deliberately contains three labeled behaviors for regression testing:

| Case | Fixture behavior | Expected scanner result |
| --- | --- | --- |
| BOLA | `/api/orders/101` discloses the same owner-tagged object to lower roles | Validated BOLA when the returned object ID is reproduced across roles |
| BFLA positive | `/api/reports` returns the same structured privileged data to member-level and admin roles | Validated when the low role's JSON response matches the successful admin control |
| BFLA negative control | `/api/admin` returns 403 to lower roles and protected JSON to admin | No lower-role finding |
| Sensitive file | `/.env` returns a fake DB password/API token | Verified exposure; output retains key names only and redacts values |
| Stateful workflow | The same coupon can be applied twice; `/cart` exposes the resulting count | Automatically validated only after baseline count 1, misuse read-back count 2, and cleanup reset |

`tests/test_assessment_benchmark_app.py` executes the repository's N-role authz
and workflow scenario code against this app. Run all three positive cases and
the negative control with:

```powershell
python scripts/run_local_benchmark.py --output targets/benchmark/local-v2.json
```

The report includes execution coverage and labeled precision/recall. BOLA and
BFLA use object identity and a same-response admin control; the exposure case
uses content evidence without retaining values; the stateful case uses a safe
baseline, intentional duplicate action, final read-back, and reset cleanup.
These are regression checks, not broad scanner recall: this fixture
does not stand in for DVWA, Juice Shop, crAPI, or production applications.
