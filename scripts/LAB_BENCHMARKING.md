# Local vulnerable-lab benchmark

This benchmark uses the repository's official DVWA, OWASP Juice Shop, and
OWASP crAPI training apps in a WSL2 Docker engine. Published ports must remain
bound to `127.0.0.1`; never expose these vulnerable apps to a LAN or public
interface. The stock local runs use no external target traffic.

## Repeat the current app versions

The recorded run is in
[`doctrine/benchmarks/lab-run-2026-11-18.json`](../doctrine/benchmarks/lab-run-2026-11-18.json).
It records source commits and image digests. Pull by digest when reproducing,
or update the report when intentionally testing newer images.

- DVWA: official [DVWA project](https://github.com/digininja/DVWA), compose
  deployment on `127.0.0.1:4280`; login `admin/password`; initialize the DB,
  and set security to `low` for the SQLi/XSS cases.
- Juice Shop: official [OWASP project](https://owasp.org/projects/juice-shop),
  app on `127.0.0.1:3000`.
- crAPI: official [OWASP project](https://github.com/OWASP/crAPI), compose
  deployment on `127.0.0.1:8888` with the official minimal resource overlay.

The official setup guides are the source of the lab-specific setup steps:
[DVWA README](https://github.com/digininja/DVWA/blob/master/README.md),
[crAPI setup](https://github.com/OWASP/crAPI/blob/develop/docs/setup.md), and
[Juice Shop Docker instructions](https://github.com/juice-shop/juice-shop).

## Run scanners and summarize outcomes

Use campaign manifests with explicit per-step budgets and `--process-only`
only for these local loopback labs (the strict network namespace intentionally
rejects loopback destinations). DVWA credentials are session-only inputs; do
not save cookies in campaign artifacts. The exposure tester can run directly
or through the registered `web_exposure` campaign tool.

The current lab-case manifest is
[`doctrine/templates/ASSESSMENT_LAB_CASES.json`](../doctrine/templates/ASSESSMENT_LAB_CASES.json).
Save scanner JSON to the ignored `targets/benchmark/` directory, then run:

```powershell
python scripts/summarize_lab_benchmark.py `
  --artifacts targets/benchmark `
  --output targets/benchmark/lab-coverage-report.json
```

The summarizer distinguishes confirmed results, candidates, and tested
negatives. Candidates stay unresolved in recall calculations. Keep app build
IDs and scanner artifacts with each run so results can be compared across
changes.

## Recorded findings and limits

The 2026-11-18 run confirmed DVWA low-security error-based SQLi and crAPI's
public secret-bearing `/.env` file. The new exposure verifier did not report
Juice Shop's `/.env` or `/.git/HEAD` routes because both returned the exact
HTML SPA shell. DVWA reflected XSS was surfaced as a candidate but not counted
confirmed because browser execution was not checked. Juice Shop's API
discovery reached its 240-request cap and is marked partial; crAPI API
discovery completed at 72 requests but found only three routes in its
anonymous pass. The broad crawl's 200 responses are leads, not confirmed
endpoints or vulnerabilities.

The labeled result is **2 true positives, 1 true negative, 0 false positives,
0 false negatives, and 1 unresolved positive**. The displayed 100% precision
and recall apply only to the resolved subset; they are not a complete recall
score and do not estimate internet-wide accuracy. The intentionally vulnerable
labs are challenge collections, not production-representative web apps.

After measurements are saved, stop the disposable local services with
`docker compose down -v` in each compose directory and `docker rm -f
catus-juice-shop`. The WSL Docker package and cached images can remain for a
later pinned run.
