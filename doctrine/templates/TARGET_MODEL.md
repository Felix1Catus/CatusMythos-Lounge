# TARGET MODEL — {PROG}

> Attack the model, not the endpoint. Every claim carries evidence (probe id / path / response
> class) or is marked [ASSUMPTION — NEEDS PROBE]. An admitted UNKNOWN is a probe target;
> a hidden one is a missed P1. If this disagrees with fresh probes, the probes win — update it.

## 1. Trust boundaries
| Hop | Receiver trusts from sender | Evidence |
|---|---|---|
| browser → edge | | |
| edge → api | | |
| api → service/db | | |
| web ↔ mobile backend | | |
| tenant → platform | | |
| partner → core | | |

## 2. Identity lifecycle
- Established at (login / OAuth / magic link / SSO):
- Re-checked at (which endpoints, how — token, session, mTLS):
- ASSUMED at (internal services, gateway-header trust, "internal-only" mounts): ← ATO country
- Token format / signing (JWT alg, kid, expiry):

## 3. Money / data / authority flows
- Prices / quantities / roles SET at:
- CHECKED at:
- CONSUMED at:  ← any set-client-side + consumed-server-side without re-derivation = forge candidate

## 4. Component trust chain / parser pairs
- Parsers that could disagree (proxy vs app path norm, JSON vs form, unicode, content-type):

## 5. Critical-shaped surfaces observed
- identity mint: · IDOR (identity/money/PII keys): · SSRF fetchers: · unauth state-writes: · payment: · RCE-family:

## 6. UNKNOWNs (each = a probe target)
- [ ]
