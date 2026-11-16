---
name: web-cache-auditor
description: Assess web and CDN cache behavior, cache-key inputs, unkeyed header reflection, cache poisoning preconditions, cache deception indicators, and URL normalization differences. Use when asked to test CDN caching, web cache poisoning/deception, cache keys, or origin/cache parsing discrepancies. For explicitly authorized testing only.
metadata:
  author: CatusMythos-Lounge contributors
  version: 1.0.0
---

# Web Cache Auditor

Research-led checks for cache behavior that ordinary endpoint scanners often
miss. This skill treats cache poisoning and cache deception as separate
problems: poisoning makes a response vary on an input absent from the key;
deception causes a cache to store sensitive dynamic content under a path it
mistakes for a static resource.

## Safety and scope

- Test only assets and routes covered by explicit authorization. Confirm the
  program's rules for CDN, cache, and availability testing first.
- Prefer a staging environment with a disposable cache. Even a unique query
  cache-buster can be ignored by a cache and cannot guarantee isolation.
- Use read-only `GET` routes. Do not probe account, session, token, billing,
  reset, or other personalized responses on a shared cache.
- The helper sends no exploit payloads, does not change the `Host` header,
  does not spoof client IP headers, and never follows redirects to another
  host. It validates TLS certificates unless `CATUS_INSECURE_TLS=1` is set.
- The normal run only observes one response. `--probe-unkeyed` sends inert
  random canaries with a fresh cache-buster for each candidate header and
  eligible query parameter. This is still an active test and may populate a
  cache if the cache ignores the query string.
- `--confirm-cache-replay` deliberately repeats a canary URL without its
  tested header or query parameter. Use this only on an isolated staging cache after checking the
  potential impact; the canary uses a reserved `.invalid` hostname but can
  still alter a reflected response.

## Run the helper

From the skill directory:

```bash
python3 scripts/cache_audit.py --target https://app.example.test/public-page
python3 scripts/cache_audit.py --target https://app.example.test/public-page --probe-unkeyed
python3 scripts/cache_audit.py --target https://staging.example.test/public-page \
  --probe-unkeyed --confirm-cache-replay --output reports/cache-audit.json
python3 scripts/cache_audit.py --demo
```

The helper is stdlib-only and makes at most one baseline request, seven
header probes, and five query-parameter probes (`utm_content`, `utm_source`,
`gclid`, `fbclid`, `_`) when eligible. It skips query names already present
and skips query probes if the target URL already contains a sensitive-looking
name such as `token`, `session`, `email`, or `key`. Replay mode adds one clean
replay per reflected candidate, for at most 25 GETs. It reads at most 128 KiB
from each response. Reports omit
response bodies and query values, and include only cache-relevant response
headers. The top-level `findings` array contains only replay leads, marked
`INFO` with a `confidence` value so they can be imported by
`vuln-chain-composer`; reflection-only candidates stay under `probes`. A
`HIT`, positive `Age`, or canary replay is evidence to investigate, not a
standalone proof of exploitability.

Per-request `--timeout` must be finite and between 0 and 30 seconds;
`--delay` must be finite and between 0 and 5 seconds. These bounds also apply
when `request_get()` is called directly by another script.

## Workflow

1. **Map cache layers.** Record the CDN, reverse proxy, application cache, and
   any browser/service-worker cache known to sit on the route. Keep evidence
   from each layer separate; headers may describe different caches.
2. **Observe the baseline.** Review `Cache-Control`, `Vary`, `Age`, `Via`,
   `ETag`, CDN cache-status headers, content type, status, and redirect
   behavior. Missing cache headers do not prove that no cache exists.
3. **Check candidate unkeyed inputs.** On public, non-personalized routes,
   send the helper's inert header and query canaries with unique cache-busters.
   Query candidates are a small seed set, not exhaustive parameter discovery.
   Reflection in a body or response header marks a candidate input only;
   inspect the exact output context and sanitization manually.
4. **Separate reflection from cacheability.** A reflected value is not a
   cache issue until a cache stores and reuses a response for requests that
   differ in that input. Replay confirmation is deliberately staging-only.
   Confirm cache behavior using cache indicators and independent requests;
   account for multiple cache layers and `Vary` dimensions.
5. **Check URL parsing and normalization.** The active mode compares a small
   query-key candidate against a clean replay using the same nonce, but skips
   candidate names already present in the input URL. Compare how the edge and
   origin handle encoded delimiters, dot segments, semicolon path parameters,
   duplicate query parameters, and extension or directory cache rules
   manually. Start with low-impact routes and unique keys. Do not automatically
   try paths against authenticated content.
6. **Assess cache deception separately.** In an authorized test account on
   staging, determine whether a private dynamic response can be cached under
   an extension or static-directory rule. Never retrieve another user's
   cached content. Stop if the response contains secrets or if the cache key
   cannot be isolated.
7. **Report the boundary.** Include the tested URL (redact tokens), cache
   layer, request differences, response status and cache headers, whether a
   marker was reflected, and whether it reappeared without the header. Mark
   uncertainty explicitly; do not label a reflection-only result as cache
   poisoning.

## Edge cases to account for

- `Vary` can key selected headers while a CDN-specific rule ignores or
  overrides origin cache directives.
- Cache keys may normalize URL paths or queries differently from the origin;
  equivalent-looking requests are not necessarily equivalent at either layer.
- The query canary seed set is limited. Duplicate-key precedence, semicolon
  delimiters, parameter cloaking, and framework-specific parsing remain
  target-aware manual checks; do not probe personalized/shared-cache routes
  unless the engagement explicitly authorizes them.
- An absent `Age` or `X-Cache` header is inconclusive. A `HIT` may come from an
  upstream cache unrelated to the target CDN.
- Cookies, authorization, `Set-Cookie`, content type, status codes, and
  extension-based rules can change whether a response is cacheable.
- Redirects are recorded rather than followed so a probe cannot silently
  reach a host outside the supplied origin.
- The script's GET-only behavior does not cover request smuggling, fat GET
  bodies, POST caching, browser caches, or authenticated cache-deception
  validation. Use a proxy and the approved test plan for those cases.

## Research basis

See [references/research.md](references/research.md) for the methodology and
limits drawn from the cited researcher writeups. Key sources:

- James Kettle, PortSwigger Research, [Web Cache Entanglement: Novel Pathways to Poisoning](https://portswigger.net/research/web-cache-entanglement).
- PortSwigger Web Security Academy, [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) and [Web cache deception](https://portswigger.net/web-security/web-cache-deception).
- PortSwigger Research, [Gotta Cache 'em all: bending the rules of web cache exploitation](https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf).
