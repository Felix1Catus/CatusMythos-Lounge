# Web cache testing: research notes

This skill separates three observations that are often conflated:

1. **Input influence:** a request component changes the origin response.
2. **Cache behavior:** the response is stored and later served for a matching
   cache key.
3. **Impact:** the stored response creates a meaningful victim effect.

A positive result at one stage does not prove the next stage.

## Research findings applied

### Unkeyed input and poisoning

James Kettle's [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
and [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
describe how a cache can ignore request components that the origin still
uses. Cache-key normalization and parser differences can also make distinct
requests collide. The [Web Security Academy methodology](https://portswigger.net/web-security/web-cache-poisoning)
separates finding an input that affects a response from proving that the
response is cached. It also warns that live probes can expose generated
responses to other visitors and recommends a unique cache-buster per probe.

The helper follows that boundary: it uses a random `.invalid` canary, does
not emit executable content, adds a fresh cache-buster to each candidate
request, and reports reflection as a candidate only. Cache replay is a
separate explicit option because no client can guarantee that a cache honors
the cache-buster.

### Query-parameter cache-key differences

PortSwigger's [Web Cache Entanglement research](https://portswigger.net/research/web-cache-entanglement)
describes parameter cloaking: a cache may exclude a parameter while the
origin's parser still treats delimiters or trailing content as meaningful.
The [Web Security Academy's unkeyed-query lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query)
demonstrates that query-string changes can still receive a cache hit when the
query is not part of the cache key.

The active helper now probes a bounded seed set of common tracking parameter
names (`utm_content`, `utm_source`, `gclid`, `fbclid`, `_`) with inert
`.invalid` canaries. It adds a unique nonce, then the staging-only replay
removes only the candidate parameter while preserving that nonce. Existing
candidate names are skipped, and all query probes are skipped when the input
URL contains a sensitive-looking key. A marker reappearing on replay is still
only a manual-review lead: the helper does not prove which cache layer served
it or whether a victim could receive harmful content. Duplicate-key
precedence, semicolon delimiters, parameter cloaking, and framework-specific
query parsing remain manual checks.

### Cache deception and normalization

The [Web cache deception guide](https://portswigger.net/web-security/web-cache-deception)
describes cache rules based on extensions and static path prefixes, and
discrepancies between cache and origin path normalization. The
[Gotta Cache 'em all whitepaper](https://portswigger.net/kb/papers/kapvrid/gotta-cache-em-all.pdf)
documents parser differences involving delimiters and framework behavior.
These checks can store authenticated dynamic content, so the helper does
not automate them or accept credentials; the skill reserves them for a
target-specific staging plan.

### Important limits

- Response cache headers are clues, not ground truth; layers may add, remove,
  or rewrite them.
- A positive `Age`, `HIT`, or replayed canary does not establish that an
  unintended user could receive harmful content.
- A negative result does not rule out internal caches, alternate cache keys,
  custom cache rules, or browser/service-worker caches.
- Cache-busting only reduces accidental collisions. If the cache ignores the
  query string, active probes can still affect a shared entry; prefer staging.
- Request timeouts and inter-request delays are finite and bounded by the
  CLI limits; this bounds local waiting but does not make an active cache probe
  safe for a shared production cache.

The numeric CLI limits use Python's `math.isfinite()` so `NaN` and infinities
cannot bypass ordinary comparisons; see the [Python math documentation](https://docs.python.org/3/library/math.html#math.isfinite).
