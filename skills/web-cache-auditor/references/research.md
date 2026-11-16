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
