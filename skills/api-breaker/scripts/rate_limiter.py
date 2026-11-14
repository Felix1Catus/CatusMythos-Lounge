#!/usr/bin/env python3
"""
Rate Limiter Tester Module - api-breaker
Tests API rate limiting enforcement and bypass techniques.
Author: orizon.one
"""

import argparse
import json
import re
import time
import urllib.request
import urllib.parse
import concurrent.futures
from datetime import datetime


from _common import http_request, log, success, vuln, warn
# IP spoofing headers for rate limit bypass
#
# NOT implemented, by design (research_notes/API breaker depth
# techniques/rate_limit_versioning.md): sending X-Forwarded-For TWICE as
# separate header lines in one request (once empty, once with a value) --
# a distinct technique from rotating a single header's value. Python's
# stdlib urllib.request/http.client (this skill's only HTTP transport,
# via _common.http_request's headers dict) collapses a dict key to one
# header line; reproducing a real duplicate header LINE needs raw-socket
# request construction, which _common.py deliberately doesn't provide.
# Documented limitation, not automated here.
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Forwared-Host": "localhost"},  # literal misspelling -- real-world broken-but-still-parsed header name
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]

# Headers rotated to a fresh fake IP on every request in the bypass burst
# (below). Host-confusion headers (X-Forwarded-Host, X-Host, the
# X-Forwared-Host misspelling) and the raw Forwarded header are left
# static, matching this file's existing convention for X-Forwarded-Host.
IP_ROTATION_HEADERS = (
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    "X-Originating-IP", "True-Client-IP", "CF-Connecting-IP",
)

# Rate limit related response headers
RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "Retry-After",
]


def extract_rate_limit_info(headers):
    """Extract rate limiting information from response headers."""
    info = {}
    for header_name in RATE_LIMIT_HEADERS:
        for key, val in headers.items():
            if key.lower() == header_name.lower():
                info[header_name] = val
    return info


def send_rapid_requests(url, count, extra_headers=None, delay=0):
    """Send rapid requests and track responses."""
    results = {
        "total_sent": 0,
        "status_codes": {},
        "rate_limited_at": None,
        "rate_limit_headers": {},
        "response_times": [],
    }

    for i in range(count):
        start_time = time.time()
        status, headers, body = http_request(url, headers=extra_headers)
        elapsed = time.time() - start_time

        results["total_sent"] += 1
        results["status_codes"][str(status)] = results["status_codes"].get(str(status), 0) + 1
        results["response_times"].append(round(elapsed, 3))

        rl_info = extract_rate_limit_info(headers)
        if rl_info:
            results["rate_limit_headers"] = rl_info

        if status == 429:
            if results["rate_limited_at"] is None:
                results["rate_limited_at"] = i + 1
            if delay:
                time.sleep(delay)
            continue

        if delay:
            time.sleep(delay)

    return results


def send_concurrent_requests(url, count, workers=20, extra_headers=None):
    """Send concurrent requests using thread pool."""
    results = {
        "total_sent": 0,
        "status_codes": {},
        "rate_limited_at": None,
        "rate_limit_headers": {},
    }

    def make_request(_):
        return http_request(url, headers=extra_headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(make_request, i) for i in range(count)]
        for idx, future in enumerate(concurrent.futures.as_completed(futures)):
            status, headers, body = future.result()
            results["total_sent"] += 1
            results["status_codes"][str(status)] = results["status_codes"].get(str(status), 0) + 1

            rl_info = extract_rate_limit_info(headers)
            if rl_info:
                results["rate_limit_headers"] = rl_info

            if status == 429 and results["rate_limited_at"] is None:
                results["rate_limited_at"] = idx + 1

    return results


# research_notes/API breaker depth techniques/rate_limit_versioning.md --
# "Auto-targeting for limited-use/financial-impact endpoints": the
# Stripe/Dropbox/Instacart/Reverb race-condition bounty class is driven by
# racing a resource that's genuinely LIMITED (a single-use coupon, an
# invite slot, a balance) rather than a generic endpoint -- Kettle's own
# target-prediction methodology asks whether the action APPENDS/CREATES
# (limit-overrun-prone) against a server-side, persistently-scoped
# resource. These substrings are the cheap, available proxy for that
# without needing real schema knowledge of the target.
FINANCIAL_IMPACT_KEYWORDS = [
    "coupon", "discount", "invite", "redeem", "gift_card",
    "credit", "balance", "voucher", "offer",
]


def find_race_condition_candidates(discovered, response_bodies=None):
    """Scan discovered paths/params/response bodies for substrings
    suggesting a limited-use or financial-impact resource worth racing,
    rather than blindly bursting every endpoint.

    `discovered` is a list of URL strings or dicts with a "url" key (the
    same shapes main() already normalizes endpoints into).
    `response_bodies`, if supplied, is an optional {url: body_text} map --
    this function never fetches bodies itself (that cost belongs to
    whatever already has them, e.g. a prior discovery pass), it only
    scans what it's given alongside the URL/path text itself.
    """
    bodies = response_bodies or {}
    candidates = []
    for item in discovered:
        url = item if isinstance(item, str) else item.get("url", "")
        if not url:
            continue
        haystack = (url + " " + str(bodies.get(url, ""))).lower()
        hits = [kw for kw in FINANCIAL_IMPACT_KEYWORDS if kw in haystack]
        if hits:
            candidates.append({"url": url, "matched_keywords": hits})
    return candidates


def test_race_condition(url, extra_headers=None, count=20, workers=20, is_financial_target=False):
    """Race-condition baseline-vs-burst comparator.

    research_notes/.../rate_limit_versioning.md: run the identical request
    sequentially N times first and record the success count, then fire
    the same N requests as a tight concurrent burst (ThreadPoolExecutor,
    building on send_concurrent_requests()); flag a bypass whenever
    successes_in_burst > successes_in_baseline. This is the realistic,
    portable ceiling for this stdlib-oriented skill -- a true HTTP/2
    single-packet attack (James Kettle, "Smashing the State Machine",
    PortSwigger 2023) needs raw h2-frame control via a dedicated library
    this skill deliberately doesn't depend on; a thread-pool concurrent
    burst will miss narrower race windows a single-packet attack could
    still catch, but is the ceiling available here.

    `is_financial_target` escalates severity to "critical" when the URL
    matched the auto-targeting keyword heuristic above (the Stripe/
    Dropbox/Instacart/Reverb financial-impact class), vs. "high" for a
    generic confirmed race.
    """
    log(f"Running race-condition baseline-vs-burst comparator on {url}...")
    findings = []

    baseline = send_rapid_requests(url, count, extra_headers, delay=0)
    baseline_successes = sum(
        v for k, v in baseline["status_codes"].items() if k in ("200", "201")
    )

    burst = send_concurrent_requests(url, count, workers=workers, extra_headers=extra_headers)
    burst_successes = sum(
        v for k, v in burst["status_codes"].items() if k in ("200", "201")
    )

    result = {
        "url": url,
        "requests_per_phase": count,
        "baseline_successes": baseline_successes,
        "burst_successes": burst_successes,
        "baseline_status_codes": baseline["status_codes"],
        "burst_status_codes": burst["status_codes"],
    }

    if burst_successes > baseline_successes:
        severity = "critical" if is_financial_target else "high"
        vuln(f"Race condition bypass on {url}: {burst_successes} successes in burst "
             f"vs {baseline_successes} in sequential baseline")
        findings.append({
            "type": "rate_limit_race_condition",
            "severity": severity,
            "url": url,
            "requests_per_phase": count,
            "baseline_successes": baseline_successes,
            "burst_successes": burst_successes,
            "excess_successes": burst_successes - baseline_successes,
            "financial_impact_candidate": is_financial_target,
            "description": (
                "A concurrent thread-pool burst produced more successful "
                "responses than an identical sequential baseline allowed -- "
                "a non-atomic check-then-act race condition (James Kettle, "
                "'Smashing the State Machine', PortSwigger 2023; same root "
                "cause as the Stripe fee-discount race, HackerOne blog, "
                "$600k exposure / $5k bounty). Thread-pool burst only "
                "(portable approximation, not a true HTTP/2 single-packet "
                "attack) -- see rate_limit_versioning.md for why a narrower "
                "race window could still exist undetected by this test."
            ),
        })

    return findings, result


def test_rate_limit_bypass(url, extra_headers=None, delay=0):
    """Test rate limit bypass using IP spoofing headers."""
    log("Testing rate limit bypass via IP spoofing headers...")
    findings = []

    for bypass in BYPASS_HEADERS:
        bypass_name = list(bypass.keys())[0]
        headers = dict(bypass)
        if extra_headers:
            headers.update(extra_headers)
            headers.update(bypass)  # Ensure bypass header takes precedence

        # Send a burst of requests with the bypass header
        got_429 = False
        success_after_limit = 0

        for i in range(30):
            # Rotate the IP for X-Forwarded-For style headers
            if bypass_name in IP_ROTATION_HEADERS:
                headers[bypass_name] = f"10.{i % 256}.{(i * 7) % 256}.{(i * 13) % 256}"

            status, _, _ = http_request(url, headers=headers)
            if delay:
                time.sleep(delay)

            if status == 429:
                got_429 = True
            elif got_429 and status in (200, 201):
                success_after_limit += 1

        if got_429 and success_after_limit > 0:
            vuln(f"Rate limit bypass via {bypass_name} header rotation")
            finding = {
                "type": "rate_limit_bypass",
                "severity": "medium",
                "bypass_header": bypass_name,
                "success_after_limit": success_after_limit,
            }
            if bypass_name in IP_ROTATION_HEADERS:
                finding["note"] = (
                    "Architectural pattern matches CVE-2025-59152 (Litestar "
                    "RateLimitMiddleware.cache_key_from_request() trusting a "
                    "client-supplied X-Forwarded-For unconditionally as the "
                    "rate-limit cache key -- rotating the header value gives "
                    "every request its own bucket; fixed in Litestar 2.18.0)."
                )
            findings.append(finding)
        elif not got_429:
            # Never rate limited even with bypass headers - might indicate no rate limiting
            pass

    return findings


def _response_shape(status, body):
    """A coarse fingerprint of a response, used to tell a genuine
    pre-limit SUCCESS response apart from a same-status-code soft-404/
    error page -- checking status code alone is exactly the false-
    positive risk the research calls out for the mutation test below."""
    return {"status": status, "length": len(body)}


def _shapes_match(reference_shape, candidate_shape, tolerance=0.3):
    """True when candidate_shape looks like the SAME kind of response as
    reference_shape: identical status code, and a response body length
    within `tolerance` (default 30%) of the reference's length."""
    if reference_shape["status"] != candidate_shape["status"]:
        return False
    ref_len = reference_shape["length"]
    cand_len = candidate_shape["length"]
    if ref_len == 0:
        return cand_len == 0
    return abs(cand_len - ref_len) / ref_len <= tolerance


def reconfirm_rate_limit(url, extra_headers=None, burst_count=35):
    """Re-burst the ORIGINAL (already-flagged-as-limited) path to confirm
    it still 429s right now, capturing the last pre-429 success response
    as the 'pre-limit success shape' reference the mutation test compares
    candidates against. Returns (rate_limited_at_or_None, reference_shape
    _or_None).
    """
    reference_shape = None
    for i in range(burst_count):
        status, _, body = http_request(url, headers=extra_headers)
        if status == 429:
            return i + 1, reference_shape
        if status in (200, 201):
            reference_shape = _response_shape(status, body)
    return None, reference_shape


def generate_path_mutations(url):
    """Generate path/method/casing mutation variants for a URL already
    confirmed rate-limited at its original form.

    research_notes/.../rate_limit_versioning.md: trailing-slash toggle,
    doubled/tripled slash, per-segment case mutation, HTTP method swap
    (+ X-HTTP-Method-Override), and one junk query parameter -- the exact
    bug class behind CVE-2023-38507 (Strapi) and CVE-2025-71399 (Better
    Auth). Returns a list of (description, mutated_url, http_method,
    method_override_header_value_or_None) tuples.
    """
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    segments = [s for s in path.split("/") if s]

    def rebuild(new_path, new_query=None):
        return urllib.parse.urlunsplit(parts._replace(
            path=new_path,
            query=new_query if new_query is not None else parts.query,
        ))

    mutations = []

    # 1. Trailing slash toggle
    if path != "/" and path.endswith("/"):
        mutations.append(("trailing_slash_removed", rebuild(path.rstrip("/")), "GET", None))
    else:
        mutations.append(("trailing_slash_added", rebuild(path + "/"), "GET", None))

    # 2. Doubled / tripled leading slash
    mutations.append(("doubled_leading_slash", rebuild("/" + path), "GET", None))
    mutations.append(("tripled_leading_slash", rebuild("//" + path), "GET", None))

    # 3. Doubled internal slash (right after the first path segment)
    if segments:
        first_seg_end = path.index(segments[0]) + len(segments[0])
        doubled_internal = path[:first_seg_end] + "/" + path[first_seg_end:]
        mutations.append(("doubled_internal_slash", rebuild(doubled_internal), "GET", None))

    # 4. Per-segment case mutation
    if segments:
        trailing = "/" if path.endswith("/") else ""
        lower_path = "/" + "/".join(s.lower() for s in segments) + trailing
        upper_path = "/" + "/".join(s.upper() for s in segments) + trailing
        title_path = "/" + "/".join(s[:1].upper() + s[1:] for s in segments) + trailing
        mutations.append(("lowercase_segments", rebuild(lower_path), "GET", None))
        mutations.append(("uppercase_segments", rebuild(upper_path), "GET", None))
        mutations.append(("titlecase_segments", rebuild(title_path), "GET", None))

    # 5. HTTP method swap + X-HTTP-Method-Override trick
    mutations.append(("method_put", rebuild(path), "PUT", None))
    mutations.append(("method_patch", rebuild(path), "PATCH", None))
    mutations.append(("method_override_header", rebuild(path), "POST", "PUT"))

    # 6. One junk query parameter appended
    junk_query = (parts.query + "&" if parts.query else "") + "_mythos_cb=1"
    mutations.append(("junk_query_param", rebuild(path, junk_query), "GET", None))

    return mutations


def test_path_mutation_bypass(url, extra_headers=None, burst_count=35):
    """Path/method/casing mutation test: for a URL the scanner already
    confirmed is rate-limited, re-confirm the baseline 429 still fires
    right now, then burst a small mutation set and flag any mutation that
    returns a response matching the pre-limit SUCCESS shape instead of a
    429 -- checking response shape (status + body-length band), not just
    status code alone, specifically to avoid soft-404 false positives.
    Cheap: only 6-10 extra mutation variants per already-confirmed-limited
    endpoint, each bursted up to burst_count times.
    """
    log(f"Testing path/method/casing mutation bypass on {url}...")
    findings = []

    rate_limited_at, reference_shape = reconfirm_rate_limit(url, extra_headers, burst_count)
    if rate_limited_at is None:
        log("  Original path did not re-confirm a 429 within the burst -- skipping mutation test")
        return findings
    if reference_shape is None:
        log("  No pre-429 success response captured to compare shapes against -- skipping mutation test")
        return findings

    for description, mutated_url, method, override_value in generate_path_mutations(url):
        mutation_hit_429 = False
        matched_shape = None

        for _ in range(burst_count):
            req_headers = dict(extra_headers) if extra_headers else {}
            if override_value:
                req_headers["X-HTTP-Method-Override"] = override_value
            status, _, body = http_request(mutated_url, method=method, headers=req_headers)
            if status == 429:
                mutation_hit_429 = True
                break
            shape = _response_shape(status, body)
            if _shapes_match(reference_shape, shape):
                matched_shape = shape
                break

        if not mutation_hit_429 and matched_shape:
            vuln(f"Rate limit bypass via path mutation ({description}): {mutated_url}")
            findings.append({
                "type": "rate_limit_path_mutation",
                "severity": "high",
                "url": url,
                "mutated_url": mutated_url,
                "mutation": description,
                "method": method,
                "original_rate_limited_at": rate_limited_at,
                "reference_success_shape": reference_shape,
                "matched_success_shape": matched_shape,
                "note": (
                    "Architectural pattern matches CVE-2023-38507 (Strapi "
                    "admin-login rate limiter compared the raw request path "
                    "as a plain string, so case variation and a trailing "
                    "slash each bypassed it -- fixed in 4.12.1) and "
                    "CVE-2025-71399 (Better Auth/rou3 path normalization "
                    "strips empty segments, so slash-padded paths reach the "
                    "handler while evading a literal-string path-based rate "
                    "limit -- fixed in 1.4.5)."
                ),
            })

    return findings


# CDN-vs-origin differential test (research_notes/.../rate_limit_
# versioning.md, "API gateway / reverse-proxy rate-limit inconsistencies"
# section): replay the identical rate-limit burst against an edge/CDN-
# fronted URL and a direct-to-origin URL for the same path+method: a
# bypass is confirmed when the edge-fronted URL 429s but the direct-
# origin URL does not. Deliberately NOT wired up as a CLI flag here --
# the research is explicit this needs a second base URL as an input (the
# origin address) that cannot be derived from path mutation alone, and
# half-wiring a --origin-base flag without a solid differential-comparison
# path (reusing send_rapid_requests()/send_concurrent_requests() against
# both base URLs for the same path, then comparing rate_limited_at the
# same way check_rate_limit_control_bypass() does in api_discovery.py)
# would ship something shakier than the rest of this file. Documented as
# a capability a future pass can wire up once an orchestrating skill/
# agent has both addresses (e.g. from recon-dominator-style output)
# rather than attempted half-done here.


_SENSITIVE_OPERATION_RE = re.compile(
    r"login|signin|sign_in|otp|verify|password|reset|mfa|2fa|changepassword", re.IGNORECASE
)


def test_graphql_batching(url, extra_headers=None, delay=0, baseline_max=60):
    """Test GraphQL query batching/aliasing as a rate-limit bypass.

    Upgraded per rate_limit_versioning.md's "Direct extension of the
    script's existing test_graphql_batching()" inference: first
    establishes a baseline by sending the UNBATCHED single operation
    repeatedly until a 429 appears (or confirmed absent after
    baseline_max attempts) -- count K. Then sends the batched/aliased
    form with K+50 copies of the identical operation in ONE request. A
    200 with all K+50 executed, when the unbatched form 429'd at K, is
    the actual gateway-blindness differential (the edge/network rate
    limiter counts HTTP requests, not GraphQL operations -- Checkmarx
    "Didn't Notice Your Rate Limiting: GraphQL Batching Attack";
    HackTricks rate-limit-bypass). Falls back to the original
    unconditional-acceptance check when no baseline 429 is ever observed
    (nothing to differentially confirm against, so it's reported as the
    weaker "accepted" signal instead).

    Checkmarx dedup caveat (noted, not automatable here): some GraphQL
    servers deduplicate IDENTICAL aliased/batched subqueries server-side
    before execution, so the request SHAPE being accepted (N operations
    in one HTTP response) is proof the EDGE/network rate limiter was
    blind to the attempt -- it is not independent proof the backend
    executed the operation N times.
    """
    log("Testing GraphQL batching...")
    findings = []

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    single_query = json.dumps({"query": "{ __typename }"})

    # Phase 1: baseline -- unbatched single operation, repeated until 429
    # or until baseline_max is exhausted.
    baseline_hit = None
    for i in range(baseline_max):
        status, _, _ = http_request(url, "POST", headers, single_query)
        if delay:
            time.sleep(delay)
        if status == 429:
            baseline_hit = i + 1
            break

    dedup_caveat = (
        "Caveat (Checkmarx): some servers dedupe identical aliased/batched "
        "subqueries server-side, so request-shape acceptance alone proves "
        "the EDGE rate limiter was blind to the attempt, not independently "
        "that the backend executed it N times."
    )

    if baseline_hit is not None:
        k_plus = baseline_hit + 50

        # Array batching: K+50 copies of the identical operation
        batch_query = json.dumps([{"query": "{ __typename }"}] * k_plus)
        status, _, body = http_request(url, "POST", headers, batch_query)
        if delay:
            time.sleep(delay)

        if status == 200:
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) >= k_plus:
                    vuln(f"GraphQL array-batch gateway-blindness bypass: {len(data)} executed "
                         f"in one request, vs unbatched 429 at request #{baseline_hit}")
                    findings.append({
                        "type": "graphql_batch_rate_limit_bypass",
                        "severity": "medium",
                        "url": url,
                        "unbatched_rate_limited_at": baseline_hit,
                        "batch_size_sent": k_plus,
                        "batch_responses_received": len(data),
                        "description": (
                            "The unbatched single operation 429'd at request "
                            f"#{baseline_hit}, but an array-batched request containing "
                            f"{k_plus} copies of the identical operation in ONE HTTP call "
                            f"returned 200 with all {len(data)} executed. " + dedup_caveat
                        ),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        # Alias batching: K+50 aliases of the identical operation
        aliases = " ".join([f"q{i}: __typename" for i in range(k_plus)])
        alias_query = json.dumps({"query": f"{{ {aliases} }}"})
        status, _, body = http_request(url, "POST", headers, alias_query)
        if delay:
            time.sleep(delay)

        if status == 200 and f"q{k_plus - 1}" in body:
            vuln(f"GraphQL alias-batch gateway-blindness bypass: {k_plus} aliases executed "
                 f"in one request, vs unbatched 429 at request #{baseline_hit}")
            findings.append({
                "type": "graphql_alias_rate_limit_bypass",
                "severity": "medium",
                "url": url,
                "unbatched_rate_limited_at": baseline_hit,
                "aliases_sent": k_plus,
                "description": (
                    "The unbatched single operation 429'd at request "
                    f"#{baseline_hit}, but an alias-multiplied request with {k_plus} "
                    "aliases of the identical operation in ONE HTTP call returned 200 "
                    "with all of them executed. " + dedup_caveat
                ),
            })
    else:
        # No baseline 429 within baseline_max attempts -- nothing confirmed
        # to differentially bypass, so fall back to the original weaker
        # "is batching merely accepted at all" check.
        log(f"  No 429 observed on the unbatched operation within {baseline_max} attempts -- "
            "falling back to unconditional batching-acceptance check")

        batch_query = json.dumps([{"query": "{ __typename }"}] * 100)
        status, _, body = http_request(url, "POST", headers, batch_query)
        if delay:
            time.sleep(delay)
        if status == 200:
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) > 1:
                    vuln(f"GraphQL batching accepted: {len(data)} responses in single request")
                    findings.append({
                        "type": "graphql_batching",
                        "severity": "medium",
                        "url": url,
                        "queries_sent": 100,
                        "responses_received": len(data),
                        "description": (
                            "GraphQL allows query batching which can bypass per-request "
                            "rate limits (no 429 baseline was observed on the unbatched "
                            "form within the attempt budget, so this is acceptance "
                            "evidence only, not a confirmed differential bypass)."
                        ),
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        aliases = " ".join([f"q{i}: __typename" for i in range(100)])
        alias_query = json.dumps({"query": f"{{ {aliases} }}"})
        status, _, body = http_request(url, "POST", headers, alias_query)
        if delay:
            time.sleep(delay)
        if status == 200 and "q99" in body:
            vuln("GraphQL alias-based batching accepted (100 aliases)")
            findings.append({
                "type": "graphql_alias_batching",
                "severity": "medium",
                "url": url,
                "aliases_sent": 100,
                "description": (
                    "GraphQL allows alias-based query multiplication (no 429 baseline "
                    "was observed on the unbatched form within the attempt budget, so "
                    "this is acceptance evidence only, not a confirmed differential "
                    "bypass)."
                ),
            })

    # Severity escalation: the research flags severity high specifically
    # when the targeted operation suggests login/OTP/password-reset --
    # directly exploitable as unlimited-rate credential/OTP brute force.
    # The GraphQL operation name itself isn't available to this function
    # (the probe query is always the safe, side-effect-free __typename),
    # so the endpoint URL is the practical, available proxy signal.
    if _SENSITIVE_OPERATION_RE.search(url):
        for f in findings:
            if f["type"] in ("graphql_batch_rate_limit_bypass", "graphql_alias_rate_limit_bypass"):
                f["severity"] = "high"
                f["sensitive_operation_target"] = True

    return findings


def main():
    parser = argparse.ArgumentParser(description="Rate Limiter Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py or schema_builder.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--api-base", help="API base URL")
    parser.add_argument("--endpoint", help="Specific endpoint to test")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--count", type=int, default=120, help="Number of requests to send (default: 120)")
    parser.add_argument("--concurrent", action="store_true", help="Send requests concurrently")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    if not args.input and not args.api_base:
        parser.error("Either --input or --api-base is required")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    base_url = args.api_base or ""
    endpoints = []
    graphql_endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        base_url = base_url or input_data.get("meta", {}).get("base_url", "")
        for api in input_data.get("discovered_apis", []):
            url = api.get("url", "")
            if url:
                endpoints.append(url)
                if api.get("api_type") == "graphql":
                    graphql_endpoints.append(url)
        for ep in input_data.get("endpoints", []):
            url = ep.get("url", "")
            if url:
                endpoints.append(url)

    if args.endpoint:
        url = urllib.parse.urljoin(base_url, args.endpoint) if base_url else args.endpoint
        endpoints.insert(0, url)

    if not endpoints and base_url:
        endpoints = [base_url]

    log(f"Testing rate limiting for: {base_url}")
    log(f"Endpoints to test: {len(endpoints)}")
    log(f"Requests per endpoint: {args.count}")

    all_findings = []
    endpoint_results = []

    # Test each endpoint
    for url in endpoints[:15]:
        log(f"\nTesting rate limit: {url}")

        if args.concurrent:
            results = send_concurrent_requests(url, args.count, extra_headers=extra_headers)
        else:
            results = send_rapid_requests(url, args.count, extra_headers, args.delay)

        results["url"] = url
        endpoint_results.append(results)

        if results["rate_limited_at"]:
            success(f"  Rate limited at request #{results['rate_limited_at']}")
            if results.get("rate_limit_headers"):
                log(f"  Rate limit headers: {results['rate_limit_headers']}")
        else:
            count_429 = results["status_codes"].get("429", 0)
            if count_429 == 0:
                vuln(f"No rate limiting detected on {url} after {args.count} requests")
                all_findings.append({
                    "type": "no_rate_limit",
                    "severity": "medium",
                    "url": url,
                    "requests_sent": args.count,
                    "status_distribution": results["status_codes"],
                    "description": f"No 429 response after {args.count} rapid requests",
                })

        log(f"  Status distribution: {results['status_codes']}")

    # Test bypass techniques on rate-limited endpoints
    rate_limited_urls = [r["url"] for r in endpoint_results if r.get("rate_limited_at")]
    for url in rate_limited_urls[:5]:
        bypass_findings = test_rate_limit_bypass(url, extra_headers, args.delay)
        all_findings.extend(bypass_findings)

    # Path/method/casing mutation test -- only meaningful against an
    # endpoint already confirmed rate-limited (re-confirms the baseline
    # 429 itself before trying any mutation).
    for url in rate_limited_urls[:5]:
        mutation_findings = test_path_mutation_bypass(url, extra_headers)
        all_findings.extend(mutation_findings)

    # Race-condition baseline-vs-burst comparator -- auto-targeted at
    # endpoints whose URL suggests a limited-use/financial-impact
    # resource (coupon/invite/credit/etc.), the Stripe/Dropbox/Instacart/
    # Reverb bounty class, rather than racing every endpoint blindly.
    race_candidates = find_race_condition_candidates(endpoints)
    for cand in race_candidates[:5]:
        race_count = min(args.count, 25)
        race_findings, _ = test_race_condition(cand["url"], extra_headers, count=race_count,
                                                is_financial_target=True)
        all_findings.extend(race_findings)

    # Test GraphQL batching
    for gql_url in graphql_endpoints[:3]:
        gql_findings = test_graphql_batching(gql_url, extra_headers, args.delay)
        all_findings.extend(gql_findings)

    # Also test common GraphQL paths
    if not graphql_endpoints:
        for path in ["/graphql", "/api/graphql", "/v1/graphql"]:
            gql_url = urllib.parse.urljoin(base_url, path)
            status, _, _ = http_request(gql_url, "POST",
                                         {"Content-Type": "application/json"},
                                         json.dumps({"query": "{__typename}"}))
            if status in (200, 400):
                gql_findings = test_graphql_batching(gql_url, extra_headers, args.delay)
                all_findings.extend(gql_findings)

    # Summary stats
    rate_limited_count = sum(1 for r in endpoint_results if r.get("rate_limited_at"))
    no_limit_count = len(endpoint_results) - rate_limited_count

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "rate_limit_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "endpoints_tested": len(endpoint_results),
            "rate_limited": rate_limited_count,
            "not_rate_limited": no_limit_count,
            "total_findings": len(all_findings),
            "requests_per_endpoint": args.count,
        },
        "endpoint_results": endpoint_results,
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"rate_limit_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  RATE LIMIT TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Endpoints tested    : {len(endpoint_results)}")
    print(f"  Requests per test   : {args.count}")
    print(f"  Rate limited        : {rate_limited_count}")
    print(f"  NOT rate limited    : {no_limit_count}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Bypass techniques   : {len([f for f in all_findings if 'bypass' in f.get('type', '')])}")
    print(f"  GraphQL batching    : {len([f for f in all_findings if 'graphql' in f.get('type', '')])}")
    print(f"  Race conditions     : {len([f for f in all_findings if f.get('type') == 'rate_limit_race_condition'])}")
    print(f"  Path mutations      : {len([f for f in all_findings if f.get('type') == 'rate_limit_path_mutation'])}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
