#!/usr/bin/env python3
"""
unbounded_consumption_tester.py — Authorized OWASP LLM10 (Unbounded
Consumption) exposure checks.

Unlike prompt_injection_tester.py, this is not a payload-and-judge design:
OWASP's LLM10:2025 category (DoS, denial-of-wallet, model extraction via API)
is tested by checking the ABSENCE of controls named in OWASP's own mitigation
list, via small, safe, non-destructive requests -- never an actual
cost-exhaustion flood. See research_notes/AI agent security depth
techniques/jailbreak_and_extraction.md: "a response-header/behavior probe,
not a payload corpus... architecturally a sibling to model_supply_chain.py
(non-conversational, non-judge-based)".

Checks:
  - oversized-input rejection (input-size validation)
  - logprobs/logit_bias exposure (the exact surface Carlini et al.'s
    embedding-extraction attack exploits)
  - server-side max_tokens capping (acceptance-time validation only --
    never lets a huge generation actually run to completion)
  - standard rate-limit response headers
  - 429 behavior under a small, pre-capped burst (default 5 requests)

Usage:
    python unbounded_consumption_tester.py --url https://app.test/api/chat --field message
    python unbounded_consumption_tester.py --demo
"""
import argparse
import json
import logging
import sys
import time
from typing import Any

logger = logging.getLogger("unbounded_consumption_tester")

try:
    import requests
except ImportError:
    requests = None

OVERSIZED_INPUT_CHARS = 200_000
ABSURD_MAX_TOKENS = 10_000_000
MAX_SAFE_BURST_SIZE = 20  # refuse anything larger -- this tool stays non-destructive by design

RATE_LIMIT_HEADER_NAMES = {
    "x-ratelimit-limit-requests", "x-ratelimit-remaining-requests",
    "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens",
    "ratelimit-limit", "ratelimit-remaining", "retry-after",
}


def dotted_get(obj: Any, path: str) -> Any:
    """Also indexes into a list via a numeric path segment -- see the
    identical fix/rationale in prompt_injection_tester.py's copy of this
    function."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur


def _contains_key_substring(obj: Any, substring: str) -> bool:
    """Recursively search a parsed JSON response for any key containing
    `substring` (case-insensitive) -- used to detect logprobs data showing
    up in a response regardless of the API's exact response shape."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if substring in str(k).lower():
                return True
            if _contains_key_substring(v, substring):
                return True
    elif isinstance(obj, list):
        return any(_contains_key_substring(item, substring) for item in obj)
    return False


def _post(url: str, body: dict, headers: dict, timeout: int):
    """Returns (status_code, response_headers, parsed_json_or_None,
    raw_text_or_None, error_or_None). Never raises -- every failure mode
    (timeout, connection error, non-JSON body) is reported as data, since
    several of these checks treat the FAILURE itself as the safe outcome."""
    try:
        r = requests.post(url, json=body, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return None, {}, None, None, "timeout"
    except requests.exceptions.RequestException as e:
        return None, {}, None, None, str(e)
    text = r.text
    try:
        parsed = r.json()
    except ValueError:
        parsed = None
    return r.status_code, r.headers, parsed, text, None


def check_oversized_input(url: str, field: str, headers: dict, timeout: int) -> dict:
    """OWASP LLM10 mitigation: 'strict input-size validation'. A single
    oversized request, short timeout -- never a flood."""
    body = {field: "A" * OVERSIZED_INPUT_CHARS}
    status, _hdrs, _parsed, _text, err = _post(url, body, headers, timeout)
    if err == "timeout":
        return {"check": "oversized_input", "verdict": "inconclusive",
                "detail": f"request timed out after {timeout}s with no rejection -- "
                          f"inconclusive, not confirmed either way"}
    if err:
        return {"check": "oversized_input", "verdict": "inconclusive", "detail": f"request failed: {err}"}
    if status and 400 <= status < 500:
        return {"check": "oversized_input", "verdict": "safe",
                "detail": f"HTTP {status} -- oversized input rejected"}
    return {"check": "oversized_input", "verdict": "exposed",
            "detail": f"HTTP {status} -- a {OVERSIZED_INPUT_CHARS}-char input was accepted "
                      f"rather than rejected (no apparent input-size validation)"}


def check_logprobs_exposure(url: str, field: str, headers: dict, timeout: int) -> dict:
    """OWASP LLM10 mitigation: 'restrict/obfuscate logit_bias/logprobs
    exposure' -- directly the surface Carlini et al.'s embedding-layer
    extraction attack exploits (arXiv:2403.06634)."""
    body = {field: "hello", "logprobs": True, "top_logprobs": 5, "logit_bias": {}}
    status, _hdrs, parsed, text, err = _post(url, body, headers, timeout)
    if err:
        return {"check": "logprobs_exposure", "verdict": "inconclusive", "detail": f"request failed: {err}"}
    haystack = parsed if parsed is not None else (text or "")
    exposed = _contains_key_substring(parsed, "logprob") if parsed is not None else "logprob" in str(haystack).lower()
    if exposed:
        return {"check": "logprobs_exposure", "verdict": "exposed",
                "detail": f"HTTP {status} -- response includes logprob data when requested, "
                          f"unrestricted (OWASP-named mitigation absent)"}
    return {"check": "logprobs_exposure", "verdict": "safe",
            "detail": f"HTTP {status} -- no logprob data observed in the response "
                      f"(either restricted, or the field is unsupported/ignored by this endpoint)"}


def check_max_tokens_capping(url: str, field: str, headers: dict, timeout: int) -> dict:
    """OWASP LLM10 mitigation: 'dynamic resource-allocation caps'. Checks
    ONLY the request-acceptance decision with a short timeout -- never lets
    an absurd generation actually run to completion."""
    body = {field: "Tell me a very long, detailed story.", "max_tokens": ABSURD_MAX_TOKENS}
    status, _hdrs, _parsed, _text, err = _post(url, body, headers, timeout)
    if err == "timeout":
        return {"check": "max_tokens_capping", "verdict": "unclear",
                "detail": f"no rejection observed within {timeout}s -- a well-behaved server should "
                          f"reject an absurd max_tokens value at acceptance time, not let it hang; "
                          f"not confirmed vulnerable, since full generation was never awaited"}
    if err:
        return {"check": "max_tokens_capping", "verdict": "inconclusive", "detail": f"request failed: {err}"}
    if status and 400 <= status < 500:
        return {"check": "max_tokens_capping", "verdict": "safe",
                "detail": f"HTTP {status} -- absurd max_tokens value ({ABSURD_MAX_TOKENS}) rejected at acceptance time"}
    return {"check": "max_tokens_capping", "verdict": "unclear",
            "detail": f"HTTP {status} -- request with max_tokens={ABSURD_MAX_TOKENS} was accepted "
                      f"without an early rejection (full generation was NOT awaited -- this does not "
                      f"confirm the value was honored, only that it wasn't validated up front)"}


def check_rate_limit_headers(url: str, field: str, headers: dict, timeout: int) -> dict:
    """OWASP LLM10 mitigation: 'rate limiting and per-user quotas'. One
    ordinary small request -- checks for standard rate-limit headers."""
    body = {field: "hello"}
    status, resp_headers, _parsed, _text, err = _post(url, body, headers, timeout)
    if err:
        return {"check": "rate_limit_headers", "verdict": "inconclusive", "detail": f"request failed: {err}"}
    present = {h for h in RATE_LIMIT_HEADER_NAMES if h in {k.lower() for k in resp_headers.keys()}}
    if present:
        return {"check": "rate_limit_headers", "verdict": "safe",
                "detail": f"HTTP {status} -- rate-limit header(s) present: {', '.join(sorted(present))}"}
    return {"check": "rate_limit_headers", "verdict": "exposed",
            "detail": f"HTTP {status} -- no standard rate-limit response header observed "
                      f"(doesn't rule out an undisclosed internal limit, but nothing is surfaced to a caller)"}


def check_burst_behavior(url: str, field: str, headers: dict, timeout: int, burst_size: int) -> dict:
    """OWASP LLM10 mitigation: 'rate limiting'. A small, pre-capped burst
    (never larger than MAX_SAFE_BURST_SIZE) -- a weak signal at this size,
    worded honestly as inconclusive rather than a confirmed absence."""
    burst_size = min(burst_size, MAX_SAFE_BURST_SIZE)
    statuses = []
    for _ in range(burst_size):
        status, _hdrs, _parsed, _text, err = _post(url, {field: "hello"}, headers, timeout)
        statuses.append(status if not err else f"error:{err}")
    if 429 in statuses:
        return {"check": "burst_429_behavior", "verdict": "safe",
                "detail": f"HTTP 429 observed within {burst_size} rapid requests: {statuses}"}
    return {"check": "burst_429_behavior", "verdict": "inconclusive",
            "detail": f"no HTTP 429 observed within only {burst_size} rapid requests: {statuses} -- "
                      f"a small sample size, not proof rate limiting is absent"}


ALL_CHECKS = [check_oversized_input, check_logprobs_exposure, check_max_tokens_capping, check_rate_limit_headers]


def export_findings(results: list[dict], url: str) -> list[dict]:
    """Shape 'exposed' verdicts into vuln-chain-composer's expected raw-
    finding format. Deliberately NOT given a chainable_as tag in
    import_findings.py -- this is a configuration/exposure gap (same shape
    as the existing "missing_headers"/"info_disclosure" types), not a
    graph-chainable primitive like scope_violation/rce_potential."""
    findings = []
    for r in results:
        if r["verdict"] != "exposed":
            continue
        findings.append({
            "type": "unboundedconsumption",
            "url": url,
            "evidence": f"OWASP LLM10 check '{r['check']}' found a missing control: {r['detail']}",
            "payload": r["check"],
            "severity": "LOW",
            "note": "unbounded_consumption_tester.py",
        })
    return findings


def _run_demo() -> int:
    """Offline self-test: verify each check's verdict logic against
    canned (status, headers, json, text, err) tuples, without any real
    network call."""
    cases_ok = True

    def fake_post(status=200, hdrs=None, parsed=None, text=None, err=None):
        def _fake(url, body, headers, timeout):
            return status, (hdrs or {}), parsed, text, err
        return _fake

    global _post
    orig = _post

    _post = fake_post(status=403)
    r = check_oversized_input("u", "f", {}, 5)
    ok = r["verdict"] == "safe"
    print(f"  [{'OK' if ok else 'FAIL'}] oversized_input rejected (403) -> safe")
    cases_ok &= ok

    _post = fake_post(status=200)
    r = check_oversized_input("u", "f", {}, 5)
    ok = r["verdict"] == "exposed"
    print(f"  [{'OK' if ok else 'FAIL'}] oversized_input accepted (200) -> exposed")
    cases_ok &= ok

    _post = fake_post(status=200, parsed={"choices": [{"logprobs": {"tokens": ["a"]}}]})
    r = check_logprobs_exposure("u", "f", {}, 5)
    ok = r["verdict"] == "exposed"
    print(f"  [{'OK' if ok else 'FAIL'}] logprobs present in response -> exposed")
    cases_ok &= ok

    _post = fake_post(status=200, parsed={"choices": [{"message": "hi"}]})
    r = check_logprobs_exposure("u", "f", {}, 5)
    ok = r["verdict"] == "safe"
    print(f"  [{'OK' if ok else 'FAIL'}] logprobs absent from response -> safe")
    cases_ok &= ok

    _post = fake_post(status=422)
    r = check_max_tokens_capping("u", "f", {}, 5)
    ok = r["verdict"] == "safe"
    print(f"  [{'OK' if ok else 'FAIL'}] absurd max_tokens rejected (422) -> safe")
    cases_ok &= ok

    _post = fake_post(status=200)
    r = check_max_tokens_capping("u", "f", {}, 5)
    ok = r["verdict"] == "unclear"
    print(f"  [{'OK' if ok else 'FAIL'}] absurd max_tokens accepted (200) -> unclear (not awaited to completion)")
    cases_ok &= ok

    _post = fake_post(status=200, hdrs={"X-RateLimit-Limit-Requests": "100"})
    r = check_rate_limit_headers("u", "f", {}, 5)
    ok = r["verdict"] == "safe"
    print(f"  [{'OK' if ok else 'FAIL'}] rate-limit header present -> safe")
    cases_ok &= ok

    _post = fake_post(status=200, hdrs={})
    r = check_rate_limit_headers("u", "f", {}, 5)
    ok = r["verdict"] == "exposed"
    print(f"  [{'OK' if ok else 'FAIL'}] no rate-limit header at all -> exposed")
    cases_ok &= ok

    _post = orig
    print("[+] demo passed" if cases_ok else "[!] demo FAILED")
    return 0 if cases_ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Authorized OWASP LLM10 (Unbounded Consumption) exposure checks")
    ap.add_argument("--url", help="Target chat/completions endpoint (POST JSON)")
    ap.add_argument("--field", default="message", help="JSON key for the user input")
    ap.add_argument("--header", action="append", default=[], help="Extra header 'K: V' (repeatable)")
    ap.add_argument("--timeout", type=int, default=10, help="Per-request timeout (seconds) -- kept short; "
                                                               "this tool never awaits a full large generation")
    ap.add_argument("--burst-size", type=int, default=5,
                     help=f"Requests in the burst/429 check, capped at {MAX_SAFE_BURST_SIZE} regardless of this value")
    ap.add_argument("--output", help="Write JSON results")
    ap.add_argument("--export-findings", help="Write 'exposed' results as vuln-chain-composer-ready "
                                                "findings JSON (feed straight to import_findings.py --input)")
    ap.add_argument("--demo", action="store_true", help="Run an offline self-test and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        sys.exit(_run_demo())
    if not args.url:
        ap.error("--url is required (or use --demo)")
    if requests is None:
        print("[!] pip install requests (required for live testing; --demo works offline)", file=sys.stderr)
        sys.exit(1)

    headers = {"Content-Type": "application/json"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    print(f"[*] Authorized LLM10 exposure checks -> {args.url}\n")
    results = []
    for check_fn in ALL_CHECKS:
        r = check_fn(args.url, args.field, headers, args.timeout)
        results.append(r)
        mark = {"exposed": "[VULN]", "safe": "[safe]", "inconclusive": "[?????]", "unclear": "[?????]"}.get(r["verdict"], "[     ]")
        print(f"  {mark} {r['check']:<24} {r['verdict']}")
        print(f"            {r['detail']}")

    burst = check_burst_behavior(args.url, args.field, headers, args.timeout, args.burst_size)
    results.append(burst)
    mark = {"exposed": "[VULN]", "safe": "[safe]", "inconclusive": "[?????]"}.get(burst["verdict"], "[     ]")
    print(f"  {mark} {burst['check']:<24} {burst['verdict']}")
    print(f"            {burst['detail']}")

    exposed_count = sum(1 for r in results if r["verdict"] == "exposed")
    print(f"\n=== {len(results)} check(s) run | {exposed_count} exposed ===")
    if exposed_count:
        print("[!] Missing OWASP LLM10 controls found -- see genai.owasp.org/llmrisk/llm102025-unbounded-consumption/")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"url": args.url, "results": results}, fh, indent=2)
        print(f"\n[+] Wrote {args.output}")

    if args.export_findings:
        findings = export_findings(results, args.url)
        with open(args.export_findings, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[+] Wrote {len(findings)} finding(s) to {args.export_findings}")


if __name__ == "__main__":
    main()
