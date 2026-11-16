#!/usr/bin/env python3
"""
Business Logic Tester Module - api-breaker
Tests for business logic vulnerabilities: price manipulation, race conditions, and more.
Author: orizon.one
"""

import argparse
import json
import time
import urllib.request
import urllib.parse
import concurrent.futures
from datetime import datetime, timezone
import math


from _common import http_request, log, same_origin_url, success, warn
from response_safety import safe_response_preview


MUTATING_METHODS = {"POST", "PUT", "PATCH"}
def classify_endpoints(endpoints):
    """Classify endpoints by likely business function."""
    classified = {
        "ecommerce": [],
        "financial": [],
        "user_management": [],
        "file_handling": [],
        "general": [],
    }

    ecommerce_patterns = ["order", "cart", "product", "checkout", "purchase", "coupon",
                           "discount", "promo", "shop", "store", "item", "catalog", "price"]
    financial_patterns = ["payment", "transfer", "transaction", "balance", "wallet",
                          "withdraw", "deposit", "refund", "invoice", "billing", "credit"]
    user_patterns = ["user", "account", "profile", "register", "signup", "role",
                     "permission", "password", "auth", "verify", "email", "2fa", "mfa"]
    file_patterns = ["file", "upload", "download", "image", "document", "media",
                     "attachment", "import", "export"]

    for ep in endpoints:
        if isinstance(ep, dict):
            path = str(ep.get("path") or ep.get("url") or "").lower()
        elif isinstance(ep, str):
            path = ep.lower()
        else:
            continue
        if not path:
            continue
        matched = False

        for pattern in ecommerce_patterns:
            if pattern in path:
                classified["ecommerce"].append(ep)
                matched = True
                break
        if matched:
            continue

        for pattern in financial_patterns:
            if pattern in path:
                classified["financial"].append(ep)
                matched = True
                break
        if matched:
            continue

        for pattern in user_patterns:
            if pattern in path:
                classified["user_management"].append(ep)
                matched = True
                break
        if matched:
            continue

        for pattern in file_patterns:
            if pattern in path:
                classified["file_handling"].append(ep)
                matched = True
                break

        if not matched:
            classified["general"].append(ep)

    return classified


def scope_business_logic_endpoints(base_url, endpoints):
    """Keep active business-logic probes on the operator-selected origin.

    Imported discovery files are data, not authorization. Every URL is
    canonicalized against the explicit --api-base before credentials or
    mutation payloads are sent.
    """
    scoped = []
    for ep in endpoints:
        if isinstance(ep, dict):
            candidate = ep.get("url") or ep.get("path") or ""
            record = dict(ep)
            method = str(ep.get("method") or "POST").upper()
        elif isinstance(ep, str):
            candidate = ep
            record = {"path": ep}
            method = "POST"
        else:
            warn(f"Skipping malformed business-logic endpoint: {ep!r}")
            continue

        url = same_origin_url(base_url, candidate)
        if not url:
            warn(f"Skipping endpoint outside the API base origin: {candidate}")
            continue
        if method not in MUTATING_METHODS:
            warn(f"Skipping non-write endpoint for business-logic probes: {method} {url}")
            continue

        record["url"] = url
        record["method"] = method
        scoped.append(record)
    return scoped


def _matching_json_fields(body, payload):
    """Return injected fields echoed with the exact JSON type and value."""
    try:
        response = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}

    matches = {}
    pending = [response]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for field, expected in payload.items():
                actual = current.get(field)
                if type(actual) is type(expected) and actual == expected:
                    matches[field] = actual
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return matches


def test_price_manipulation(url, method, auth_headers, delay=0):
    """Test price manipulation on e-commerce endpoints."""
    log(f"Testing price manipulation: {url}")
    findings = []

    test_cases = [
        {"name": "zero_price", "payload": {"price": 0}},
        {"name": "negative_price", "payload": {"price": -1}},
        {"name": "tiny_price", "payload": {"price": 0.001}},
        {"name": "zero_total", "payload": {"total": 0}},
        {"name": "negative_total", "payload": {"total": -100}},
        {"name": "zero_amount", "payload": {"amount": 0}},
        {"name": "negative_amount", "payload": {"amount": -50}},
        {"name": "max_discount", "payload": {"discount": 100}},
        {"name": "over_discount", "payload": {"discount": 150}},
        {"name": "negative_discount", "payload": {"discount": -100}},
        {"name": "zero_cost", "payload": {"cost": 0}},
        {"name": "currency_confusion", "payload": {"currency": "XXX", "amount": 1}},
    ]

    for test in test_cases:
        data = json.dumps(test["payload"])
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        status, _, body = http_request(url, method=method, headers=headers, data=data)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            echoed = _matching_json_fields(body, test["payload"])
            if echoed:
                warn(f"Price manipulation candidate: injected values echoed by {url}; verify persisted impact")
                findings.append({
                    "type": "price_manipulation_candidate",
                    "severity": "INFO",
                    "confidence": "low",
                    "validated": False,
                    "evidence": "The response echoed injected values; a persisted price/total change is unverified.",
                    "echoed_fields": echoed,
                    "test_name": test["name"],
                    "url": url,
                    "method": method,
                    "payload": test["payload"],
                    "status": status,
                    "response_preview": safe_response_preview(body, max_chars=300),
                })

    return findings


def test_quantity_overflow(url, method, auth_headers, delay=0):
    """Test quantity/integer overflow."""
    log(f"Testing quantity overflow: {url}")
    findings = []

    test_quantities = [
        {"name": "zero_quantity", "payload": {"quantity": 0}},
        {"name": "negative_quantity", "payload": {"quantity": -1}},
        {"name": "huge_quantity", "payload": {"quantity": 999999999}},
        {"name": "int_overflow", "payload": {"quantity": 2147483647}},
        {"name": "int_overflow_plus", "payload": {"quantity": 2147483648}},
        {"name": "float_quantity", "payload": {"quantity": 0.1}},
        {"name": "negative_count", "payload": {"count": -10}},
        {"name": "zero_count", "payload": {"count": 0}},
    ]

    for test in test_quantities:
        data = json.dumps(test["payload"])
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        status, _, body = http_request(url, method=method, headers=headers, data=data)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            echoed = _matching_json_fields(body, test["payload"])
            if not echoed:
                continue
            warn(f"Quantity overflow candidate: injected values echoed by {url}; verify persisted impact")
            findings.append({
                "type": "quantity_overflow_candidate",
                "severity": "INFO",
                "confidence": "low",
                "validated": False,
                "evidence": "The response echoed an injected quantity/count; range enforcement and persisted impact are unverified.",
                "echoed_fields": echoed,
                "test_name": test["name"],
                "url": url,
                "method": method,
                "payload": test["payload"],
                "status": status,
                "response_preview": safe_response_preview(body, max_chars=300),
            })

    return findings


def test_coupon_stacking(url, method, auth_headers, delay=0):
    """Test coupon/promo code stacking."""
    log(f"Testing coupon stacking: {url}")
    findings = []

    test_cases = [
        {"name": "multiple_coupons", "payload": {"coupons": ["TEST1", "TEST2", "TEST3"]}},
        {"name": "duplicate_coupon", "payload": {"coupon": "TEST1", "coupons": ["TEST1", "TEST1"]}},
        {"name": "coupon_array", "payload": {"discount_codes": ["A", "B", "C"]}},
        {"name": "empty_coupon", "payload": {"coupon": ""}},
        {"name": "wildcard_coupon", "payload": {"coupon": "*"}},
    ]

    for test in test_cases:
        data = json.dumps(test["payload"])
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        status, _, body = http_request(url, method=method, headers=headers, data=data)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            lower_body = body.lower()
            if any(kw in lower_body for kw in ["discount", "applied", "coupon", "success"]):
                warn(f"Coupon stacking candidate: response suggests handling for {test['name']} on {url}")
                findings.append({
                    "type": "coupon_stacking_candidate",
                    "severity": "INFO",
                    "confidence": "low",
                    "validated": False,
                    "evidence": "A 2xx response referenced coupon/discount handling; stacked discounts and persisted totals are unverified.",
                    "test_name": test["name"],
                    "url": url,
                    "method": method,
                    "payload": test["payload"],
                    "status": status,
                    "response_preview": safe_response_preview(body, max_chars=300),
                })

    return findings


def test_race_condition(url, method, auth_headers, delay=0):
    """Test double spending / race conditions via concurrent requests."""
    log(f"Testing race conditions: {url}")
    findings = []

    headers = dict(auth_headers)
    headers["Content-Type"] = "application/json"

    # Send identical requests concurrently
    test_payloads = [
        {"name": "double_spend", "payload": {"amount": 1}},
        {"name": "double_redeem", "payload": {"coupon": "TEST", "action": "redeem"}},
        {"name": "double_submit", "payload": {"action": "submit"}},
    ]

    for test in test_payloads:
        data = json.dumps(test["payload"])
        success_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _ in range(10):
                futures.append(
                    executor.submit(http_request, url, method, headers, data)
                )

            for future in concurrent.futures.as_completed(futures):
                status, _, body = future.result()
                if status in (200, 201):
                    success_count += 1

        if success_count > 1:
            warn(f"Race condition candidate: {success_count}/10 requests returned 2xx ({test['name']}); verify duplicate side effects")
            findings.append({
                "type": "race_condition_candidate",
                "severity": "INFO",
                "confidence": "low",
                "validated": False,
                "evidence": "Multiple concurrent requests returned 2xx; a sequential baseline and duplicate state change are unverified.",
                "test_name": test["name"],
                "url": url,
                "method": method,
                "concurrent_requests": 10,
                "successful_requests": success_count,
                "description": f"{success_count} of 10 identical concurrent requests succeeded",
            })

    return findings


def test_negative_amounts(url, method, auth_headers, delay=0):
    """Test negative amount transfers/operations."""
    log(f"Testing negative amounts: {url}")
    findings = []

    test_cases = [
        {"name": "negative_transfer", "payload": {"amount": -100, "to": "attacker"}},
        {"name": "negative_payment", "payload": {"amount": -50}},
        {"name": "negative_withdraw", "payload": {"amount": -200}},
        {"name": "negative_deposit", "payload": {"amount": -100}},
        {"name": "reverse_transfer", "payload": {"from_amount": -100, "to_amount": 100}},
    ]

    for test in test_cases:
        data = json.dumps(test["payload"])
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        status, _, body = http_request(url, method=method, headers=headers, data=data)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            warn(f"Negative amount candidate: {test['name']} returned 2xx on {url}; verify transaction impact")
            findings.append({
                "type": "negative_amount_candidate",
                "severity": "INFO",
                "confidence": "low",
                "validated": False,
                "evidence": "The negative-value request returned 2xx; a persisted balance or transaction change is unverified.",
                "test_name": test["name"],
                "url": url,
                "method": method,
                "payload": test["payload"],
                "status": status,
                "response_preview": safe_response_preview(body, max_chars=300),
            })

    return findings


def test_privilege_escalation(url, method, auth_headers, delay=0):
    """Test self-privilege escalation on user management endpoints."""
    log(f"Testing privilege escalation: {url}")
    findings = []

    test_cases = [
        {"name": "self_admin", "payload": {"role": "admin"}},
        {"name": "self_superuser", "payload": {"is_superuser": True}},
        {"name": "self_verify", "payload": {"email_verified": True, "verified": True}},
        {"name": "skip_2fa", "payload": {"two_factor_enabled": False, "mfa_enabled": False}},
        {"name": "unlock_account", "payload": {"locked": False, "suspended": False}},
        {"name": "change_permissions", "payload": {"permissions": ["*", "admin:*"]}},
        {"name": "change_group", "payload": {"group": "administrators"}},
    ]

    for test in test_cases:
        data = json.dumps(test["payload"])
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        for m in ([method] if method in ("PUT", "PATCH") else ["PUT", "PATCH"]):
            status, _, body = http_request(url, method=m, headers=headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201):
                echoed = _matching_json_fields(body, test["payload"])
                if echoed:
                    warn(f"Privilege escalation candidate: injected fields echoed by {url}; verify persisted authorization impact")
                    findings.append({
                        "type": "privilege_escalation_candidate",
                        "severity": "INFO",
                        "confidence": "low",
                        "validated": False,
                        "evidence": "The response echoed injected privilege fields; a persisted role/authorization change is unverified.",
                        "echoed_fields": echoed,
                        "test_name": test["name"],
                        "url": url,
                        "method": m,
                        "payload": test["payload"],
                        "status": status,
                        "response_preview": safe_response_preview(body, max_chars=300),
                    })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Business Logic Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from schema_builder.py or api_discovery.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--api-base", required=True,
                        help="Trusted API base URL; imported endpoint metadata is never trusted as scope")
    parser.add_argument("--endpoint", help="Specific endpoint to test")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    if not math.isfinite(args.delay) or args.delay < 0 or args.delay > 60:
        parser.error("--delay must be between 0 and 60 seconds")

    base_url = same_origin_url(args.api_base, args.api_base)
    if not base_url:
        parser.error("--api-base must be a credential-free absolute HTTP(S) URL")

    auth_headers = {}
    if args.cookie:
        auth_headers["Cookie"] = args.cookie
    if args.token:
        auth_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        if not isinstance(input_data, dict):
            parser.error("Input JSON must contain an object at the top level")
        for key in ("discovered_apis", "endpoints", "openapi_endpoints"):
            values = input_data.get(key, [])
            if isinstance(values, list):
                endpoints.extend(values)

    specific_url = None
    if args.endpoint:
        specific_url = same_origin_url(base_url, args.endpoint)
        if not specific_url:
            parser.error("--endpoint must remain on the trusted --api-base origin")
        endpoints.insert(0, {"path": args.endpoint, "url": specific_url, "method": "POST"})

    endpoints = scope_business_logic_endpoints(base_url, endpoints)

    log(f"Testing business logic for: {base_url}")
    log(f"Total endpoints: {len(endpoints)}")

    # Classify endpoints
    classified = classify_endpoints(endpoints)
    for category, eps in classified.items():
        if eps:
            log(f"  {category}: {len(eps)} endpoints")

    all_findings = []

    # E-commerce tests
    for ep in classified["ecommerce"][:10] if not args.endpoint else []:
        url = ep["url"]
        method = ep["method"]

        all_findings.extend(test_price_manipulation(url, method, auth_headers, args.delay))
        all_findings.extend(test_quantity_overflow(url, method, auth_headers, args.delay))
        all_findings.extend(test_coupon_stacking(url, method, auth_headers, args.delay))
        all_findings.extend(test_race_condition(url, method, auth_headers, args.delay))

    # Financial tests
    for ep in classified["financial"][:10] if not args.endpoint else []:
        url = ep["url"]
        method = ep["method"]

        all_findings.extend(test_negative_amounts(url, method, auth_headers, args.delay))
        all_findings.extend(test_race_condition(url, method, auth_headers, args.delay))

    # User management tests
    for ep in classified["user_management"][:10] if not args.endpoint else []:
        url = ep["url"]
        method = ep["method"]

        all_findings.extend(test_privilege_escalation(url, method, auth_headers, args.delay))

    # If a specific endpoint is given, run all tests
    if args.endpoint:
        url = specific_url
        log(f"\nRunning all logic tests on: {url}")
        all_findings.extend(test_price_manipulation(url, "POST", auth_headers, args.delay))
        all_findings.extend(test_quantity_overflow(url, "POST", auth_headers, args.delay))
        all_findings.extend(test_coupon_stacking(url, "POST", auth_headers, args.delay))
        all_findings.extend(test_negative_amounts(url, "POST", auth_headers, args.delay))
        all_findings.extend(test_race_condition(url, "POST", auth_headers, args.delay))
        all_findings.extend(test_privilege_escalation(url, "PUT", auth_headers, args.delay))

    # Deduplicate findings by (type, url, test_name)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.get("type", ""), f.get("url", ""), f.get("test_name", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    all_findings = unique_findings

    # Categorize
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "type": "business_logic_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "ecommerce_endpoints": len(classified["ecommerce"]),
            "financial_endpoints": len(classified["financial"]),
            "user_mgmt_endpoints": len(classified["user_management"]),
        },
        "classified_endpoints": {k: len(v) for k, v in classified.items()},
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"logic_test_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  BUSINESS LOGIC TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  E-commerce endpoints: {len(classified['ecommerce'])}")
    print(f"  Financial endpoints : {len(classified['financial'])}")
    print(f"  User mgmt endpoints : {len(classified['user_management'])}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
