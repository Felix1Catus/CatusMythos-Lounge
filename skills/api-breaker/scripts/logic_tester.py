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
RACE_REQUESTS_PER_CASE = 10
RACE_MAX_REQUEST_BUDGET = 840
RACE_ACCEPTED_STATUSES = {200, 201, 202}


class RequestBudget:
    """Bound race-payload, control, and state-readback requests for one run."""

    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self._warned = False

    @property
    def remaining(self):
        return self.limit - self.used

    def can_consume(self, amount):
        return amount <= self.remaining

    def consume(self, amount=1):
        if not self.can_consume(amount):
            return False
        self.used += amount
        return True

    def warn_exhausted(self):
        if not self._warned:
            warn(
                f"Race request budget exhausted after {self.used}/{self.limit} "
                "requests; remaining race cases were skipped."
            )
            self._warned = True


def _explicit_applied_coupon_collection(body):
    """Find an explicit applied-coupon collection with at least two entries.

    Generic 2xx responses, mentions of "success", and echoes of request keys
    such as ``coupons`` are not evidence that multiple discounts were applied.
    This returns only a low-confidence response signal; it does not prove a
    changed total or persisted business state.
    """
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

    applied_keys = {
        "appliedcoupon", "appliedcoupons", "applieddiscount",
        "applieddiscounts", "applieddiscountcodes", "appliedcouponcount",
        "applieddiscountcount", "discountsapplied", "couponcodesapplied",
        "numberofappliedcoupons",
    }
    pending = [document]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                normalized_key = "".join(ch for ch in str(key).casefold() if ch.isalnum())
                if normalized_key in applied_keys:
                    if isinstance(value, list):
                        entry_count = sum(
                            1 for item in value
                            if (isinstance(item, str) and item.strip())
                            or (isinstance(item, dict) and bool(item))
                            or (isinstance(item, (int, float)) and not isinstance(item, bool))
                        )
                    elif isinstance(value, dict):
                        entry_count = sum(
                            1 for key, item in value.items()
                            if str(key).strip() and item is not None and item is not False
                        )
                    elif isinstance(value, int) and not isinstance(value, bool):
                        entry_count = value
                    else:
                        entry_count = 0
                    if entry_count >= 2:
                        return {
                            "application_field": str(key),
                            "applied_entry_count": entry_count,
                        }
                if isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(current, list):
            pending.extend(item for item in current if isinstance(item, (dict, list)))
    return None


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


def _json_pointer_tokens(pointer):
    """Parse an RFC 6901 JSON Pointer, returning None when it is malformed."""
    if pointer == "":
        return []
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None

    tokens = []
    for raw_token in pointer[1:].split("/"):
        decoded = []
        index = 0
        while index < len(raw_token):
            char = raw_token[index]
            if char != "~":
                decoded.append(char)
                index += 1
                continue
            if index + 1 >= len(raw_token) or raw_token[index + 1] not in "01":
                return None
            decoded.append("~" if raw_token[index + 1] == "0" else "/")
            index += 2
        tokens.append("".join(decoded))
    return tokens


def _numeric_json_pointer(body, pointer):
    """Read a finite numeric JSON value without accepting booleans as numbers."""
    tokens = _json_pointer_tokens(pointer)
    if tokens is None:
        return None
    try:
        value = json.loads(body)
        for token in tokens:
            if isinstance(value, dict):
                if token not in value:
                    return None
                value = value[token]
            elif isinstance(value, list) and token.isascii() and token.isdecimal():
                if token != "0" and token.startswith("0"):
                    return None
                position = int(token)
                if position >= len(value):
                    return None
                value = value[position]
            else:
                return None
    except (json.JSONDecodeError, TypeError, ValueError, IndexError, RecursionError):
        return None

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if math.isfinite(value) else None
    except (OverflowError, TypeError, ValueError):
        return None


def _read_race_state(state_url, headers, pointer, request_budget=None):
    if request_budget is not None and not request_budget.consume():
        return None
    status, _, body = http_request(state_url, method="GET", headers=headers)
    if status != 200:
        return None
    return _numeric_json_pointer(body, pointer)


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
            evidence = _explicit_applied_coupon_collection(body)
            if evidence:
                warn(f"Coupon stacking candidate: response suggests handling for {test['name']} on {url}")
                findings.append({
                    "type": "coupon_stacking_candidate",
                    "severity": "INFO",
                    "confidence": "low",
                    "validated": False,
                    "evidence": (
                        "A 2xx JSON response returned at least two entries in an explicit "
                        "applied-coupon/discount collection; the calculated total and "
                        "persisted business state remain unverified."
                    ),
                    **evidence,
                    "test_name": test["name"],
                    "url": url,
                    "method": method,
                    "payload": test["payload"],
                    "status": status,
                    "response_preview": safe_response_preview(body, max_chars=300),
                })

    return findings


def test_race_condition(
    url,
    method,
    auth_headers,
    delay=0,
    state_readback_url=None,
    state_json_pointer=None,
    request_budget=None,
):
    """Compare a sequential control with a bounded concurrent request burst.

    Supplying a read-back URL and numeric JSON Pointer adds a sequential
    one-request control and state comparison for each payload. These controls
    are active writes; the caller must use a disposable, authorized test
    object and a read-only same-origin state endpoint.
    """
    log(f"Testing race conditions: {url}")
    findings = []

    if (state_readback_url is None) != (state_json_pointer is None):
        raise ValueError("state read-back URL and JSON Pointer must be provided together")
    if state_json_pointer is not None and _json_pointer_tokens(state_json_pointer) is None:
        raise ValueError("state JSON Pointer is malformed")

    headers = dict(auth_headers)
    headers["Content-Type"] = "application/json"

    # Send identical requests concurrently
    test_payloads = [
        {"name": "double_spend", "payload": {"amount": 1}},
        {"name": "double_redeem", "payload": {"coupon": "TEST", "action": "redeem"}},
        {"name": "double_submit", "payload": {"action": "submit"}},
    ]

    for test in test_payloads:
        # A state-aware case can use one pre-read, one sequential write, one
        # post-control read, ten concurrent writes, and one final read.
        case_budget = RACE_REQUESTS_PER_CASE + (4 if state_readback_url else 0)
        if request_budget is not None and not request_budget.can_consume(case_budget):
            request_budget.warn_exhausted()
            break

        data = json.dumps(test["payload"])
        success_count = 0
        baseline_status = None
        baseline_delta = None
        baseline_state_observed = False
        control_state = None
        before_state = None

        if state_readback_url:
            before_state = _read_race_state(
                state_readback_url, auth_headers, state_json_pointer, request_budget
            )
            if before_state is not None:
                if request_budget is None or request_budget.consume():
                    baseline_status, _, _ = http_request(
                        url, method=method, headers=headers, data=data
                    )
                    control_state = _read_race_state(
                        state_readback_url, auth_headers, state_json_pointer,
                        request_budget,
                    )
                    if (
                        baseline_status in RACE_ACCEPTED_STATUSES
                        and control_state is not None
                    ):
                        baseline_delta = control_state - before_state
                        baseline_state_observed = True

        if request_budget is not None and not request_budget.consume(
            RACE_REQUESTS_PER_CASE
        ):
            request_budget.warn_exhausted()
            break
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _ in range(RACE_REQUESTS_PER_CASE):
                futures.append(
                    executor.submit(http_request, url, method, headers, data)
                )

            for future in concurrent.futures.as_completed(futures):
                try:
                    status, _, _ = future.result()
                except Exception:
                    status = 0
                if status in RACE_ACCEPTED_STATUSES:
                    success_count += 1

        concurrent_state = None
        if state_readback_url:
            concurrent_state = _read_race_state(
                state_readback_url, auth_headers, state_json_pointer, request_budget
            )

        if state_readback_url and baseline_state_observed and baseline_delta == 0:
            warn(
                f"Race state baseline did not change for {test['name']}; "
                "check whether the selected pointer tracks this action."
            )
            continue

        comparable_state = (
            baseline_status in RACE_ACCEPTED_STATUSES
            and baseline_delta is not None
            and baseline_delta != 0
            and control_state is not None
            and concurrent_state is not None
        )
        state_effect_multiple = None
        if comparable_state:
            concurrent_delta = concurrent_state - control_state
            state_effect_multiple = concurrent_delta / baseline_delta
            if not math.isfinite(state_effect_multiple):
                state_effect_multiple = None
                comparable_state = False

        if comparable_state:
            # A valid one-request baseline lets the operator-provided numeric
            # state indicator distinguish 2xx response echoes from an excess
            # side effect. If the state changed no more than once, suppress it.
            if (
                success_count <= 1
                or state_effect_multiple is None
                or state_effect_multiple <= 1.000001
            ):
                continue
            evidence = (
                "The configured numeric state read-back changed more than the "
                "one-request sequential control after the concurrent burst. "
                "Confirm that the measured state transition should occur only once."
            )
        else:
            if success_count <= 1:
                continue
            if state_readback_url:
                evidence = (
                    "Multiple concurrent requests returned 2xx, but the configured "
                    "sequential baseline and numeric state read-back were not "
                    "comparable; duplicate side effects remain unverified."
                )
            else:
                evidence = (
                    "Multiple concurrent requests returned 2xx; no sequential "
                    "baseline or state read-back was supplied, so duplicate side "
                    "effects remain unverified."
                )

        warn(
            f"Race condition candidate: {success_count}/{RACE_REQUESTS_PER_CASE} "
            f"requests returned 2xx ({test['name']}); review state evidence"
        )
        finding = {
            "type": "race_condition_candidate",
            "severity": "INFO",
            "confidence": "low",
            "validated": False,
            "evidence": evidence,
            "test_name": test["name"],
            "url": url,
            "method": method,
            "concurrent_requests": RACE_REQUESTS_PER_CASE,
            "successful_requests": success_count,
            "description": (
                f"{success_count} of {RACE_REQUESTS_PER_CASE} identical "
                "concurrent requests succeeded"
            ),
        }
        if baseline_status is not None:
            finding["sequential_baseline_status"] = baseline_status
        if state_effect_multiple is not None:
            finding["state_effect_multiple"] = round(state_effect_multiple, 4)
        findings.append(finding)

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
    parser.add_argument(
        "--race-request-budget",
        type=int,
        default=RACE_MAX_REQUEST_BUDGET,
        help=(
            "Maximum race payload, sequential-control, and state-readback "
            f"requests across this run (10-{RACE_MAX_REQUEST_BUDGET}; default: "
            f"{RACE_MAX_REQUEST_BUDGET})"
        ),
    )
    parser.add_argument(
        "--race-state-url",
        help="Optional same-origin read-only GET URL for race state verification",
    )
    parser.add_argument(
        "--race-state-json-pointer",
        help=(
            "RFC 6901 pointer to a finite numeric state counter; use with "
            "--race-state-url to compare one sequential control with the burst"
        ),
    )
    args = parser.parse_args()

    if not math.isfinite(args.delay) or args.delay < 0 or args.delay > 60:
        parser.error("--delay must be between 0 and 60 seconds")
    if not RACE_REQUESTS_PER_CASE <= args.race_request_budget <= RACE_MAX_REQUEST_BUDGET:
        parser.error(
            f"--race-request-budget must be between {RACE_REQUESTS_PER_CASE} "
            f"and {RACE_MAX_REQUEST_BUDGET}"
        )
    if (args.race_state_url is None) != (args.race_state_json_pointer is None):
        parser.error("--race-state-url and --race-state-json-pointer must be used together")

    base_url = same_origin_url(args.api_base, args.api_base)
    if not base_url:
        parser.error("--api-base must be a credential-free absolute HTTP(S) URL")

    state_readback_url = None
    if args.race_state_url is not None:
        if not args.race_state_url:
            parser.error("--race-state-url must not be empty")
        state_readback_url = same_origin_url(base_url, args.race_state_url)
        if not state_readback_url:
            parser.error("--race-state-url must remain on the trusted --api-base origin")
        if _json_pointer_tokens(args.race_state_json_pointer) is None:
            parser.error("--race-state-json-pointer must be a valid RFC 6901 JSON Pointer")
        if args.race_request_budget < RACE_REQUESTS_PER_CASE + 4:
            parser.error(
                "--race-request-budget must be at least 14 when state verification is enabled"
            )

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
    race_request_budget = RequestBudget(args.race_request_budget)

    # E-commerce tests
    for ep in classified["ecommerce"][:10] if not args.endpoint else []:
        url = ep["url"]
        method = ep["method"]

        all_findings.extend(test_price_manipulation(url, method, auth_headers, args.delay))
        all_findings.extend(test_quantity_overflow(url, method, auth_headers, args.delay))
        all_findings.extend(test_coupon_stacking(url, method, auth_headers, args.delay))
        all_findings.extend(test_race_condition(
            url, method, auth_headers, args.delay,
            state_readback_url=state_readback_url,
            state_json_pointer=args.race_state_json_pointer,
            request_budget=race_request_budget,
        ))

    # Financial tests
    for ep in classified["financial"][:10] if not args.endpoint else []:
        url = ep["url"]
        method = ep["method"]

        all_findings.extend(test_negative_amounts(url, method, auth_headers, args.delay))
        all_findings.extend(test_race_condition(
            url, method, auth_headers, args.delay,
            state_readback_url=state_readback_url,
            state_json_pointer=args.race_state_json_pointer,
            request_budget=race_request_budget,
        ))

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
        all_findings.extend(test_race_condition(
            url, "POST", auth_headers, args.delay,
            state_readback_url=state_readback_url,
            state_json_pointer=args.race_state_json_pointer,
            request_budget=race_request_budget,
        ))
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
            "race_requests_attempted": race_request_budget.used,
            "race_request_budget": race_request_budget.limit,
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
