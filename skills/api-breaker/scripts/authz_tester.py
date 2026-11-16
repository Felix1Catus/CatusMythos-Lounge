#!/usr/bin/env python3
"""
Authorization Tester Module - api-breaker
Tests for BOLA (Broken Object Level Authorization) and BFLA (Broken Function Level Authorization).
Author: orizon.one
"""

import argparse
import json
import math
import re
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone


from _common import http_request, log, same_origin_url, success, vuln, warn
# Admin/privileged endpoint patterns
ADMIN_PATTERNS = [
    "/admin", "/admin/", "/api/admin", "/api/v1/admin",
    "/manage", "/management", "/dashboard",
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/roles", "/api/permissions",
    "/api/settings", "/api/config", "/api/configuration",
    "/internal", "/api/internal",
    "/api/logs", "/api/audit",
    "/api/billing", "/api/subscriptions",
    "/api/export", "/api/import",
    "/api/reports", "/api/analytics",
    "/api/webhooks",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Common IDOR test IDs
TEST_IDS = ["1", "2", "0", "100", "999", "1000", "admin"]
OBJECT_ID_RESOURCES = {
    "users", "accounts", "orders", "items", "products", "posts", "messages",
    "documents", "files", "tickets",
}


def parse_delay(value):
    try:
        delay = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("delay must be a number") from exc
    if not math.isfinite(delay) or not 0 <= delay <= 60:
        raise argparse.ArgumentTypeError("delay must be finite and between 0 and 60 seconds")
    return delay


def extract_object_ids(body):
    """Extract potential object IDs from a response body."""
    ids = set()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ids

    def walk(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key.lower() in ("id", "uid", "user_id", "userid", "account_id",
                                    "accountid", "order_id", "orderid", "object_id"):
                    if val is not None and not isinstance(val, (bool, dict, list)):
                        object_id = str(val)
                        if object_id and len(object_id) <= 200 and not any(ord(c) < 32 for c in object_id):
                            ids.add(object_id)
                walk(val)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return ids


def find_id_endpoints(base_url, endpoints):
    """Find endpoints that contain ID placeholders or patterns."""
    id_endpoints = []

    for ep in endpoints:
        if isinstance(ep, dict):
            path = ep.get("path", "")
            if not path and ep.get("url"):
                path = urllib.parse.urlsplit(ep["url"]).path
        else:
            candidate = str(ep)
            parsed = urllib.parse.urlsplit(candidate)
            path = parsed.path if parsed.scheme or parsed.netloc else candidate

        # Match patterns like /users/1, /api/v1/orders/123
        if re.search(r'/\d+(?:/|$)', path) or re.search(r'/\{[^}]+\}', path):
            id_endpoints.append(ep)
        # Match common resource/id patterns
        elif re.search(
            r'/(?:users|accounts|orders|items|products|posts|messages|documents|files|tickets)/[^/?#]+(?:/|$)',
            path,
        ):
            id_endpoints.append(ep)

    return id_endpoints


def object_id_from_path(path):
    """Extract a concrete ID following a known collection segment."""
    parts = [segment for segment in urllib.parse.urlsplit(path).path.split("/") if segment]
    for index, segment in enumerate(parts[:-1]):
        if segment.lower() in OBJECT_ID_RESOURCES:
            candidate = urllib.parse.unquote(parts[index + 1])
            if candidate and not (candidate.startswith("{") and candidate.endswith("}")):
                return candidate
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None


def build_object_url(base_url, endpoint_url, object_id, is_id_endpoint=False):
    """Build an object URL without duplicating existing IDs or losing queries."""
    parsed = urllib.parse.urlsplit(endpoint_url)
    encoded_id = urllib.parse.quote(str(object_id), safe="")
    path = parsed.path or "/"

    if re.search(r"\{[^{}]+\}", path):
        path = re.sub(r"\{[^{}]+\}", lambda _match: encoded_id, path)
    elif not is_id_endpoint:
        path = path.rstrip("/") + "/" + encoded_id

    candidate = urllib.parse.urlunsplit(parsed._replace(path=path, fragment=""))
    return same_origin_url(base_url, candidate)


def build_initial_object_url(base_url, endpoint_url):
    """Replace OpenAPI-style path parameters before the initial object read."""
    parsed = urllib.parse.urlsplit(endpoint_url)
    if re.search(r"\{[^{}]+\}", parsed.path):
        return build_object_url(base_url, endpoint_url, TEST_IDS[0], is_id_endpoint=True)
    return same_origin_url(base_url, endpoint_url)


def test_bola(
    base_url, endpoints, token_a, token_b=None, extra_headers=None, delay=0,
    allow_mutation_write=False, cookie_b=None,
):
    """Test for Broken Object Level Authorization (BOLA/IDOR)."""
    log("Testing for BOLA (Broken Object Level Authorization)...")
    findings = []

    headers_a = {"Authorization": token_a if " " in token_a else f"Bearer {token_a}"}
    if extra_headers:
        headers_a.update(extra_headers)

    headers_b = {}
    if token_b:
        headers_b = {"Authorization": token_b if " " in token_b else f"Bearer {token_b}"}
        if extra_headers:
            headers_b.update({key: value for key, value in extra_headers.items()
                              if key.lower() != "cookie"})
        if cookie_b:
            headers_b["Cookie"] = cookie_b

    # Phase 1: Get objects owned by user A
    tested = 0
    methods_to_test = HTTP_METHODS if allow_mutation_write else ["GET"]
    id_endpoints = find_id_endpoints(base_url, endpoints)
    for ep in endpoints:
        candidate = (ep.get("url") or ep.get("path", "")) if isinstance(ep, dict) else ep
        url = same_origin_url(base_url, candidate)
        if not url:
            warn(f"Skipping endpoint outside the API base origin: {candidate}")
            continue
        path = ep.get("path", "") if isinstance(ep, dict) else str(ep)
        path = path or urllib.parse.urlsplit(url).path
        is_id_endpoint = ep in id_endpoints
        probe_url = build_initial_object_url(base_url, url)
        if not probe_url:
            warn(f"Skipping endpoint that cannot be kept on the API origin: {candidate}")
            continue

        # Get resources as User A
        status_a, _, body_a = http_request(probe_url, headers=headers_a)
        if delay:
            time.sleep(delay)

        if status_a != 200:
            continue

        # Extract IDs from response
        ids_found = extract_object_ids(body_a)
        path_object_id = object_id_from_path(probe_url) if is_id_endpoint else None
        if path_object_id:
            ids_found = {path_object_id}
        if not ids_found:
            continue

        log(f"Found {len(ids_found)} object IDs at {path}")

        # Phase 2: Try accessing those IDs from User B (or no auth)
        for obj_id in sorted(ids_found)[:5]:
            id_url = build_object_url(base_url, url, obj_id, is_id_endpoint=is_id_endpoint)
            if not id_url:
                warn(f"Skipping object ID that cannot be kept on the API origin: {obj_id!r}")
                continue

            for method in methods_to_test:
                # Test with User B token
                if token_b:
                    status_b, _, body_b = http_request(id_url, method=method, headers=headers_b)
                    if delay:
                        time.sleep(delay)

                    if status_b in (200, 201, 204):
                        confirmed = (
                            method == "GET" and status_b == 200
                            and obj_id in extract_object_ids(body_b)
                        )
                        message = (
                            f"BOLA: {method} {id_url} accessible with different user token"
                            if confirmed else
                            f"BOLA candidate: {method} {id_url} returned {status_b} with different user token; verify object access/read-back"
                        )
                        (vuln if confirmed else log)(message)
                        findings.append({
                            "type": "bola" if confirmed else "bola_candidate",
                            "severity": "high" if confirmed else "info",
                            "method": method,
                            "url": id_url,
                            "object_id": obj_id,
                            "access": "different_user",
                            "status": status_b,
                            "response_preview": body_b[:200],
                            "validated": confirmed,
                        })
                        tested += 1

                # Test without auth
                status_noauth, _, body_noauth = http_request(id_url, method=method)
                if delay:
                    time.sleep(delay)

                if status_noauth in (200, 201, 204):
                    confirmed = (
                        method == "GET" and status_noauth == 200
                        and obj_id in extract_object_ids(body_noauth)
                    )
                    message = (
                        f"BOLA: {method} {id_url} accessible without auth"
                        if confirmed else
                        f"BOLA candidate: {method} {id_url} returned {status_noauth} without auth; verify object access/read-back"
                    )
                    (vuln if confirmed else log)(message)
                    findings.append({
                        "type": "bola" if confirmed else "bola_candidate",
                        "severity": "critical" if confirmed else "info",
                        "method": method,
                        "url": id_url,
                        "object_id": obj_id,
                        "access": "no_auth",
                        "status": status_noauth,
                        "response_preview": body_noauth[:200],
                        "validated": confirmed,
                    })
                    tested += 1

        if tested >= 50:
            break

    # Phase 3: Test with common IDs on known resource paths
    resource_paths = ["/api/users/", "/api/v1/users/", "/api/accounts/",
                      "/api/orders/", "/api/v1/orders/", "/api/products/"]

    for rpath in resource_paths:
        for test_id in TEST_IDS:
            url = urllib.parse.urljoin(base_url, f"{rpath}{test_id}")

            if token_b:
                status, _, body = http_request(url, headers=headers_b)
                if delay:
                    time.sleep(delay)
                if status == 200 and len(body) > 20:
                    log(f"BOLA candidate: GET {url} returned data with an alternate token; object ownership was not established")
                    findings.append({
                        "type": "bola_idor_candidate",
                        "severity": "info",
                        "url": url,
                        "test_id": test_id,
                        "status": status,
                        "response_preview": body[:200],
                        "validated": False,
                    })

            status, _, body = http_request(url)
            if delay:
                time.sleep(delay)
            if status == 200 and len(body) > 20:
                log(f"BOLA candidate: GET {url} returned data without auth; sensitivity and object ownership were not established")
                findings.append({
                    "type": "bola_idor_candidate",
                    "severity": "info",
                    "url": url,
                    "test_id": test_id,
                    "status": status,
                    "response_preview": body[:200],
                    "validated": False,
                })

    return findings


def test_bfla(base_url, token, extra_headers=None, delay=0, allow_mutation_write=False):
    """Test for Broken Function Level Authorization (BFLA)."""
    log("Testing for BFLA (Broken Function Level Authorization)...")
    findings = []

    headers_user = {"Authorization": token if " " in token else f"Bearer {token}"}
    if extra_headers:
        headers_user.update(extra_headers)

    methods_to_test = HTTP_METHODS if allow_mutation_write else ["GET"]
    for admin_path in ADMIN_PATTERNS:
        url = urllib.parse.urljoin(base_url, admin_path)

        for method in methods_to_test:
            data = None
            req_headers = dict(headers_user)
            if method in ("POST", "PUT", "PATCH"):
                req_headers["Content-Type"] = "application/json"
                data = json.dumps({"test": "bfla_probe"})

            status, resp_headers, body = http_request(url, method=method, headers=req_headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 204):
                has_data = len(body) > 20
                log(f"BFLA candidate: {method} {admin_path} returned {status} with a user token; privileged impact was not verified")
                findings.append({
                    "type": "bfla_candidate",
                    "severity": "info",
                    "method": method,
                    "path": admin_path,
                    "url": url,
                    "status": status,
                    "has_data": has_data,
                    "response_preview": body[:200],
                    "validated": False,
                })

    if not allow_mutation_write:
        return findings

    # Test method override (X-HTTP-Method-Override)
    log("Testing HTTP method override headers...")
    override_headers_list = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    ]

    for admin_path in ADMIN_PATTERNS[:5]:
        url = urllib.parse.urljoin(base_url, admin_path)
        for override_header in override_headers_list:
            for target_method in ["PUT", "DELETE", "PATCH"]:
                req_headers = dict(headers_user)
                req_headers[override_header] = target_method
                req_headers["Content-Type"] = "application/json"

                status, _, body = http_request(url, method="POST", headers=req_headers,
                                                data=json.dumps({"test": "override"}))
                if delay:
                    time.sleep(delay)

                if status in (200, 201, 204):
                    log(f"BFLA candidate via method override: {override_header}: {target_method} on {admin_path}; privileged impact was not verified")
                    findings.append({
                        "type": "bfla_method_override_candidate",
                        "severity": "info",
                        "override_header": override_header,
                        "target_method": target_method,
                        "path": admin_path,
                        "status": status,
                        "validated": False,
                    })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Authorization Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from schema_builder.py or api_discovery.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", required=True, help="User A auth token")
    parser.add_argument("--token-b", help="User B auth token (for BOLA cross-user testing)")
    parser.add_argument("--cookie", help="User A session cookie")
    parser.add_argument("--cookie-b", help="User B session cookie (never reuses User A's cookie)")
    parser.add_argument("--api-base", required=True, help="Trusted API base URL for endpoint scoping")
    parser.add_argument("--delay", type=parse_delay, default=0,
                        help="Delay between requests (0-60 seconds)")
    parser.add_argument(
        "--allow-mutation-write",
        action="store_true",
        help="Enable POST/PUT/PATCH/DELETE authorization probes that can change target state",
    )
    args = parser.parse_args()

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    base_url = args.api_base
    endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        for api in input_data.get("discovered_apis", []):
            endpoints.append(api)
        for ep in input_data.get("endpoints", []):
            endpoints.append(ep)
        for ep in input_data.get("openapi_endpoints", []):
            endpoints.append(ep)

    if not base_url:
        parser.error("--api-base or --input with base_url is required")
    validated_base_url = same_origin_url(base_url, base_url)
    if not validated_base_url:
        parser.error("API base must be a credential-free absolute HTTP(S) URL")
    base_url = validated_base_url

    log(f"Testing authorization for: {base_url}")
    log(f"Endpoints loaded: {len(endpoints)}")

    all_findings = []

    # Test BOLA
    bola_findings = test_bola(
        base_url, endpoints, args.token, args.token_b, extra_headers, args.delay,
        allow_mutation_write=args.allow_mutation_write,
        cookie_b=args.cookie_b,
    )
    all_findings.extend(bola_findings)

    # Test BFLA
    bfla_findings = test_bfla(
        base_url, args.token, extra_headers, args.delay,
        allow_mutation_write=args.allow_mutation_write,
    )
    all_findings.extend(bfla_findings)

    # Categorize
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]

    bola_count = len([f for f in all_findings if f["type"].startswith("bola")])
    bfla_count = len([f for f in all_findings if f["type"].startswith("bfla")])

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "type": "authz_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "bola_findings": bola_count,
            "bfla_findings": bfla_count,
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "endpoints_tested": len(endpoints),
        },
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown"
    output_path = args.output or f"authz_test_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  AUTHORIZATION TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Endpoints tested    : {len(endpoints)}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  BOLA findings       : {bola_count}")
    print(f"  BFLA findings       : {bfla_count}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
