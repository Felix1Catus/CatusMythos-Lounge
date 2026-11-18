#!/usr/bin/env python3
"""
Authorization Tester Module - api-breaker
Tests for BOLA (Broken Object Level Authorization) and BFLA (Broken Function Level Authorization).
Author: orizon.one
"""

import argparse
import importlib.util
import json
import math
import os
import re
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path


from _common import http_request, log, same_origin_url, success, vuln, warn
from response_safety import safe_response_preview
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
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return ids

    stack = [data]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key.lower() in ("id", "uid", "user_id", "userid", "account_id",
                                    "accountid", "order_id", "orderid", "object_id"):
                    if val is not None and not isinstance(val, (bool, dict, list)):
                        object_id = str(val)
                        if object_id and len(object_id) <= 200 and not any(ord(c) < 32 for c in object_id):
                            ids.add(object_id)
                if isinstance(val, (dict, list)):
                    stack.append(val)
        elif isinstance(obj, list):
            stack.extend(obj)
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


def parse_role(value):
    """Parse one --role NAME:TOKEN argument for the N-role matrix. An
    empty TOKEN (e.g. 'anonymous:') declares an explicitly anonymous/
    no-auth role at that exact position in the privilege ordering,
    instead of relying on a separate implicit no-auth check."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            "--role must be NAME:TOKEN (TOKEN may be empty for an explicit anonymous role)")
    name, _, token = value.partition(":")
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("--role name must not be empty")
    return name, token.strip()


def build_role_matrix(roles, extra_headers=None, cookies=None):
    """Build the ordered role matrix used by *_matrix testers.

    roles: ordered list of (name, token) pairs, LOWEST privilege first --
        declaration order IS the rank (0 = lowest). This is a simple,
        explicit convention rather than inferring privilege from token
        contents, which this tool has no reliable way to do.
    cookies: optional {name: cookie} map. A role never inherits another
        role's cookie -- each gets exactly its own, or none.

    Returns an ordered list of {"name", "rank", "headers"} dicts.
    """
    matrix = []
    for rank, (name, token) in enumerate(roles):
        headers = {}
        if extra_headers:
            headers.update({k: v for k, v in extra_headers.items() if k.lower() != "cookie"})
        if token:
            headers["Authorization"] = token if " " in token else f"Bearer {token}"
        own_cookie = (cookies or {}).get(name)
        if own_cookie:
            headers["Cookie"] = own_cookie
        matrix.append({"name": name, "rank": rank, "headers": headers})
    return matrix


def test_bola_matrix(base_url, endpoints, roles, delay=0, allow_mutation_write=False, knowledge=None):
    """N-role generalization of test_bola(): for every role that can
    itself read an object (the "source" role for that object), test
    EVERY OTHER role in the matrix against those same object IDs -- a
    direct extension of the original's "User A's objects, tried as User
    B" to however many named roles were supplied. Unlike test_bola(),
    there is no separate automatic no-auth check here: declare an
    explicit anonymous role (e.g. "anonymous:") in the matrix for that,
    the same way any other role is declared.

    Scope note: this generalizes Phase 1+2 of test_bola() (the real
    cross-identity object-ownership crossing). Phase 3 (probing common
    IDs on hardcoded resource paths with no established ownership) is
    deliberately NOT generalized here -- it never established ownership
    in the original either, and doing so meaningfully for N roles needs
    its own design; left for a follow-up.
    """
    log(f"Testing for BOLA across {len(roles)} roles...")
    findings = []
    if len(roles) < 2:
        warn("Need at least 2 roles in the matrix to cross-test object access")
        return findings

    tested = 0
    max_probes = 100  # scales with N roles vs. the original's fixed 50 for a single pair
    methods_to_test = HTTP_METHODS if allow_mutation_write else ["GET"]
    id_endpoints = find_id_endpoints(base_url, endpoints)

    for ep in endpoints:
        if tested >= max_probes:
            break
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

        for source in roles:
            status_src, _, body_src = http_request(probe_url, headers=source["headers"])
            if knowledge is not None:
                knowledge.record_auth_outcome(probe_url, source["name"], status_src, source["headers"],
                                              "api-breaker/authz_tester", resource=path)
            if delay:
                time.sleep(delay)
            if status_src != 200:
                continue

            ids_found = extract_object_ids(body_src)
            path_object_id = object_id_from_path(probe_url) if is_id_endpoint else None
            if path_object_id:
                ids_found = {path_object_id}
            if not ids_found:
                continue

            log(f"Found {len(ids_found)} object ID(s) at {path} as role '{source['name']}'")

            for obj_id in sorted(ids_found)[:5]:
                id_url = build_object_url(base_url, url, obj_id, is_id_endpoint=is_id_endpoint)
                if not id_url:
                    warn(f"Skipping object ID that cannot be kept on the API origin: {obj_id!r}")
                    continue

                for other in roles:
                    if other["name"] == source["name"]:
                        continue
                    for method in methods_to_test:
                        if tested >= max_probes:
                            break
                        status_other, _, body_other = http_request(
                            id_url, method=method, headers=other["headers"])
                        if knowledge is not None:
                            knowledge.record_auth_outcome(id_url, other["name"], status_other,
                                                         other["headers"], "api-breaker/authz_tester",
                                                         resource=path)
                        if delay:
                            time.sleep(delay)
                        tested += 1

                        if status_other not in (200, 201, 204):
                            continue
                        confirmed = (
                            method == "GET" and status_other == 200
                            and obj_id in extract_object_ids(body_other)
                        )
                        message = (
                            f"BOLA: role '{other['name']}' accessed {method} {id_url} "
                            f"owned by role '{source['name']}'"
                            if confirmed else
                            f"BOLA candidate: role '{other['name']}' {method} {id_url} returned "
                            f"{status_other} (object seen under role '{source['name']}'); verify read-back"
                        )
                        (vuln if confirmed else log)(message)
                        findings.append({
                            "type": "bola" if confirmed else "bola_candidate",
                            "severity": "critical" if confirmed and other["rank"] < source["rank"] else
                                        ("high" if confirmed else "info"),
                            "method": method,
                            "url": id_url,
                            "object_id": obj_id,
                            "owner_role": source["name"],
                            "owner_rank": source["rank"],
                            "accessing_role": other["name"],
                            "accessing_rank": other["rank"],
                            "status": status_other,
                            "response_preview": safe_response_preview(body_other),
                            "validated": confirmed,
                        })
            if tested >= max_probes:
                break

    return findings


def test_bfla_matrix(base_url, roles, delay=0, allow_mutation_write=False, knowledge=None):
    """N-role generalization of test_bfla(): probes every role against
    every admin/privileged path, but -- unlike the single-token original,
    which has no way to know whether its one token IS the admin -- an
    access by the matrix's HIGHEST-ranked (last-declared) role is treated
    as expected and NOT reported; only a role ranked BELOW the top
    succeeding is a real BFLA candidate. Severity scales with the rank
    gap (how far below the top the successful role sits): the lowest-
    ranked role (rank 0, e.g. an explicit anonymous entry) succeeding is
    the worst case."""
    log(f"Testing for BFLA across {len(roles)} roles...")
    findings = []
    if not roles:
        return findings

    max_rank = max(r["rank"] for r in roles)
    methods_to_test = HTTP_METHODS if allow_mutation_write else ["GET"]
    admin_role = next(role for role in roles if role["rank"] == max_rank)

    def semantic_signature(body):
        try:
            value = json.loads(body)
        except (TypeError, ValueError):
            return None
        volatile = {"timestamp", "request_id", "trace_id", "csrf", "csrf_token", "nonce"}

        def clean(item):
            if isinstance(item, dict):
                return {key: clean(value) for key, value in sorted(item.items())
                        if key.lower() not in volatile}
            if isinstance(item, list):
                return [clean(value) for value in item]
            return item

        encoded = json.dumps(clean(value), sort_keys=True, separators=(",", ":"))
        if re.search(r"(?i)unauthorized|forbidden|access denied|not authenticated|login required", encoded):
            return None
        return "json:" + encoded if isinstance(value, (dict, list)) and len(encoded) >= 20 else None

    for admin_path in ADMIN_PATTERNS:
        url = urllib.parse.urljoin(base_url, admin_path)

        for role in roles:
            if role["rank"] == max_rank:
                continue  # the top-ranked role reaching its own admin surface is expected

            for method in methods_to_test:
                control_status, _control_headers, control_body = http_request(
                    url, method=method, headers=dict(admin_role["headers"]))
                if knowledge is not None:
                    knowledge.record_auth_outcome(url, admin_role["name"], control_status,
                                                  admin_role["headers"], "api-breaker/authz_tester")
                data = None
                req_headers = dict(role["headers"])
                if method in ("POST", "PUT", "PATCH"):
                    req_headers["Content-Type"] = "application/json"
                    data = json.dumps({"test": "bfla_probe"})

                status, _resp_headers, body = http_request(
                    url, method=method, headers=req_headers, data=data)
                if knowledge is not None:
                    knowledge.record_auth_outcome(url, role["name"], status, role["headers"],
                                                  "api-breaker/authz_tester")
                if delay:
                    time.sleep(delay)

                if status not in (200, 201, 204):
                    continue

                control_ok = control_status in (200, 201, 204)
                control_signature = semantic_signature(control_body) if control_ok else None
                low_signature = semantic_signature(body)
                matched_privileged_response = bool(
                    method == "GET" and control_signature and low_signature
                    and control_signature == low_signature)

                gap = max_rank - role["rank"]
                severity = "critical" if role["rank"] == 0 else ("high" if gap > 1 else "medium")
                has_data = len(body) > 20
                validated = matched_privileged_response
                finding_type = "bfla" if validated else "bfla_candidate"
                message = (f"BFLA: role '{role['name']}' received the same protected response as "
                           f"the highest-ranked role at {method} {admin_path}"
                           if validated else
                           f"BFLA candidate: role '{role['name']}' (rank {role['rank']}/{max_rank}) "
                           f"reached {method} {admin_path} with status {status}; impact not proven")
                (vuln if validated else log)(message)
                findings.append({
                    "type": finding_type,
                    "severity": severity,
                    "method": method,
                    "path": admin_path,
                    "url": url,
                    "status": status,
                    "has_data": has_data,
                    "role": role["name"],
                    "role_rank": role["rank"],
                    "max_rank": max_rank,
                    "response_preview": safe_response_preview(body),
                    "validated": validated,
                    "control_role": admin_role["name"],
                    "control_status": control_status,
                    "control_passed": control_ok,
                    "response_matches_privileged_control": matched_privileged_response,
                    "verification_method": "same_semantic_read_response_as_privileged_role"
                    if validated else "candidate_without_semantic_control_match",
                })

    return findings


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
                            "response_preview": safe_response_preview(body_b),
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
                        "response_preview": safe_response_preview(body_noauth),
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
                        "response_preview": safe_response_preview(body),
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
                    "response_preview": safe_response_preview(body),
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
                    "response_preview": safe_response_preview(body),
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
    parser.add_argument("--token", help="User A auth token (2-role mode; omit when using --role)")
    parser.add_argument("--token-b", help="User B auth token (2-role mode BOLA cross-user testing)")
    parser.add_argument("--cookie", help="User A session cookie (2-role mode)")
    parser.add_argument("--cookie-b", help="User B session cookie (2-role mode; never reuses User A's cookie)")
    parser.add_argument(
        "--role", action="append", type=parse_role, default=[], metavar="NAME:TOKEN",
        help="N-role authorization matrix: repeat in ASCENDING privilege order, lowest first "
             "(e.g. --role anonymous: --role viewer:TOKEN1 --role admin:TOKEN2). An empty TOKEN "
             "declares an explicit anonymous role at that position. Needs at least 2 for BOLA "
             "cross-testing; the highest-ranked (last) role is treated as the expected admin for "
             "BFLA, so only a lower-ranked role reaching a privileged endpoint is flagged. "
             "Mutually exclusive with --token/--token-b.",
    )
    parser.add_argument(
        "--role-cookie", action="append", default=[], metavar="NAME:COOKIE",
        help="Session cookie for one named --role (repeatable). A role never inherits another "
             "role's cookie.",
    )
    parser.add_argument("--api-base", required=True, help="Trusted API base URL for endpoint scoping")
    parser.add_argument("--campaign-gate-required", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--knowledge-db", help="Opt-in shared SQLite target-knowledge file")
    parser.add_argument("--engagement", help="Required engagement namespace when knowledge is enabled")
    parser.add_argument("--delay", type=parse_delay, default=0,
                        help="Delay between requests (0-60 seconds)")
    parser.add_argument(
        "--allow-mutation-write",
        action="store_true",
        help="Enable POST/PUT/PATCH/DELETE authorization probes that can change target state",
    )
    args = parser.parse_args()

    if args.campaign_gate_required and any(not os.environ.get(name) for name in (
            "CATUS_CAMPAIGN_GATE_DB", "CATUS_CAMPAIGN_GATE_CAMPAIGN",
            "CATUS_CAMPAIGN_GATE_STEP", "CATUS_CAMPAIGN_GATE_ORIGIN")):
        parser.error("campaign request gate is required but its environment is incomplete")

    if args.knowledge_db and not args.engagement:
        parser.error("--knowledge-db requires --engagement")
    if args.engagement and not args.knowledge_db:
        parser.error("--engagement requires --knowledge-db")
    knowledge = None
    if args.knowledge_db:
        module_path = Path(__file__).resolve().parents[3] / "scripts" / "target_knowledge.py"
        if not module_path.is_file():
            parser.error("shared knowledge requires the full plugin checkout, including scripts/target_knowledge.py")
        spec = importlib.util.spec_from_file_location("catus_target_knowledge", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            knowledge = module.KnowledgeStore(args.knowledge_db, args.engagement)
        except (ValueError, OSError, module.sqlite3.Error) as exc:
            parser.error(str(exc))

    if args.role and (args.token or args.token_b):
        parser.error("--role and --token/--token-b are mutually exclusive -- use one mode or the other")
    if args.role and len(args.role) < 2:
        parser.error("--role needs at least 2 entries to cross-test object/function access")
    if not args.role and not args.token:
        parser.error("--token is required unless using --role")

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

    # Endpoint observations imported from crawler/browser runs share the same
    # engagement store as API discovery. Treat them as test leads, not proof.
    if knowledge is not None:
        try:
            inventory = knowledge.query(base_url, kind="api_inventory", key="observed_endpoints")
            for row in inventory:
                for item in row.get("value", []):
                    path = item.get("path") if isinstance(item, dict) else None
                    if isinstance(path, str) and path.startswith("/") and not any(
                            isinstance(existing, dict) and existing.get("path") == path
                            for existing in endpoints):
                        endpoints.append({"path": path, "url": urllib.parse.urljoin(base_url, path),
                                          "methods_tested": item.get("methods_tested", [])})
        except (OSError, ValueError) as exc:
            parser.error("could not reuse selected target knowledge: {}".format(exc))

    if not base_url:
        parser.error("--api-base or --input with base_url is required")
    validated_base_url = same_origin_url(base_url, base_url)
    if not validated_base_url:
        parser.error("API base must be a credential-free absolute HTTP(S) URL")
    base_url = validated_base_url

    log(f"Testing authorization for: {base_url}")
    log(f"Endpoints loaded: {len(endpoints)}")

    all_findings = []
    role_names = []

    if args.role:
        role_cookies = {}
        for entry in args.role_cookie:
            if ":" not in entry:
                parser.error("--role-cookie must be NAME:COOKIE")
            name, _, cookie = entry.partition(":")
            role_cookies[name.strip()] = cookie.strip()

        roles = build_role_matrix(args.role, extra_headers=extra_headers, cookies=role_cookies)
        role_names = [r["name"] for r in roles]
        log(f"Role matrix ({len(roles)} roles, lowest to highest privilege): {', '.join(role_names)}")

        all_findings.extend(test_bola_matrix(
            base_url, endpoints, roles, args.delay,
            allow_mutation_write=args.allow_mutation_write,
            knowledge=knowledge,
        ))
        all_findings.extend(test_bfla_matrix(
            base_url, roles, args.delay,
            allow_mutation_write=args.allow_mutation_write,
            knowledge=knowledge,
        ))
    else:
        all_findings.extend(test_bola(
            base_url, endpoints, args.token, args.token_b, extra_headers, args.delay,
            allow_mutation_write=args.allow_mutation_write,
            cookie_b=args.cookie_b,
        ))
        all_findings.extend(test_bfla(
            base_url, args.token, extra_headers, args.delay,
            allow_mutation_write=args.allow_mutation_write,
        ))

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
            "roles": role_names,  # empty list in 2-role (--token) mode
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
