#!/usr/bin/env python3
"""Guarded v1 executor for the redirect-into-allowlist -> SSRF chain.

The executor accepts an operator-authored plan, not imported finding payloads.
It is dry-run by default. Active execution is two GET requests, gated by exact
source origins, an exact destination origin, and an explicit --execute flag.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAX_BODY_BYTES = 65536
MAX_TIMEOUT = 10
PARAMETER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_loopback(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _split_http_url(value, label, allow_query=True):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError(f"{label} must be a non-empty URL under 4096 characters")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must use an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError(f"{label} cannot contain credentials or a fragment")
    if not allow_query and parsed.query:
        raise ValueError(f"{label} must not contain a query; the executor builds it")
    if parsed.scheme.lower() != "https" and not _is_loopback(parsed.hostname):
        raise ValueError(f"{label} must use HTTPS except for loopback fixtures")
    port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed, (parsed.scheme.lower(), parsed.hostname.lower(), port)


def canonical_origin(value):
    parsed, origin = _split_http_url(value, "origin", allow_query=False)
    if parsed.path not in {"", "/"}:
        raise ValueError("scope origins must not include a path")
    return origin


def _validate_parameter(value, label):
    if not isinstance(value, str) or not PARAMETER_RE.fullmatch(value):
        raise ValueError(f"{label} must be a simple query parameter name")
    return value


def _validate_endpoint(section, label):
    if not isinstance(section, dict):
        raise ValueError(f"{label} must be an object")
    url = section.get("url")
    _split_http_url(url, f"{label}.url", allow_query=False)
    parameter = _validate_parameter(section.get("parameter"), f"{label}.parameter")
    return {"url": url, "parameter": parameter}


def validate_plan(plan):
    """Validate the narrow, confirmed two-finding plan before any request."""
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise ValueError("plan schema_version must be 1")
    if plan.get("chain_type") != "redirect_into_allowlist":
        raise ValueError("only redirect_into_allowlist chains are executable in v1")
    if plan.get("confidence") != "confirmed":
        raise ValueError("only confirmed chains may be executed")
    chain_id = plan.get("chain_id")
    if not isinstance(chain_id, str) or not chain_id.strip() or len(chain_id) > 200:
        raise ValueError("chain_id is required")
    finding_ids = plan.get("finding_ids")
    if (not isinstance(finding_ids, list) or len(finding_ids) != 2
            or any(not isinstance(item, str) or not item.strip() or len(item) > 200 for item in finding_ids)
            or finding_ids[0] == finding_ids[1]):
        raise ValueError("finding_ids must contain two distinct non-empty IDs")
    return {
        "schema_version": 1,
        "chain_type": "redirect_into_allowlist",
        "chain_id": chain_id,
        "confidence": "confirmed",
        "finding_ids": list(finding_ids),
        "redirect": _validate_endpoint(plan.get("redirect"), "redirect"),
        "ssrf": _validate_endpoint(plan.get("ssrf"), "ssrf"),
    }


def _request_url(endpoint, parameter, value):
    parsed = urllib.parse.urlsplit(endpoint)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, existing) for key, existing in query if key != parameter]
    query.append((parameter, value))
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))


def _safe_url_summary(url):
    parsed = urllib.parse.urlsplit(url)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}{port}{parsed.path or '/'}"


def _parse_headers(values):
    headers = {}
    for value in values:
        name, sep, content = value.partition(":")
        name = name.strip()
        content = content.strip()
        if not sep or not HEADER_NAME_RE.fullmatch(name) or "\r" in content or "\n" in content:
            raise ValueError("headers must use 'Name: value' without control characters")
        headers[name] = content
    return headers


def _http_get(url, headers, timeout):
    if os.environ.get("CATUS_CAMPAIGN_GATE_DB"):
        from campaign_request_gate import reserve_from_environment
        reserve_from_environment(url, "GET")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except Exception as error:  # network failures are evidence, never success
        return {"status": 0, "headers": {}, "body": b"", "error": type(error).__name__}
    try:
        body = response.read(MAX_BODY_BYTES + 1)
        truncated = len(body) > MAX_BODY_BYTES
        return {
            "status": int(response.code),
            "headers": dict(response.headers.items()),
            "body": body[:MAX_BODY_BYTES],
            "truncated": truncated,
        }
    finally:
        response.close()


def _header(headers, name):
    wanted = name.lower()
    return next((value for key, value in headers.items() if key.lower() == wanted), None)


def _check_scope(url, allowed_origins, label):
    _parsed, origin = _split_http_url(url, label)
    if origin not in allowed_origins:
        raise ValueError(f"{label} origin is outside the explicit --allow-origin scope")
    return origin


def dry_run(plan):
    validated = validate_plan(plan)
    return {
        "schema_version": 1,
        "mode": "dry_run",
        "chain_id": validated["chain_id"],
        "finding_ids": validated["finding_ids"],
        "chain_type": validated["chain_type"],
        "requests_sent": 0,
        "steps": [
            {"id": "redirect", "method": "GET", "endpoint": _safe_url_summary(validated["redirect"]["url"])},
            {"id": "ssrf", "method": "GET", "endpoint": _safe_url_summary(validated["ssrf"]["url"])},
        ],
        "success": None,
        "message": "Dry run only. Active execution requires --execute, explicit source and destination scope, destination URL, and expected response marker.",
    }


def execute_plan(plan, *, allow_origins, allow_destinations, destination_url,
                 expected_body, expected_status=200, headers=None, timeout=5):
    """Execute the supported chain with stop-on-failure and exact scope gates."""
    validated = validate_plan(plan)
    if not allow_origins or not allow_destinations:
        raise ValueError("active execution requires source and destination scope")
    if not 1 <= int(timeout) <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    if not isinstance(expected_body, str) or not expected_body or len(expected_body) > 256:
        raise ValueError("expected_body must be an explicit non-empty marker of at most 256 characters")
    if not isinstance(expected_status, int) or not 100 <= expected_status <= 599:
        raise ValueError("expected_status must be an HTTP status code")

    source_origins = {canonical_origin(origin) for origin in allow_origins}
    destination_origins = {canonical_origin(origin) for origin in allow_destinations}
    redirect_url = validated["redirect"]["url"]
    ssrf_url = validated["ssrf"]["url"]
    _check_scope(redirect_url, source_origins, "redirect endpoint")
    _check_scope(ssrf_url, source_origins, "SSRF endpoint")
    _destination_parsed, destination_origin = _split_http_url(destination_url, "destination_url")
    if destination_origin not in destination_origins:
        raise ValueError("destination_url origin is outside the explicit --allow-destination scope")

    request_headers = dict(headers or {})
    first_url = _request_url(redirect_url, validated["redirect"]["parameter"], destination_url)
    first = _http_get(first_url, request_headers, int(timeout))
    first_result = {
        "id": "redirect",
        "request": _safe_url_summary(first_url),
        "status": first["status"],
        "success": False,
    }
    results = [first_result]
    if first["status"] < 300 or first["status"] >= 400:
        first_result["reason"] = "redirect endpoint did not return a 3xx response"
        return _report(validated, results, success=False, reason=first_result["reason"])

    location = _header(first["headers"], "Location")
    if not location:
        first_result["reason"] = "redirect response omitted Location"
        return _report(validated, results, success=False, reason=first_result["reason"])
    resolved_location = urllib.parse.urljoin(first_url, location)
    try:
        _location_parsed, location_origin = _split_http_url(resolved_location, "redirect Location")
    except ValueError:
        first_result["reason"] = "redirect Location is not a safe absolute HTTP(S) URL"
        return _report(validated, results, success=False, reason=first_result["reason"])
    if location_origin not in destination_origins:
        first_result["reason"] = "redirect Location is outside explicit --allow-destination scope"
        first_result["location_origin"] = _origin_text(location_origin)
        return _report(validated, results, success=False, reason=first_result["reason"])
    first_result["location_origin"] = _origin_text(location_origin)
    first_result["success"] = True

    second_url = _request_url(ssrf_url, validated["ssrf"]["parameter"], resolved_location)
    second = _http_get(second_url, request_headers, int(timeout))
    second_result = {
        "id": "ssrf",
        "request": _safe_url_summary(second_url),
        "status": second["status"],
        "body_bytes": len(second["body"]),
        "body_sha256": hashlib.sha256(second["body"]).hexdigest(),
        "body_truncated": second.get("truncated", False),
        "success": second["status"] == expected_status and expected_body.encode("utf-8") in second["body"],
    }
    if second["status"] == 0:
        second_result["reason"] = "SSRF endpoint request failed"
    elif second["status"] != expected_status:
        second_result["reason"] = f"expected HTTP {expected_status}, received {second['status']}"
    elif not second_result["success"]:
        second_result["reason"] = "expected response marker was not present"
    results.append(second_result)
    reason = None if second_result["success"] else second_result.get("reason")
    return _report(validated, results, success=second_result["success"], reason=reason)


def _origin_text(origin):
    scheme, host, port = origin
    default = 443 if scheme == "https" else 80
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{rendered_host}" + (f":{port}" if port != default else "")


def _report(plan, steps, *, success, reason=None):
    report = {
        "schema_version": 1,
        "mode": "executed",
        "chain_type": plan["chain_type"],
        "chain_id": plan["chain_id"],
        "finding_ids": plan["finding_ids"],
        "steps": steps,
        "requests_sent": len(steps),
        "success": success,
    }
    if reason:
        report["stop_reason"] = reason
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Guarded executor for redirect-into-allowlist -> SSRF chains")
    parser.add_argument("--plan", required=True, help="Operator-authored execution plan JSON")
    parser.add_argument("--execute", action="store_true", help="Send the two scoped GET requests; default is dry-run")
    parser.add_argument("--allow-origin", action="append", default=[], help="Explicit source origin; repeat for each endpoint")
    parser.add_argument("--allow-destination", action="append", default=[], help="Explicit destination origin for the redirect Location")
    parser.add_argument("--destination-url", help="Expected redirect destination URL (required with --execute)")
    parser.add_argument("--expect-body", help="Response marker expected from the SSRF endpoint")
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--header", action="append", default=[], help="HTTP request header; may be repeated")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--output", help="Optional JSON execution report path")
    args = parser.parse_args(argv)
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        if args.execute:
            if not args.destination_url or not args.expect_body:
                parser.error("--execute requires --destination-url and --expect-body")
            report = execute_plan(
                plan,
                allow_origins=args.allow_origin,
                allow_destinations=args.allow_destination,
                destination_url=args.destination_url,
                expected_body=args.expect_body,
                expected_status=args.expect_status,
                headers=_parse_headers(args.header),
                timeout=args.timeout,
            )
        else:
            report = dry_run(plan)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report.get("success") is not False else 2


if __name__ == "__main__":
    raise SystemExit(main())
