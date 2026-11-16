#!/usr/bin/env python3
"""Low-impact HTTP cache behavior checks for explicitly authorized targets.

The default request is read-only. Active header probes use inert, unique
canaries and per-probe cache busters. Cache replay confirmation is a separate
opt-in because even a canary response can affect a shared cache when its key
ignores the query string.
"""

import argparse
import json
import math
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BODY_LIMIT = 128 * 1024
DEFAULT_DELAY = 0.35
MAX_REQUEST_TIMEOUT = 30.0
MAX_DELAY = 5.0
QUERY_PARAMETER_CANDIDATES = ("utm_content", "utm_source", "gclid", "fbclid", "_")
SENSITIVE_QUERY_PARAMETER_NAMES = frozenset({
    "access_token", "accesstoken", "api_key", "apikey", "auth",
    "auth_token", "authtoken", "authorization", "client_secret",
    "clientsecret", "email", "jwt", "key", "password", "refresh_token",
    "refreshtoken", "secret", "session", "session_id", "sessionid",
    "session_token", "sessiontoken", "sid", "token", "user", "userid",
    "username",
})
CACHE_HEADERS = {
    "age",
    "cache-control",
    "cdn-cache-control",
    "cf-cache-status",
    "content-type",
    "etag",
    "expires",
    "surrogate-control",
    "vary",
    "via",
    "warning",
    "x-cache",
    "x-cache-hits",
    "x-cache-status",
    "x-proxy-cache",
    "x-served-by",
    "x-varnish",
}


def probe_headers(marker):
    """Return a small set of inert cache-key candidates, never Host/XFF."""
    return [
        ("X-Forwarded-Host", marker),
        ("X-Original-Host", marker),
        ("X-Forwarded-Server", marker),
        ("X-Host", marker),
        ("Forwarded", 'host="{}"'.format(marker)),
        ("X-Original-URL", "/" + marker),
        ("X-Rewrite-URL", "/" + marker),
    ]


def validate_target(url):
    """Reject URLs that could escape the intended HTTP(S) origin."""
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        # Accessing .port also validates malformed port syntax.
        if parsed.port == 0:
            raise ValueError("target port must be between 1 and 65535")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid target URL: {}".format(exc))
    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise ValueError("target must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in target URLs are not accepted")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to servers; remove the fragment")
    return url


def safe_target_label(url):
    """Describe the target without persisting query values that may be secrets."""
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "[redacted]" if parsed.query else "", ""))


def add_cache_buster(url, token):
    """Append a nonce without normalizing the original path or query bytes."""
    if url.endswith("?") or ("?" in url and url.endswith("&")):
        separator = ""
    else:
        separator = "&" if "?" in url else "?"
    return "{}{}_catus_cache_probe={}".format(
        url, separator, urllib.parse.quote(str(token), safe="")
    )


def add_query_parameter(url, name, value):
    """Append one encoded parameter while preserving the existing raw query."""
    parts = urllib.parse.urlsplit(url)
    pair = "{}={}".format(
        urllib.parse.quote(str(name), safe=""),
        urllib.parse.quote(str(value), safe=""),
    )
    if parts.query and not parts.query.endswith("&"):
        query = parts.query + "&" + pair
    else:
        query = parts.query + pair
    return urllib.parse.urlunsplit(parts._replace(query=query))


def query_probe_parameter_names(url):
    """Return unused low-impact query candidates, or none for sensitive URLs."""
    existing = urllib.parse.parse_qsl(
        urllib.parse.urlsplit(url).query, keep_blank_values=True
    )
    names = {
        "".join(ch for ch in name.casefold() if ch.isalnum())
        for name, _ in existing
    }
    sensitive_names = {
        "".join(ch for ch in name.casefold() if ch.isalnum())
        for name in SENSITIVE_QUERY_PARAMETER_NAMES
    }
    if names.intersection(sensitive_names):
        return []
    return [
        name for name in QUERY_PARAMETER_CANDIDATES
        if "".join(ch for ch in name.casefold() if ch.isalnum()) not in names
    ]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep all traffic on the user-supplied origin; report redirects only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_body(stream):
    data = stream.read(BODY_LIMIT + 1)
    return data[:BODY_LIMIT], len(data) > BODY_LIMIT


def request_get(url, headers=None, timeout=8.0):
    """Perform one GET without following redirects or retaining response bodies."""
    timeout = _bounded_float(
        timeout, minimum=0.0, maximum=MAX_REQUEST_TIMEOUT, allow_minimum=False,
        label="timeout",
    )
    context = ssl.create_default_context()
    if os.environ.get("CATUS_INSECURE_TLS") == "1":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    request_headers = {
        "User-Agent": "CatusMythos-WebCacheAudit/1.0",
        "Accept": "text/html,application/json,*/*;q=0.8",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    opener = urllib.request.build_opener(
        NoRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body, truncated = _read_body(response)
            status = response.status
            response_headers = dict(response.headers.items())
            error = None
    except urllib.error.HTTPError as exc:
        try:
            body, truncated = _read_body(exc)
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            error = None
        finally:
            exc.close()
    except Exception as exc:  # network and malformed-response errors are findings data
        body, truncated, status, response_headers = b"", False, 0, {}
        error = "connection failed ({})".format(type(exc).__name__)

    return {
        "status": status,
        "headers": response_headers,
        "body": body,
        "body_truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "error": error,
    }


def cache_state(headers):
    """Summarize cache headers as a clue, not authoritative proof."""
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    evidence = {key: lowered[key] for key in sorted(CACHE_HEADERS) if key in lowered}
    states = set()
    for key in ("age", "cf-cache-status", "x-cache", "x-cache-hits", "x-cache-status", "x-proxy-cache"):
        value = lowered.get(key, "").lower()
        if key == "age":
            try:
                if int(value) > 0:
                    states.add("hit")
            except ValueError:
                pass
        tokens = set(re.findall(r"[a-z0-9]+", value.replace("_", " ").replace("-", " ")))
        if tokens.intersection(("hit", "cached", "revalidated")):
            states.add("hit")
        if tokens.intersection(("miss", "bypass", "dynamic", "expired")):
            states.add("miss")
    state = "mixed" if len(states) > 1 else (next(iter(states)) if states else "unknown")
    return state, evidence


def marker_locations(response, marker):
    """Return only where a marker appeared; never put response content in reports."""
    needle = marker.lower().encode("utf-8")
    found = []
    if needle in response["body"].lower():
        found.append("body")
    for name, value in response["headers"].items():
        if needle in str(value).lower().encode("utf-8", errors="replace"):
            found.append("header:" + str(name).lower())
    return found


def response_summary(response, marker=None):
    state, cache_headers = cache_state(response["headers"])
    result = {
        "status": response["status"],
        "elapsed_ms": response["elapsed_ms"],
        "body_bytes_observed": len(response["body"]),
        "body_truncated": response["body_truncated"],
        "cache_state_hint": state,
        "cache_headers": cache_headers,
    }
    if response["error"]:
        result["error"] = response["error"]
    if marker is not None:
        result["marker_locations"] = marker_locations(response, marker)
    return result


def cache_findings(target, probes):
    """Convert only replayed canaries into low-confidence, INFO-level leads."""
    findings = []
    for probe in probes:
        replay = probe.get("cache_replay") or {}
        if not replay.get(
            "canary_reappeared_without_input",
            replay.get("canary_reappeared_without_header"),
        ):
            continue
        input_label = probe.get("input_label", probe.get("header", "unknown input"))
        confidence = "likely_cache_reuse" if replay.get("likely_cache_reuse") else "possible_cache_reuse"
        cache_hint = replay.get("cache_state_hint", "unknown")
        findings.append({
            "type": "cache_unkeyed_replay",
            "title": "Potential unkeyed cache input: {}".format(input_label),
            "severity": "INFO",
            "confidence": confidence,
            "url": safe_target_label(target),
            "parameter": probe.get("query_parameter", probe.get("header")),
            "input_type": probe.get("input_type", "header"),
            "method": "GET",
            "evidence": (
                "An inert canary sent in {} reappeared in the response to a matched GET "
                "without that input; cache signal was {}. This is a lead for manual "
                "cache-key validation, not proof of harmful cache poisoning."
            ).format(input_label, cache_hint),
            "source_tool": "web-cache-auditor",
        })
    return findings


def _run_demo():
    """Exercise parsing and evidence classification without network access."""
    target = "https://example.test/a%2fb?x=1&"
    probe = add_cache_buster(target, "nonce value")
    assert probe == target + "_catus_cache_probe=nonce%20value", probe
    assert safe_target_label("https://example.test/path?token=secret") == "https://example.test/path?[redacted]"
    try:
        validate_target("https://user:pass@example.test/")
    except ValueError:
        pass
    else:
        raise AssertionError("URL credentials must be rejected")
    marker = "catus-probe-123.invalid"
    response = {"body": b"<a href='https://catus-probe-123.invalid'>", "headers": {"Location": marker}}
    assert marker_locations(response, marker) == ["body", "header:location"]
    assert cache_state({"CF-Cache-Status": "HIT", "Age": "18"})[0] == "hit"
    assert cache_state({"X-Cache": "MISS"})[0] == "miss"
    assert cache_state({"Cache-Control": "private, no-store"})[0] == "unknown"
    assert len(probe_headers(marker)) == 7
    assert len(QUERY_PARAMETER_CANDIDATES) == 5
    print("[+] cache audit offline demo passed")
    return 0


def _bounded_float(value, *, minimum, maximum, allow_minimum, label):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} must be a finite number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{label} must be a finite number")
    if number < minimum or (number == minimum and not allow_minimum):
        operator = "at least" if allow_minimum else "greater than"
        raise ValueError(f"{label} must be {operator} {minimum:g}")
    if number > maximum:
        raise ValueError(f"{label} must not exceed {maximum:g}")
    return number


def _positive_float(value):
    try:
        return _bounded_float(
            value, minimum=0.0, maximum=MAX_REQUEST_TIMEOUT,
            allow_minimum=False, label="timeout",
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _nonnegative_float(value):
    try:
        return _bounded_float(
            value, minimum=0.0, maximum=MAX_DELAY,
            allow_minimum=True, label="delay",
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Inspect HTTP cache signals and, optionally, probe inert unkeyed-input canaries."
    )
    parser.add_argument("--target", help="authorized absolute HTTP(S) URL; GET-only")
    parser.add_argument(
        "--probe-unkeyed", action="store_true",
        help="send inert header and eligible query canaries, each with a fresh cache-buster",
    )
    parser.add_argument(
        "--confirm-cache-replay", action="store_true",
        help="replay reflected canaries without their tested input using the same nonce (staging only)",
    )
    parser.add_argument(
        "--timeout", type=_positive_float, default=8.0,
        help=f"per-request timeout in seconds (0 < timeout <= {MAX_REQUEST_TIMEOUT:g})",
    )
    parser.add_argument(
        "--delay", type=_nonnegative_float, default=DEFAULT_DELAY,
        help=f"delay between requests in seconds (0 <= delay <= {MAX_DELAY:g})",
    )
    parser.add_argument("--output", help="optional JSON output path (query values and bodies are omitted)")
    parser.add_argument("--demo", action="store_true", help="run offline self-checks")
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.demo:
        return _run_demo()
    if not args.target:
        parser.error("--target is required unless --demo is used")
    if args.confirm_cache_replay and not args.probe_unkeyed:
        parser.error("--confirm-cache-replay requires --probe-unkeyed")
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    mode = "active_input_probes" if args.probe_unkeyed else "passive_cache_headers"
    if args.confirm_cache_replay:
        print("[!] Cache replay enabled: use an isolated staging cache. A target may ignore the cache-buster.", file=sys.stderr)
    elif args.probe_unkeyed:
        print("[!] Active canary probes enabled. Cache-busters reduce collisions but cannot guarantee cache isolation.", file=sys.stderr)

    baseline = request_get(target, timeout=args.timeout)
    result = {
        "tool": "CatusMythos-WebCacheAudit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": safe_target_label(target),
        "mode": mode,
        "authorization_note": "Run only against explicitly authorized, read-only GET endpoints.",
        "baseline": response_summary(baseline),
        "probes": [],
        "findings": [],
        "limitations": [
            "Cache headers are hints and may be absent, rewritten, or inaccurate.",
            "A fresh query parameter is a best-effort cache buster; some caches ignore query strings.",
            "Query-parameter probes use a small seed set and skip sensitive-looking target query keys.",
            "A reflection candidate is not proof of cacheability or exploitability.",
            "Path-normalization and authenticated cache-deception checks require manual, target-aware validation.",
            "Response bodies and query values are not written to the report.",
        ],
    }

    if args.probe_unkeyed:
        for header_name in (name for name, _ in probe_headers("placeholder.invalid")):
            nonce = secrets.token_urlsafe(12)
            marker = "catus-probe-{}.invalid".format(secrets.token_hex(8))
            header_value = dict(probe_headers(marker))[header_name]
            probe_url = add_cache_buster(target, nonce)
            injected = request_get(probe_url, headers={header_name: header_value}, timeout=args.timeout)
            entry = {
                "header": header_name,
                "input_label": header_name,
                "input_type": "header",
                "canary": marker,
                "response": response_summary(injected, marker),
                "cache_replay": None,
            }
            if args.confirm_cache_replay and marker_locations(injected, marker):
                time.sleep(args.delay)
                replay = request_get(probe_url, timeout=args.timeout)
                locations = marker_locations(replay, marker)
                replay_summary = response_summary(replay, marker)
                replay_summary["canary_reappeared_without_header"] = bool(locations)
                replay_summary["likely_cache_reuse"] = bool(locations) and replay_summary["cache_state_hint"] == "hit"
                entry["cache_replay"] = replay_summary
            result["probes"].append(entry)
            if args.delay:
                time.sleep(args.delay)

        # Test a small seed set of common cache-excluded tracking parameters.
        # Do not duplicate names already present in the user's query, and skip
        # query probing entirely when the URL contains sensitive-looking keys.
        for parameter_name in query_probe_parameter_names(target):
            nonce = secrets.token_urlsafe(12)
            marker = "catus-probe-{}.invalid".format(secrets.token_hex(8))
            query_target = add_query_parameter(target, parameter_name, marker)
            probe_url = add_cache_buster(query_target, nonce)
            injected = request_get(probe_url, timeout=args.timeout)
            input_label = "query parameter {}".format(parameter_name)
            entry = {
                "input_label": input_label,
                "input_type": "query_parameter",
                "query_parameter": parameter_name,
                "response": response_summary(injected, marker),
                "cache_replay": None,
            }
            if args.confirm_cache_replay and marker_locations(injected, marker):
                time.sleep(args.delay)
                # Keep the nonce and original raw query, removing only the
                # candidate parameter. Any canary returned now indicates
                # possible cache-key omission; it remains a manual-review lead.
                replay_url = add_cache_buster(target, nonce)
                replay = request_get(replay_url, timeout=args.timeout)
                locations = marker_locations(replay, marker)
                replay_summary = response_summary(replay, marker)
                replay_summary["canary_reappeared_without_input"] = bool(locations)
                replay_summary["canary_reappeared_without_query_parameter"] = bool(locations)
                replay_summary["likely_cache_reuse"] = (
                    bool(locations) and replay_summary["cache_state_hint"] == "hit"
                )
                entry["cache_replay"] = replay_summary
            result["probes"].append(entry)
            if args.delay:
                time.sleep(args.delay)

        result["findings"] = cache_findings(target, result["probes"])

    print("Target: {}".format(result["target"]))
    print("Mode: {}".format(mode))
    baseline_state = result["baseline"]["cache_state_hint"]
    print("Baseline: HTTP {} (cache signal: {})".format(result["baseline"]["status"], baseline_state))
    for entry in result["probes"]:
        input_label = entry.get("input_label", entry.get("header", "unknown input"))
        reflected = bool(entry["response"]["marker_locations"])
        label = "canary reflected" if reflected else "no canary reflection observed"
        replay = entry["cache_replay"]
        if replay and entry.get("input_type", "header") == "header" \
                and replay.get("canary_reappeared_without_header"):
            label += "; canary reappeared without header"
        if replay and entry.get("input_type") == "query_parameter" \
                and replay.get("canary_reappeared_without_query_parameter"):
            label += "; canary reappeared without query parameter"
        print("  {}: HTTP {} - {}".format(input_label, entry["response"]["status"], label))

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("JSON: {}".format(output))
    return 0 if baseline["status"] else 1


if __name__ == "__main__":
    sys.exit(main())
