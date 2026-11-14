#!/usr/bin/env python3
"""
API Discovery Module - api-breaker
Discovers REST, GraphQL, and SOAP API endpoints from domains.
Author: orizon.one
"""

import argparse
import json
import re
import urllib.request
import urllib.parse
import concurrent.futures
from pathlib import Path
from datetime import datetime


from _common import http_request, log, success, vuln, warn
# Common API paths to fuzz
API_PATHS = [
    # Documentation
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/docs", "/redoc",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-resources",
    "/.well-known/openapi", "/api/swagger.json",

    # GraphQL
    "/graphql", "/graphiql", "/playground", "/api/graphql",
    "/graphql/console", "/v1/graphql", "/v2/graphql",

    # REST common
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/v1/", "/v2/", "/v3/",

    # Common resources
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/products", "/api/orders", "/api/items",
    "/api/posts", "/api/comments", "/api/messages",
    "/api/config", "/api/settings", "/api/status",
    "/api/health", "/api/version", "/api/info",
    "/api/auth/login", "/api/auth/register",
    "/api/auth/token", "/api/auth/refresh",
    "/api/search", "/api/upload", "/api/download",

    # Health/monitoring
    "/health", "/healthz", "/ready", "/alive",
    "/status", "/ping", "/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings",

    # SOAP/WSDL
    "/ws", "/wsdl", "/soap", "/service.asmx",
    "/?wsdl", "/ws?wsdl",
]

# research_notes/API breaker depth techniques/rate_limit_versioning.md --
# "API-version/legacy-path discovery, in api_discovery.py" section.
# Response headers that self-disclose version/deprecation metadata (RFC
# 8594 Sunset, HTTP Deprecation header, RFC 8288 Link rel="deprecation"),
# fingerprinted on every probed endpoint regardless of whether it's a
# legacy-version candidate -- this both surfaces servers that self-report
# their own deprecation status and helps identify the CURRENT version
# string to decrement from.
DEPRECATION_HEADER_NAMES = {"sunset", "deprecation"}

# Non-numeric alternate-version labels to substitute for a detected
# version segment, per the research's cited real-world schemes (Stripe
# URI versioning, Box date-based tokens, informal "old/legacy/internal"
# staging labels).
VERSION_WORD_CANDIDATES = ["beta", "alpha", "old", "legacy", "internal", "deprecated"]

# Matches a path segment that IS a version token on its own, e.g. "v2",
# "V10" -- deliberately anchored to the whole segment (not a substring of
# a longer word) so we don't mistake something like "reviews" for a
# version segment.
VERSION_SEGMENT_RE = re.compile(r'^(v)(\d+)$', re.IGNORECASE)

# Matches a path segment that is a bare year or a Box-style date token
# ("2025", "2025.0", "2025-01").
DATE_SEGMENT_RE = re.compile(r'^(\d{4})([.\-]\d{1,2})?$')

# Used by fetch_wayback_cdx_paths() to pull a version/date-shaped path
# segment out of an archived URL's path.
# A pure DETECTOR (is there a version/date-shaped segment anywhere in this
# path?) -- deliberately not used to slice out a substring, since doing
# that would truncate off everything before the matched segment (e.g.
# "/api/v1/old_endpoint" would wrongly become just "/v1/old_endpoint",
# losing the "/api" prefix the live host actually needs to route it).
WAYBACK_VERSION_TOKEN_RE = re.compile(r'/v\d+(?:/|$)|/\d{4}[.\-]\d{1,2}(?:/|$)', re.IGNORECASE)

# Safety cap on how many (auth-control + rate-limit-control) differential
# bypass checks discover_legacy_versions() will run in one pass -- each
# rate-limit-control check alone can cost up to 2*burst_count requests, so
# this bounds total request volume against a single target regardless of
# how many version-token-bearing endpoints were discovered.
MAX_LEGACY_BYPASS_CHECKS = 5


def extract_version_headers(headers):
    """Fingerprint response headers that self-disclose version/deprecation
    metadata: exact Sunset/Deprecation headers, a Link header whose value
    names a deprecation relation, and any header whose NAME contains
    'version' (X-API-Version, X-Version, API-Version, etc.)."""
    found = {}
    for key, val in headers.items():
        lk = key.lower()
        if lk in DEPRECATION_HEADER_NAMES:
            found[key] = val
        elif lk == "link" and "deprecation" in str(val).lower():
            found[key] = val
        elif "version" in lk:
            found[key] = val
    return found


def probe_path(base_url, path, extra_headers=None):
    """Probe a single path and return details if found."""
    url = urllib.parse.urljoin(base_url, path)
    status, headers, body = http_request(url, headers=extra_headers)

    if status in (200, 201, 301, 302, 401, 403, 405):
        content_type = headers.get("Content-Type", "").lower()
        api_type = "unknown"

        if "graphql" in path.lower() or "graphql" in body.lower():
            api_type = "graphql"
        elif "swagger" in path.lower() or "openapi" in body.lower():
            api_type = "openapi_docs"
        elif "wsdl" in body.lower() or "soap" in body.lower():
            api_type = "soap"
        elif "json" in content_type:
            api_type = "rest_json"
        elif "xml" in content_type:
            api_type = "rest_xml"

        return {
            "url": url,
            "path": path,
            "status": status,
            "content_type": content_type,
            "api_type": api_type,
            "response_length": len(body),
            "auth_required": status in (401, 403),
            "methods_tested": ["GET"],
            "version_headers": extract_version_headers(headers),
        }
    return None


def test_graphql(url, extra_headers=None):
    """Test if a GraphQL endpoint supports introspection."""
    log(f"Testing GraphQL introspection on {url}...")

    introspection_query = json.dumps({
        "query": "{ __schema { types { name } } }"
    })

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, resp_headers, body = http_request(url, "POST", headers, introspection_query)

    if status == 200 and "__schema" in body:
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            type_names = [t["name"] for t in types if not t["name"].startswith("__")]
            return {
                "introspection_enabled": True,
                "types_found": len(type_names),
                "type_names": type_names[:50],
            }
        except (json.JSONDecodeError, KeyError):
            pass

    return {"introspection_enabled": False}


def extract_openapi_endpoints(url, extra_headers=None):
    """Parse OpenAPI/Swagger documentation for endpoints."""
    log(f"Parsing OpenAPI docs from {url}...")
    status, _, body = http_request(url, headers=extra_headers)

    if status != 200:
        return []

    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        return []

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                params = []
                for param in details.get("parameters", []):
                    params.append({
                        "name": param.get("name"),
                        "in": param.get("in"),
                        "required": param.get("required", False),
                        "type": param.get("schema", {}).get("type", "string"),
                    })

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "parameters": params,
                    "auth_required": bool(details.get("security")),
                    "tags": details.get("tags", []),
                })

    success(f"Parsed {len(endpoints)} endpoints from OpenAPI spec")
    return endpoints


def discover_from_js(base_url, js_urls, extra_headers=None):
    """Extract API endpoints from JavaScript files."""
    log("Analyzing JavaScript files for API endpoints...")
    endpoints = set()

    patterns = [
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/v[0-9]+\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
        r'["\'](\/rest\/[^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    for js_url in js_urls[:20]:
        _, _, js_body = http_request(js_url, headers=extra_headers)
        if not js_body:
            continue
        for pattern in patterns:
            for match in re.finditer(pattern, js_body):
                ep = match.group(1)
                if ep.startswith("/"):
                    endpoints.add(ep)
                elif ep.startswith("http"):
                    parsed = urllib.parse.urlparse(ep)
                    endpoints.add(parsed.path)

    success(f"Found {len(endpoints)} endpoints from JS analysis")
    return list(endpoints)


def test_http_methods(url, extra_headers=None):
    """Test which HTTP methods are allowed on an endpoint."""
    methods = []
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        status, headers, _ = http_request(url, method=method, headers=extra_headers)
        if status not in (0, 404, 501, 405):
            methods.append(method)

        # Also check OPTIONS Allow header
        if method == "OPTIONS" and "Allow" in headers:
            allowed = headers["Allow"]
            methods.extend([m.strip() for m in allowed.split(",")])

    return list(set(methods))


def generate_legacy_candidates(path):
    """Given a discovered path, generate sibling candidate paths by
    substring-replacing the FIRST version- or date-shaped segment found.

    research_notes/API breaker depth techniques/rate_limit_versioning.md:
    "Candidate-path generator: for every discovered endpoint ... generate
    siblings by substring-replacing the version token: v2->v1, v2->v0, v3
    (probe forward too), plus beta, alpha, old, legacy, internal,
    deprecated, plus date-token variants (2025.0->2024.0->2023.0)."

    Returns a list of (candidate_path, variant_label) tuples; empty if no
    version/date-shaped segment is present in the path at all (nothing to
    substitute).
    """
    segments = path.split("/")
    candidates = []

    for i, seg in enumerate(segments):
        m = VERSION_SEGMENT_RE.match(seg)
        if m:
            prefix, num = m.group(1), int(m.group(2))
            # v2 -> v1, v0, v3 (one back, zero, one forward) -- deduped,
            # excluding the number already in the path.
            numeric_variants = sorted({n for n in (num - 1, 0, num + 1) if n >= 0 and n != num})
            for n in numeric_variants:
                new_segments = list(segments)
                new_segments[i] = f"{prefix}{n}"
                candidates.append(("/".join(new_segments), f"{prefix}{n}"))
            for word in VERSION_WORD_CANDIDATES:
                new_segments = list(segments)
                new_segments[i] = word
                candidates.append(("/".join(new_segments), word))
            break  # only substitute the first version-shaped segment

        dm = DATE_SEGMENT_RE.match(seg)
        if dm:
            year = int(dm.group(1))
            suffix = dm.group(2) or ""
            for delta in (1, 2):
                new_year = year - delta
                if new_year > 1990:
                    new_segments = list(segments)
                    new_segments[i] = f"{new_year}{suffix}"
                    candidates.append(("/".join(new_segments), f"{new_year}{suffix}"))
            break

    return candidates


def fetch_wayback_cdx_paths(domain, timeout=10):
    """Query the Internet Archive's CDX Server API for historically-
    crawled API paths under this domain, regex-extract version/date-shaped
    path segments, dedupe, and return plain LIVE-host-relative path
    strings -- never the archived snapshot URL itself (archived content is
    stale and unsuitable for a live security-control differential; only
    the path is reused, re-probed fresh against the real target).

    research_notes/.../rate_limit_versioning.md: "query
    http://web.archive.org/cdx/search/cdx?url=<target>/api/*&output=json
    &collapse=urlkey&fl=original,timestamp ... regex-extract path segments
    matching /v\\d+/ or date-like tokens; dedupe; then re-probe each
    extracted path against the LIVE host."

    The research also suggests repeating with a wildcard host
    (*.target.com) to catch legacy subdomains (api-v1.target.com,
    legacy.target.com) -- deliberately NOT implemented here (it returns
    cross-host URLs that would need their own base_url to re-probe against
    rather than the single target's base_url this function returns plain
    paths for); noted as a known extension point, not wired up.
    """
    cdx_query = urllib.parse.urlencode({
        "url": f"{domain}/api/*",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original,timestamp",
    })
    cdx_url = f"http://web.archive.org/cdx/search/cdx?{cdx_query}"

    status, _, body = http_request(cdx_url, timeout=timeout)
    if status != 200 or not body:
        return []

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return []

    if not isinstance(rows, list) or len(rows) < 2:
        return []  # header row only (or empty) -- nothing was ever crawled

    found_paths = set()
    for row in rows[1:]:
        if not row or not isinstance(row, list):
            continue
        original_url = row[0] if row else ""
        if not original_url:
            continue
        try:
            archived_path = urllib.parse.urlparse(original_url).path
        except Exception:
            continue
        if not archived_path or len(archived_path) >= 200:
            continue
        has_version_token = bool(WAYBACK_VERSION_TOKEN_RE.search(archived_path))
        looks_api_ish = "/api/" in archived_path.lower()
        if has_version_token or looks_api_ish:
            found_paths.add(archived_path)

    # CDX can return many thousands of rows for a busy domain -- cap to
    # keep the live re-probe pass bounded.
    return sorted(found_paths)[:50]


def check_auth_control_bypass(current_ep, candidate_url):
    """Differential security-control confirmation (auth variant): if the
    CURRENT version of this endpoint required auth (401/403) when probed,
    but the IDENTICAL unauthenticated request against the candidate legacy
    path succeeds, the auth control was never backported to the old
    version -- this is the actual exploit-confirmation step, not just "the
    old path exists". Deliberately sends NO credentials/extra_headers:
    the point is to test whether the candidate is reachable with nothing
    at all, which is only meaningful evidence when the current version
    demonstrably required something.
    """
    if not current_ep.get("auth_required"):
        return None  # current version wasn't auth-gated either -- nothing to differentially confirm

    status, _, body = http_request(candidate_url)
    if status in (200, 201):
        return {
            "control": "authentication",
            "current_status": "401/403 (auth required)",
            "candidate_status": status,
            "candidate_response_length": len(body),
        }
    return None


def check_rate_limit_control_bypass(current_url, candidate_url, extra_headers=None, burst_count=30):
    """Differential security-control confirmation (rate-limit variant):
    burst the CURRENT version first -- if it never 429s within
    burst_count, there's no rate-limit control here to differentially
    confirm, so bail out without even touching the candidate. Only when
    the current version 429s do we burst the candidate with the identical
    request count; a candidate that never 429s under the same burst is the
    bypass (the control fires on current but not on the old path).
    """
    current_hit = None
    for i in range(burst_count):
        status, _, _ = http_request(current_url, headers=extra_headers)
        if status == 429:
            current_hit = i + 1
            break
    if current_hit is None:
        return None

    candidate_hit = None
    candidate_last_status = None
    for i in range(burst_count):
        status, _, _ = http_request(candidate_url, headers=extra_headers)
        candidate_last_status = status
        if status == 429:
            candidate_hit = i + 1
            break

    if candidate_hit is None:
        return {
            "control": "rate_limit",
            "current_rate_limited_at": current_hit,
            "candidate_rate_limited_at": None,
            "candidate_requests_sent": burst_count,
            "candidate_last_status": candidate_last_status,
        }
    return None


def discover_legacy_versions(discovered, base_url, extra_headers=None, burst_count=30,
                              enable_wayback=True, domain=None):
    """API-version/legacy-path discovery and exploit-confirmation.

    For every discovered endpoint path, generates sibling old-version
    candidates (version-token substitution + date-token variants),
    separately fingerprints version/deprecation response headers across
    ALL discovered endpoints, and enumerates the Wayback/CDX archive for
    additional historically-crawled candidate paths to re-probe live.

    Flags a "legacy_api_version_exists" finding (low severity) whenever a
    candidate resolves at all, and the higher-value
    "legacy_api_version_bypass" finding (high severity) only when a
    security control (auth requirement, or a confirmed rate limit)
    demonstrably fires on the current version but not on the candidate --
    the actual exploit-confirmation step, matching real incidents cited in
    rate_limit_versioning.md (St. Luke's Health System deprecated SOAP
    API, an unnamed retailer's legacy XML checkout API, Optus).
    """
    findings = []
    seen_candidates = set()
    bypass_checks_run = 0

    for ep in discovered:
        path = ep.get("path", "")
        if not path:
            continue
        candidates = generate_legacy_candidates(path)
        if not candidates:
            continue

        for candidate_path, variant in candidates:
            if candidate_path == path or candidate_path in seen_candidates:
                continue
            seen_candidates.add(candidate_path)

            probe = probe_path(base_url, candidate_path, extra_headers)
            if not probe:
                continue

            success(f"Legacy candidate resolves: {candidate_path} (variant={variant}, status={probe['status']})")
            findings.append({
                "type": "legacy_api_version_exists",
                "severity": "low",
                "url": probe["url"],
                "current_url": ep.get("url"),
                "variant": variant,
                "status": probe["status"],
                "discovery_method": "version_substitution",
            })

            if bypass_checks_run >= MAX_LEGACY_BYPASS_CHECKS:
                continue
            bypass_checks_run += 1

            bypass = check_auth_control_bypass(ep, probe["url"])
            if not bypass:
                bypass = check_rate_limit_control_bypass(ep.get("url"), probe["url"], extra_headers, burst_count)

            if bypass:
                vuln(f"Legacy version bypasses {bypass['control']} control: {candidate_path}")
                findings.append({
                    "type": "legacy_api_version_bypass",
                    "severity": "high",
                    "url": probe["url"],
                    "current_url": ep.get("url"),
                    "variant": variant,
                    "bypassed_control": bypass["control"],
                    "detail": bypass,
                    "discovery_method": "version_substitution",
                    "description": (
                        f"A security control ({bypass['control']}) confirmed enforced on "
                        f"the current version is absent on legacy path '{candidate_path}'. "
                        "Architectural pattern matches CVE-2023-38507 (Strapi admin-login "
                        "rate limiter bypassed via path case/slash variation) and "
                        "CVE-2025-71399 (Better Auth slash-normalization bypassing "
                        "path-based rate limits) -- a deprecated surface that never "
                        "received the security backport applied to the current version."
                    ),
                })

    # Deprecation/version-disclosure header fingerprinting, across every
    # discovered endpoint (not just legacy candidates) -- RFC 8594
    # Sunset / HTTP Deprecation header / RFC 8288 Link deprecation
    # relation, plus any *version* header.
    for ep in discovered:
        vh = ep.get("version_headers")
        if vh:
            findings.append({
                "type": "api_deprecation_header_disclosed",
                "severity": "low",
                "url": ep.get("url"),
                "headers": vh,
                "description": (
                    "Response discloses version/deprecation metadata "
                    "(Sunset/Deprecation/Link rel=deprecation, or a "
                    "*version* header) -- useful both as a self-reported "
                    "deprecation signal and to identify the current "
                    "version string to decrement from."
                ),
            })

    # Wayback/CDX enumeration -- additional candidates sourced from
    # historically-crawled URLs, re-probed against the LIVE host only.
    if enable_wayback and domain:
        try:
            wayback_paths = fetch_wayback_cdx_paths(domain)
        except Exception as e:
            warn(f"Wayback/CDX enumeration failed: {e}")
            wayback_paths = []

        for wb_path in wayback_paths:
            if wb_path in seen_candidates:
                continue
            seen_candidates.add(wb_path)
            probe = probe_path(base_url, wb_path, extra_headers)
            if not probe:
                continue
            success(f"Wayback-sourced legacy path resolves live: {wb_path}")
            findings.append({
                "type": "legacy_api_version_exists",
                "severity": "low",
                "url": probe["url"],
                "variant": "wayback_cdx",
                "status": probe["status"],
                "discovery_method": "wayback_cdx",
            })

    return findings


def main():
    parser = argparse.ArgumentParser(description="API Discovery - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--threads", type=int, default=15, help="Concurrent threads")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain.startswith("http"):
        base_url = f"https://{domain}"
    else:
        base_url = domain
        domain = urllib.parse.urlparse(domain).hostname

    log(f"Starting API discovery on: {domain}")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    # Phase 1: Fuzz API paths
    log(f"Fuzzing {len(API_PATHS)} common API paths...")
    discovered = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(probe_path, base_url, path, extra_headers): path
            for path in API_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)
                success(f"Found: {result['path']} ({result['status']}, {result['api_type']})")

    # Phase 2: Test GraphQL endpoints
    graphql_results = {}
    graphql_endpoints = [d for d in discovered if d["api_type"] == "graphql"]
    for gql in graphql_endpoints:
        graphql_results[gql["url"]] = test_graphql(gql["url"], extra_headers)

    # Phase 3: Parse OpenAPI docs
    openapi_endpoints = []
    doc_endpoints = [d for d in discovered if d["api_type"] == "openapi_docs"]
    for doc in doc_endpoints:
        openapi_endpoints.extend(extract_openapi_endpoints(doc["url"], extra_headers))

    # Phase 4: Test HTTP methods on key endpoints
    for endpoint in discovered[:20]:
        if endpoint["status"] == 200:
            methods = test_http_methods(endpoint["url"], extra_headers)
            endpoint["methods_available"] = methods

    # Phase 5: Legacy API version discovery + exploit-confirmation
    # (rate_limit_versioning.md) -- version/date-token substitution,
    # deprecation-header fingerprinting, and Wayback/CDX enumeration,
    # with a differential check confirming whether a security control
    # enforced on the current version was backported to the candidate.
    log("Discovering legacy/deprecated API versions...")
    legacy_findings = discover_legacy_versions(discovered, base_url, extra_headers, domain=domain)
    for lf in legacy_findings:
        if lf["type"] == "legacy_api_version_bypass":
            vuln(f"  {lf['url']} bypasses {lf['bypassed_control']} control present on {lf['current_url']}")
        elif lf["type"] == "legacy_api_version_exists":
            success(f"  Legacy candidate live: {lf['url']} (variant={lf['variant']})")
    all_findings = list(legacy_findings)

    output = {
        "meta": {
            "domain": domain,
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "api_discovery",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "paths_tested": len(API_PATHS),
            "apis_found": len(discovered),
            "graphql_endpoints": len(graphql_endpoints),
            "openapi_docs": len(doc_endpoints),
            "documented_endpoints": len(openapi_endpoints),
            "legacy_version_findings": len(legacy_findings),
        },
        "discovered_apis": discovered,
        "graphql": graphql_results,
        "openapi_endpoints": openapi_endpoints,
        "findings": all_findings,
    }

    output_path = args.output or f"api_discovery_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  API DISCOVERY SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  APIs found          : {len(discovered)}")
    print(f"  GraphQL endpoints   : {len(graphql_endpoints)}")
    print(f"  OpenAPI docs        : {len(doc_endpoints)}")
    print(f"  Documented endpoints: {len(openapi_endpoints)}")
    print(f"  Auth-required APIs  : {sum(1 for d in discovered if d.get('auth_required'))}")
    print(f"  Legacy version finds: {len(legacy_findings)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
