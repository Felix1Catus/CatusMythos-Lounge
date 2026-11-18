"""Normalize observed application behavior and rank bounded follow-up work.

This module is deliberately offline: it consumes saved crawler, API discovery,
or browser-audit JSON and emits sanitized, exact-origin endpoint observations.
It never creates requests or treats a discovered route as a vulnerability.
"""

import json
from urllib.parse import urlsplit


def _path_for(url, origin):
    if not isinstance(url, str):
        return None
    parsed, expected = urlsplit(url), urlsplit(origin)
    parsed_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    expected_port = expected.port or (443 if expected.scheme.lower() == "https" else 80)
    if (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed_port) != (
            expected.scheme.lower(), (expected.hostname or "").lower(), expected_port):
        return None
    if parsed.username or parsed.password:
        return None
    return parsed.path or "/"


def normalize_observations(document, origin):
    """Convert crawler/API/browser outputs to the shared portable API inventory."""
    if not isinstance(document, dict):
        raise ValueError("observation input must be a JSON object")
    rows = {}

    def add(url, method="GET", *, status=0, api_type="observed", auth_required=False):
        path = _path_for(url, origin)
        if path is None or "?" in path or "#" in path or len(path) > 2048:
            return
        method = str(method).upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            method = "GET"
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        if not 0 <= status <= 599:
            status = 0
        key = path
        row = rows.setdefault(key, {"path": path, "status": status,
                                    "api_type": str(api_type)[:80],
                                    "auth_required": bool(auth_required),
                                    "methods_tested": []})
        if method not in row["methods_tested"]:
            row["methods_tested"].append(method)
        row["auth_required"] = row["auth_required"] or bool(auth_required)

    for item in document.get("discovered_apis", []):
        if isinstance(item, dict):
            add(item.get("url"), item.get("method", "GET"), status=item.get("status", 0),
                api_type=item.get("api_type", "api"), auth_required=item.get("auth_required", False))
    for item in document.get("endpoints", []):
        if isinstance(item, dict):
            add(item.get("url"), item.get("method", "GET"), status=item.get("status", 0),
                api_type="crawler")
    for item in document.get("forms", []):
        if isinstance(item, dict):
            add(item.get("url") or item.get("action"), item.get("method", "GET"), api_type="form")
    for page in document.get("pages", []):
        if not isinstance(page, dict):
            continue
        page_url = page.get("url")
        add(page_url, "GET", api_type="browser_page")
        for form in page.get("forms", []):
            if isinstance(form, dict):
                add(form.get("action") or page_url, form.get("method", "GET"), api_type="browser_form")
        for link in page.get("links", []):
            add(link, "GET", api_type="browser_link")
    bounded = []
    for key in sorted(rows):
        if len(bounded) >= 1000:
            break
        candidate = bounded + [rows[key]]
        if len(json.dumps(candidate, separators=(",", ":")).encode("utf-8")) > 60000:
            break
        bounded = candidate
    return bounded


def prioritize_cases(cases, outcomes):
    """Rank unresolved benchmark cases for triage; never changes test decisions."""
    outcome_by_id = {item.get("case_id"): item.get("status") for item in outcomes
                     if isinstance(item, dict) and isinstance(item.get("case_id"), str)}
    ranked = []
    for case in cases:
        status = outcome_by_id.get(case["id"], "untested")
        if status in ("confirmed", "tested_negative"):
            continue
        preconditions = " ".join(case.get("preconditions", [])).lower()
        evidence = " ".join(case.get("expected_evidence", [])).lower()
        score = 50
        reasons = ["case is unresolved"]
        if status == "candidate":
            score += 20
            reasons.append("candidate needs validation")
        elif status == "blocked":
            score += 10
            reasons.append("blocked test may need credentials or scope setup")
        if any(term in (preconditions + " " + evidence) for term in ("role", "owner", "object", "auth")):
            score += 15
            reasons.append("authorization evidence is specified")
        if any(term in (preconditions + " " + evidence) for term in ("workflow", "state", "sequence", "business")):
            score += 15
            reasons.append("stateful behavior is specified")
        ranked.append({"case_id": case["id"], "status": status, "priority": score,
                       "reasons": reasons})
    return sorted(ranked, key=lambda item: (-item["priority"], item["case_id"]))
