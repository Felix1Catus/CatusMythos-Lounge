"""Evidence-linked business-context severity for vulnerability chains.

This module deliberately does not inspect vulnerability types or alter CVSS.
It scores explicit business context attached to affected assets, retaining the
source/evidence that supports each contextual assessment.
"""

import ipaddress
import re
from urllib.parse import urlsplit

CONTEXT_FIELDS = {
    "business_criticality": {"low": 1, "moderate": 2, "high": 3, "critical": 4},
    "data_sensitivity": {"public": 1, "internal": 2, "confidential": 3, "restricted": 4},
    "affected_scope": {"individual": 1, "team": 2, "organization": 3, "multi_tenant": 4, "ecosystem": 4},
}
SEVERITY_BY_LEVEL = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
HOST_LABEL_RE = re.compile(r"^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$")


def _host(value):
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip()
    parsed = urlsplit(text if "://" in text else "//" + text)
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return ""
    if (not hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.scheme.lower() not in {"", "http", "https"}):
        return ""
    try:
        normalized = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return ""
    if not normalized or len(normalized) > 253 or any(char.isspace() for char in normalized):
        return ""
    try:
        return ipaddress.ip_address(normalized).compressed
    except ValueError:
        labels = normalized.split(".")
        return normalized if all(HOST_LABEL_RE.fullmatch(label) for label in labels) else ""


def _context_record(record, default_host=None):
    if not isinstance(record, dict):
        raise ValueError("each business context entry must be an object")
    host = _host(record.get("host") or default_host)
    if not host:
        raise ValueError("business context requires a valid host")
    service_name = record.get("service_name")
    purpose = record.get("purpose")
    evidence = record.get("evidence")
    impact_evidence = record.get("impact_evidence")
    source = record.get("source", "")
    if not isinstance(service_name, str) or not service_name.strip() or len(service_name) > 160:
        raise ValueError("business context requires service_name (1-160 characters)")
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 500:
        raise ValueError("business context requires purpose (1-500 characters)")
    if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 1000:
        raise ValueError("business context requires evidence (1-1000 characters)")
    if not isinstance(impact_evidence, str) or not impact_evidence.strip() or len(impact_evidence) > 1000:
        raise ValueError("business context requires impact_evidence (1-1000 characters)")
    if not isinstance(source, str) or len(source) > 500:
        raise ValueError("business context source must be a string under 500 characters")
    normalized = {
        "host": host,
        "service_name": service_name.strip(),
        "purpose": purpose.strip(),
        "evidence": evidence.strip(),
        "impact_evidence": impact_evidence.strip(),
        "source": source.strip(),
    }
    for field, levels in CONTEXT_FIELDS.items():
        value = record.get(field)
        if not isinstance(value, str) or value.lower() not in levels:
            allowed = ", ".join(levels)
            raise ValueError(f"{field} must be one of: {allowed}")
        normalized[field] = value.lower()
    environment = record.get("environment", "unknown")
    if not isinstance(environment, str) or len(environment) > 80:
        raise ValueError("environment must be a string under 80 characters")
    normalized["environment"] = environment.strip() or "unknown"
    return normalized


def load_context_document(data):
    """Validate the versioned explicit context artifact and return host records."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("business context schema_version must be 1")
    assets = data.get("assets")
    if not isinstance(assets, list) or len(assets) > 1000:
        raise ValueError("business context assets must be a list of at most 1000 entries")
    records = [_context_record(item) for item in assets]
    seen = set()
    for record in records:
        if record["host"] in seen:
            raise ValueError(f"duplicate business context host: {record['host']}")
        seen.add(record["host"])
    return records


def _chain_items(chain):
    items = []
    primary = chain.get("primary_finding")
    supporting = chain.get("supporting_findings", [])
    if isinstance(primary, dict):
        items.append(primary)
    if isinstance(supporting, list):
        items.extend(item for item in supporting if isinstance(item, dict))
    return items


def assess_chain_context(chain, *, business_context=None, technical_severity=""):
    """Assess business context without modifying or replacing technical CVSS."""
    records = []
    for item in _chain_items(chain):
        attached = item.get("business_context")
        if attached is None:
            continue
        default_host = item.get("domain") or item.get("url")
        attached_items = attached if isinstance(attached, list) else [attached]
        records.extend(_context_record(entry, default_host) for entry in attached_items)
    explicit = [] if business_context is None else business_context
    if isinstance(explicit, dict):
        explicit = load_context_document(explicit)
    if not isinstance(explicit, list):
        raise ValueError("business_context must be a validated context document or record list")
    records.extend(_context_record(entry) for entry in explicit)

    affected_hosts = {
        host for item in _chain_items(chain)
        if (host := _host(item.get("domain") or item.get("url")))
    }
    matched = [record for record in records if record["host"] in affected_hosts]
    result = {
        "status": "matched" if matched else "no_matching_context",
        "technical_severity": technical_severity or "UNKNOWN",
        "contextual_severity": None,
        "potential_contextual_severity": None,
        "matched_assets": matched,
        "rationale": "",
        "limitations": "Context and impact evidence are supplied by assessment artifacts/operator and are not independently verified.",
    }
    if not matched:
        result["rationale"] = "No evidence-linked business context matched the chain's exact affected hosts."
        return result

    factor_scores = []
    for asset in matched:
        for field, levels in CONTEXT_FIELDS.items():
            factor_scores.append((levels[asset[field]], asset["host"], field, asset[field]))
    highest = max(score for score, *_rest in factor_scores)
    severity = SEVERITY_BY_LEVEL[highest]
    drivers = [f"{host}: {field}={value}" for score, host, field, value in factor_scores if score == highest]
    rationale = "Contextual tier follows the highest documented consequence factor: " + "; ".join(drivers) + "."

    if chain.get("confidence") == "confirmed":
        result["contextual_severity"] = severity
        result["status"] = "matched_confirmed"
        result["rationale"] = rationale
    else:
        result["potential_contextual_severity"] = severity
        result["status"] = "matched_unconfirmed"
        result["rationale"] = "Potential only; the chain is not confirmed, so contextual severity is not assigned. " + rationale
    return result
