#!/usr/bin/env python3
"""Validate and plan a bounded, evidence-led assessment campaign.

This v1 planner is deliberately offline: it never launches tools or sends
requests. It turns an operator-authored manifest into an ordered plan and
coverage ledger input while enforcing exact-origin scope, role labels,
dependency order, request budgets, and explicit state-change declarations.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
MAX_TARGETS = 100
MAX_STEPS = 500
MAX_REQUEST_BUDGET = 100000
MAX_TOOL_REQUESTS = 50000
MAX_JSON_BYTES = 10 * 1024 * 1024
MAX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
MAX_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# Names are stable campaign vocabulary, not arbitrary command execution.
TOOLS = {
    "tech_fingerprint": {"skill": "recon-dominator", "stateful": False},
    "cloud_detector": {"skill": "cloud-pivot-finder", "stateful": False},
    "api_discovery": {"skill": "api-breaker", "stateful": False},
    "api_authz": {"skill": "api-breaker", "stateful": False},
    "web_crawl": {"skill": "webapp-exploit-hunter", "stateful": False},
    "web_sqli": {"skill": "webapp-exploit-hunter", "stateful": False},
    "web_xss": {"skill": "webapp-exploit-hunter", "stateful": False},
    "web_idor": {"skill": "webapp-exploit-hunter", "stateful": False},
    "web_dom_xss": {"skill": "webapp-exploit-hunter", "stateful": False},
    "web_cache": {"skill": "web-cache-auditor", "stateful": False},
    "llm_prompt_injection": {"skill": "16-ai-llm-security", "stateful": False},
    "llm_rag_security": {"skill": "16-ai-llm-security", "stateful": False},
    "llm_unbounded_consumption": {"skill": "16-ai-llm-security", "stateful": False},
    "llm_mcp_security": {"skill": "16-ai-llm-security", "stateful": False},
    "chain_execute": {"skill": "vuln-chain-composer", "stateful": False},
    "external_probe": {"skill": "recon-dominator", "stateful": False},
    "business_workflow": {"skill": "webapp-exploit-hunter", "stateful": True},
    "chain_analysis": {"skill": "vuln-chain-composer", "stateful": False},
    "report": {"skill": "vuln-chain-composer", "stateful": False},
}

# Fixed CLI entrypoints; network calls use a campaign-aware shared helper or
# an explicit per-transport reservation before each request/probe.
TOOL_ENTRYPOINTS = {
    "api_authz": ("api-breaker", "authz_tester.py"),
    "cloud_detector": ("cloud-pivot-finder", "cloud_detector.py"),
    "web_crawl": ("webapp-exploit-hunter", "crawler.py"),
    "web_sqli": ("webapp-exploit-hunter", "sqli_tester.py"),
    "web_xss": ("webapp-exploit-hunter", "xss_tester.py"),
    "web_idor": ("webapp-exploit-hunter", "idor_tester.py"),
    "web_dom_xss": ("webapp-exploit-hunter", "dom_xss_auditor.py"),
    "web_cache": ("web-cache-auditor", "cache_audit.py"),
    "llm_prompt_injection": ("16-ai-llm-security", "prompt_injection_tester.py"),
    "llm_rag_security": ("16-ai-llm-security", "rag_security_tester.py"),
    "llm_unbounded_consumption": ("16-ai-llm-security", "unbounded_consumption_tester.py"),
    "llm_mcp_security": ("16-ai-llm-security", "mcp_security_tester.py"),
    "chain_execute": ("vuln-chain-composer", "execute_chain.py"),
}
CLI_TIMEOUT_SECONDS = 1800


class CampaignError(ValueError):
    """Invalid or unsafe campaign manifest."""


def canonical_origin(value):
    """Return exact HTTP(S) origin or reject credentials, paths, and bad ports."""
    if not isinstance(value, str) or not value.strip():
        raise CampaignError("target must be an absolute HTTP(S) URL")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise CampaignError("target URL has an invalid port") from exc
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise CampaignError("scope entries must be credential-free HTTP(S) origins")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CampaignError("target hostname is invalid") from exc
    scheme = parsed.scheme.lower()
    port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise CampaignError("target port is invalid")
    host = "[" + host + "]" if ":" in host else host
    return "{}://{}:{}".format(scheme, host, port)


def target_origin(value):
    """Validate an in-scope target URL while allowing its path and query."""
    if not isinstance(value, str) or not value.strip():
        raise CampaignError("target URL must be an absolute HTTP(S) URL")
    try:
        parsed = urlsplit(value.strip())
        parsed.port
    except ValueError as exc:
        raise CampaignError("target URL has an invalid port") from exc
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or any(char in value for char in "\r\n\\")):
        raise CampaignError("target URL must be credential-free HTTP(S) without fragments")
    return canonical_origin("{}://{}{}".format(parsed.scheme, parsed.netloc, "/"))


def _bounded_int(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CampaignError("{} must be an integer from {} to {}".format(label, minimum, maximum))
    return value


def _normalize_network_host(value):
    if not isinstance(value, str) or not value or len(value) > 253 or any(
            char.isspace() or ord(char) < 33 or char in "/\\@?#" for char in value):
        raise CampaignError("network endpoint host must be a bare IP address or DNS name")
    host = value.strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise CampaignError("network endpoint host is invalid") from exc
        labels = host.split(".")
        if (not host or len(host) > 253 or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label) for label in labels)):
            raise CampaignError("network endpoint host is invalid")
        return host


def _validate_network_endpoints(value):
    if not isinstance(value, list) or len(value) > 500:
        raise CampaignError("scope.network_endpoints must be a list of at most 500 entries")
    normalized, seen, total_ports = [], set(), 0
    for item in value:
        if not isinstance(item, dict):
            raise CampaignError("each network endpoint must be an object")
        host = _normalize_network_host(item.get("host"))
        protocol = item.get("protocol")
        if protocol not in ("tcp", "udp"):
            raise CampaignError("network endpoint protocol must be tcp or udp")
        ports = item.get("ports")
        if not isinstance(ports, list) or not ports or len(ports) > 256:
            raise CampaignError("network endpoint ports must be a list of 1 to 256 ports")
        checked_ports = [_bounded_int(port, "network endpoint port", 1, 65535) for port in ports]
        if len(set(checked_ports)) != len(checked_ports):
            raise CampaignError("network endpoint ports must be unique")
        total_ports += len(checked_ports)
        if total_ports > 10000:
            raise CampaignError("scope.network_endpoints may contain at most 10000 host/protocol/port tuples")
        for port in checked_ports:
            key = (host, protocol, port)
            if key in seen:
                raise CampaignError("scope.network_endpoints contains a duplicate host/protocol/port")
            seen.add(key)
        normalized.append({"host": host, "protocol": protocol, "ports": sorted(checked_ports)})
    return normalized


def _role_cases(target_id, target, objects):
    module_path = Path(__file__).resolve().parent / "role_matrix.py"
    spec = importlib.util.spec_from_file_location("catus_role_matrix", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = module.build_matrix(list(target["roles"].values()), objects)
    for row in matrix:
        row["target"] = target_id
    return matrix


def validate_manifest(manifest):
    """Validate an operator-authored campaign without reading credentials."""
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise CampaignError("manifest schema_version must be 1")
    engagement = manifest.get("engagement")
    if not isinstance(engagement, str) or not engagement.strip() or len(engagement) > 120:
        raise CampaignError("engagement must be a nonempty label under 120 characters")

    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        raise CampaignError("scope must be an object with explicit origins")
    origins = scope.get("origins")
    if not isinstance(origins, list) or not origins or len(origins) > MAX_TARGETS:
        raise CampaignError("scope.origins must contain 1 to {} origins".format(MAX_TARGETS))
    normalized_origins = [canonical_origin(item) for item in origins]
    if len(set(normalized_origins)) != len(normalized_origins):
        raise CampaignError("scope.origins contains duplicate origins")
    request_budget = _bounded_int(scope.get("request_budget"), "scope.request_budget", 1, MAX_REQUEST_BUDGET)
    allow_mutations = scope.get("allow_state_changes", False)
    if not isinstance(allow_mutations, bool):
        raise CampaignError("scope.allow_state_changes must be boolean")
    network_endpoints = _validate_network_endpoints(scope.get("network_endpoints", []))

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        raise CampaignError("targets must contain 1 to {} entries".format(MAX_TARGETS))
    targets_by_id = {}
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("id"), str) or not MAX_ID.fullmatch(target["id"]):
            raise CampaignError("each target needs a valid id")
        if target["id"] in targets_by_id:
            raise CampaignError("duplicate target id: " + target["id"])
        origin = target_origin(target.get("url"))
        if origin not in normalized_origins:
            raise CampaignError("target {} is outside the explicit origin scope".format(target["id"]))
        roles = target.get("roles", [{"name": "anonymous"}])
        if not isinstance(roles, list) or not roles or len(roles) > 32:
            raise CampaignError("target roles must contain 1 to 32 entries")
        role_map = {}
        for role in roles:
            if not isinstance(role, dict) or not isinstance(role.get("name"), str):
                raise CampaignError("each role needs a name")
            name = role["name"].strip()
            if not name or len(name) > 80 or name in role_map:
                raise CampaignError("role names must be unique, nonempty labels under 80 characters")
            env_name = role.get("credential_env")
            if env_name is not None and (not isinstance(env_name, str) or not MAX_ENV.fullmatch(env_name)):
                raise CampaignError("credential_env must be an environment-variable name")
            header_name = role.get("credential_header")
            if env_name and (not isinstance(header_name, str) or not MAX_HEADER.fullmatch(header_name)):
                raise CampaignError("credential_env requires a valid credential_header")
            if header_name is not None and (not isinstance(header_name, str) or not MAX_HEADER.fullmatch(header_name)):
                raise CampaignError("credential_header must be a valid HTTP header name")
            role_map[name] = {"name": name, "credential_env": env_name,
                              "credential_header": header_name}
        targets_by_id[target["id"]] = {"id": target["id"], "url": target["url"],
                                        "origin": origin, "roles": role_map}

    steps = manifest.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise CampaignError("steps must contain 1 to {} entries".format(MAX_STEPS))
    seen = set()
    planned = []
    budget_used = 0
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise CampaignError("each step must be an object")
        step_id, tool, target_id = step.get("id"), step.get("tool"), step.get("target")
        if not isinstance(step_id, str) or not MAX_ID.fullmatch(step_id) or step_id in seen:
            raise CampaignError("step ids must be unique valid identifiers")
        if not isinstance(tool, str) or tool not in TOOLS:
            raise CampaignError("step {} uses an unsupported tool".format(step_id))
        target = targets_by_id.get(target_id)
        if target is None:
            raise CampaignError("step {} references an unknown target".format(step_id))
        role_name = step.get("role", "anonymous")
        if not isinstance(role_name, str) or role_name not in target["roles"]:
            raise CampaignError("step {} references an undeclared target role".format(step_id))
        dependencies = step.get("depends_on", [])
        if (not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies)
                or len(set(dependencies)) != len(dependencies)):
            raise CampaignError("step {} dependencies must be a unique list".format(step_id))
        if any(dep not in seen for dep in dependencies):
            raise CampaignError("step {} dependencies must refer to earlier steps".format(step_id))
        max_requests = _bounded_int(step.get("max_requests"), step_id + ".max_requests", 1, MAX_TOOL_REQUESTS)
        budget_used += max_requests
        if budget_used > request_budget:
            raise CampaignError("declared step budgets exceed scope.request_budget")
        mode = "stateful" if TOOLS[tool]["stateful"] else "active"
        cleanup = step.get("cleanup", [])
        fixture_note = step.get("fixture_note")
        if mode == "stateful":
            if not allow_mutations:
                raise CampaignError("stateful step {} requires scope.allow_state_changes".format(step_id))
            if not isinstance(fixture_note, str) or not fixture_note.strip():
                raise CampaignError("stateful step {} requires a fixture_note".format(step_id))
            if not isinstance(cleanup, list) or (not cleanup and not step.get("manual_cleanup_note")):
                raise CampaignError("stateful step {} requires cleanup or manual_cleanup_note".format(step_id))
            if any(not isinstance(action, str) or not action.strip() or len(action) > 240
                   or any(ord(char) < 32 or ord(char) == 127 for char in action) for action in cleanup):
                raise CampaignError("stateful cleanup entries must be short action labels")
            manual_note = step.get("manual_cleanup_note")
            if manual_note is not None and (not isinstance(manual_note, str) or not manual_note.strip()
                                            or len(manual_note) > 500):
                raise CampaignError("manual_cleanup_note must be a short nonempty explanation")
            scenario_file = step.get("scenario_file")
            if (not isinstance(scenario_file, str) or not scenario_file.strip()
                    or Path(scenario_file).is_absolute() or ".." in Path(scenario_file).parts
                    or len(scenario_file) > 500):
                raise CampaignError("stateful steps require a relative scenario_file without parent traversal")
        elif cleanup or fixture_note:
            raise CampaignError("fixture and cleanup fields are reserved for stateful steps")
        planned.append({"id": step_id, "tool": tool, "skill": TOOLS[tool]["skill"],
                        "target": target_id, "origin": target["origin"], "role": role_name,
                        "depends_on": dependencies, "max_requests": max_requests,
                        "mode": mode, "position": index + 1,
                        "status": "planned", "cleanup": cleanup if mode == "stateful" else [],
                        "fixture_note": fixture_note if mode == "stateful" else None,
                        "scenario_file": step.get("scenario_file") if mode == "stateful" else None,
                        "manual_cleanup_note": step.get("manual_cleanup_note") if mode == "stateful" else None})
        seen.add(step_id)
    authorization_matrices = manifest.get("authorization_matrices", [])
    if not isinstance(authorization_matrices, list) or len(authorization_matrices) > MAX_TARGETS:
        raise CampaignError("authorization_matrices must be a bounded list")
    authorization_cases = []
    for item in authorization_matrices:
        if (not isinstance(item, dict) or not isinstance(item.get("target"), str)
                or item.get("target") not in targets_by_id):
            raise CampaignError("authorization matrix references an unknown target")
        try:
            authorization_cases.extend(_role_cases(item["target"], targets_by_id[item["target"]], item.get("objects")))
        except (ValueError, OSError) as exc:
            raise CampaignError("invalid authorization matrix: {}".format(exc)) from exc
    context_assets = _validate_business_context(manifest.get("business_context"), normalized_origins)
    return {"schema_version": 1, "engagement": engagement.strip(),
            "scope": {"origins": normalized_origins, "request_budget": request_budget,
                      "declared_request_budget": budget_used, "allow_state_changes": allow_mutations,
                      "network_endpoints": network_endpoints},
            "targets": [{"id": item["id"], "url": item["url"], "origin": item["origin"],
                         "roles": list(item["roles"].values())} for item in targets_by_id.values()],
            "authorization_matrix": authorization_cases,
            "business_context": context_assets,
            "steps": planned}


def _validate_business_context(document, origins):
    if document is None:
        return {"schema_version": 1, "assets": []}
    module_path = Path(__file__).resolve().parents[1] / "skills" / "vuln-chain-composer" / "scripts" / "context_severity.py"
    spec = importlib.util.spec_from_file_location("catus_context_severity", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        records = module.load_context_document(document)
    except (ValueError, TypeError) as exc:
        raise CampaignError("invalid business_context: {}".format(exc)) from exc
    scoped_hosts = {urlsplit(origin).hostname for origin in origins}
    if any(record["host"] not in scoped_hosts for record in records):
        raise CampaignError("business_context assets must match an explicitly scoped hostname")
    return {"schema_version": 1, "assets": records}


def load_coverage_manifest(document):
    """Validate and normalize a versioned test-case coverage manifest."""
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise CampaignError("coverage manifest schema_version must be 1")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) > 10000:
        raise CampaignError("coverage cases must be a list of at most 10000 entries")
    result, seen = [], set()
    for case in cases:
        if not isinstance(case, dict):
            raise CampaignError("coverage case must be an object")
        case_id, behavior = case.get("id"), case.get("behavior")
        if not isinstance(case_id, str) or not MAX_ID.fullmatch(case_id) or case_id in seen:
            raise CampaignError("coverage case ids must be unique valid identifiers")
        if not isinstance(behavior, str) or not behavior.strip() or len(behavior) > 160:
            raise CampaignError("coverage case needs a behavior label")
        for field in ("tool", "role", "configuration"):
            value = case.get(field, {"role": "any", "configuration": "any"}.get(field, ""))
            if not isinstance(value, str) or len(value) > 160:
                raise CampaignError("coverage {} must be a bounded string".format(field))
        preconditions = case.get("preconditions", [])
        if not isinstance(preconditions, list) or any(not isinstance(value, str) for value in preconditions):
            raise CampaignError("coverage preconditions must be strings")
        expected_evidence = case.get("expected_evidence", [])
        if (not isinstance(expected_evidence, list) or len(expected_evidence) > 20
                or any(not isinstance(value, str) or not value.strip() or len(value) > 500
                       for value in expected_evidence)):
            raise CampaignError("expected_evidence must be a bounded list of evidence requirements")
        expected = case.get("expected", "unknown")
        if expected not in ("vulnerable", "not_vulnerable", "unknown"):
            raise CampaignError("coverage expected must be vulnerable, not_vulnerable, or unknown")
        gold_source = case.get("gold_source", "")
        if expected != "unknown" and (not isinstance(gold_source, str) or not gold_source.strip()
                                      or len(gold_source) > 500):
            raise CampaignError("labeled coverage cases require a bounded gold_source")
        result.append({"id": case_id, "behavior": behavior.strip(),
                       "tool": case.get("tool", ""), "role": case.get("role", "any"),
                       "configuration": case.get("configuration", "any"),
                       "preconditions": preconditions, "expected_evidence": expected_evidence,
                       "expected": expected,
                       "gold_source": gold_source if expected != "unknown" else ""})
        seen.add(case_id)
    return result


def evaluate_coverage(cases, step_results):
    """Summarize outcomes without treating missing/blocked tests as negatives."""
    outcomes = {}
    for result in step_results:
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str):
            continue
        status = result.get("status")
        if status == "confirmed":
            review = result.get("evidence_review")
            checks = review.get("proof_checks", {}) if isinstance(review, dict) else {}
            if (not isinstance(review, dict) or review.get("schema_version") != 1
                    or review.get("assessment_state") != "confirmed"
                    or not isinstance(checks, dict) or checks.get("complete") is not True):
                status = "candidate"
        if status in ("confirmed", "candidate", "tested_negative", "blocked", "untested"):
            outcomes.setdefault(result["case_id"], []).append(status)
    rows = []
    for case in cases:
        observed = outcomes.get(case["id"], [])
        status = ("conflict" if "confirmed" in observed and "tested_negative" in observed else
                  "confirmed" if "confirmed" in observed else
                  "candidate" if "candidate" in observed else
                  "tested_negative" if "tested_negative" in observed else
                  "blocked" if "blocked" in observed else "untested")
        rows.append(dict(case, status=status))
    counts = {key: sum(row["status"] == key for row in rows)
              for key in ("confirmed", "candidate", "tested_negative", "blocked", "untested", "conflict")}
    counts["total"] = len(rows)
    counts["executed"] = counts["confirmed"] + counts["candidate"] + counts["tested_negative"]
    counts["execution_coverage_percent"] = round(100 * counts["executed"] / len(rows), 1) if rows else 0.0
    tp = fp = fn = tn = unresolved_labeled = 0
    for row in rows:
        expected, status = row["expected"], row["status"]
        if expected == "unknown":
            continue
        if status == "confirmed":
            if expected == "vulnerable":
                tp += 1
            else:
                fp += 1
        elif status == "tested_negative":
            if expected == "vulnerable":
                fn += 1
            else:
                tn += 1
        else:
            unresolved_labeled += 1
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    metrics = {"true_positive": tp, "false_positive": fp, "false_negative": fn,
               "true_negative": tn, "unresolved_labeled": unresolved_labeled,
               "labeled_cases": tp + fp + fn + tn + unresolved_labeled,
               "precision_percent": round(100 * tp / precision_denominator, 1)
               if precision_denominator else None,
               "recall_percent": round(100 * tp / recall_denominator, 1)
               if recall_denominator else None,
               "scope_note": "Metrics apply only to labeled cases in this manifest; they do not estimate internet-wide accuracy."}
    dimensions = {}
    for field in ("tool", "role", "configuration"):
        groups = {}
        for row in rows:
            label = row.get(field) or "unspecified"
            groups.setdefault(label, []).append(row)
        dimensions[field] = {
            label: {
                "total": len(group),
                "executed": sum(item["status"] in ("confirmed", "candidate", "tested_negative")
                                for item in group),
                **{status: sum(item["status"] == status for item in group)
                   for status in ("confirmed", "candidate", "tested_negative", "blocked", "untested", "conflict")},
            }
            for label, group in sorted(groups.items())
        }
    return {"counts": counts, "cases": rows, "coverage_by_dimension": dimensions,
            "labeled_metrics": metrics if metrics["labeled_cases"] else None}


def enrich_plan_with_knowledge(plan, database, engagement):
    """Attach sanitized, exact-origin facts as advisory inputs; never suppress tests."""
    module_path = Path(__file__).resolve().parent / "target_knowledge.py"
    spec = importlib.util.spec_from_file_location("catus_target_knowledge", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        store = module.KnowledgeStore(database, engagement)
    except (OSError, ValueError, module.sqlite3.Error) as exc:
        raise CampaignError("cannot open selected target knowledge: {}".format(exc)) from exc
    for target in plan["targets"]:
        rows = store.query(target["url"])
        safe_rows = []
        for row in rows:
            value = module.KnowledgeStore._portable_value(row["kind"], row["value"])
            if value is None:
                continue
            safe_row = {key: row[key] for key in (
                "kind", "fact_key", "resource", "source", "confidence", "observed_at", "expires_at")}
            safe_row["value"] = value
            safe_rows.append(safe_row)
        target["knowledge_observations"] = safe_rows
        target["knowledge_advisory"] = (
            "Fresh exact-origin observations are context only; selected tools may reuse exact matching facts, "
            "and vulnerability-specific proof still requires its own checks.")
    return plan


class CampaignLedger:
    """SQLite-backed campaign identity, step state, and aggregate request counter."""

    def __init__(self, database, campaign_id):
        if not isinstance(campaign_id, str) or not MAX_ID.fullmatch(campaign_id):
            raise CampaignError("campaign_id must be a stable identifier (letters, digits, . _ -)")
        self.database = str(database)
        self.campaign_id = campaign_id
        try:
            # Some registered adapters (API discovery) invoke the request gate
            # from a bounded worker pool; their gate serializes ledger access.
            self.connection = sqlite3.connect(self.database, timeout=15, check_same_thread=False)
            self.connection.execute("PRAGMA busy_timeout=15000")
            self.connection.executescript("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    engagement TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    request_budget INTEGER NOT NULL,
                    requests_used INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS campaign_steps (
                    campaign_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requests_used INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (campaign_id, step_id),
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
                );
                CREATE TABLE IF NOT EXISTS campaign_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    step_id TEXT,
                    event TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS campaign_step_dependencies (
                    campaign_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    dependency_id TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, step_id, dependency_id)
                );
                CREATE TABLE IF NOT EXISTS campaign_step_registry (
                    campaign_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    max_requests INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (campaign_id, step_id)
                );
                CREATE TABLE IF NOT EXISTS campaign_step_attestations (
                    campaign_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    note_sha256 TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (campaign_id, step_id)
                );
                CREATE TABLE IF NOT EXISTS campaign_network_endpoints (
                    campaign_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    PRIMARY KEY (campaign_id, host, protocol, port)
                );
            """)
            registry_columns = {row[1] for row in self.connection.execute(
                "PRAGMA table_info(campaign_step_registry)")}
            if "max_requests" not in registry_columns:
                self.connection.execute(
                    "ALTER TABLE campaign_step_registry ADD COLUMN max_requests INTEGER NOT NULL DEFAULT 0")
        except sqlite3.Error as exc:
            raise CampaignError("cannot open campaign ledger: {}".format(exc)) from exc

    def bind(self, manifest):
        plan = validate_manifest(manifest)
        fingerprint = hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        connection = self.connection
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT engagement, manifest_sha256, request_budget FROM campaigns WHERE campaign_id=?",
                (self.campaign_id,)).fetchone()
            if row is None:
                connection.execute("INSERT INTO campaigns VALUES (?, ?, ?, ?, 0, ?)",
                                   (self.campaign_id, plan["engagement"], fingerprint,
                                    plan["scope"]["request_budget"], time.time_ns()))
                self._event(None, "campaign_created")
            elif row != (plan["engagement"], fingerprint, plan["scope"]["request_budget"]):
                raise CampaignError("campaign id is already bound to a different engagement or manifest")
            for step in plan["steps"]:
                connection.execute(
                    "INSERT OR IGNORE INTO campaign_steps "
                    "(campaign_id, step_id, status, requests_used, updated_at) VALUES (?, ?, 'planned', 0, ?)",
                    (self.campaign_id, step["id"], time.time_ns()))
                connection.execute(
                    "INSERT OR IGNORE INTO campaign_step_registry"
                    "(campaign_id, step_id, tool, max_requests) VALUES (?, ?, ?, ?)",
                    (self.campaign_id, step["id"], step["tool"], step["max_requests"]))
                connection.execute(
                    "UPDATE campaign_step_registry SET max_requests=? "
                    "WHERE campaign_id=? AND step_id=? AND max_requests=0",
                    (step["max_requests"], self.campaign_id, step["id"]))
                for dependency_id in step["depends_on"]:
                    connection.execute(
                        "INSERT OR IGNORE INTO campaign_step_dependencies "
                        "(campaign_id, step_id, dependency_id) VALUES (?, ?, ?)",
                        (self.campaign_id, step["id"], dependency_id))
            for endpoint in plan["scope"]["network_endpoints"]:
                for port in endpoint["ports"]:
                    connection.execute(
                        "INSERT OR IGNORE INTO campaign_network_endpoints"
                        "(campaign_id, host, protocol, port) VALUES (?, ?, ?, ?)",
                        (self.campaign_id, endpoint["host"], endpoint["protocol"], port))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return plan

    def _event(self, step_id, event):
        self.connection.execute(
            "INSERT INTO campaign_events(campaign_id, step_id, event, created_at) VALUES (?, ?, ?, ?)",
            (self.campaign_id, step_id, event, time.time_ns()))

    def start_step(self, step_id, retry_interrupted=False):
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT status FROM campaign_steps WHERE campaign_id=? AND step_id=?",
                (self.campaign_id, step_id)).fetchone()
            if row is None:
                raise CampaignError("campaign step is not registered")
            if row[0] == "completed":
                raise CampaignError("campaign step is already completed; refusing duplicate execution")
            if row and row[0] == "running" and not retry_interrupted:
                raise CampaignError("campaign step has an unfinished run; inspect it before explicit retry")
            if row and row[0] in ("interrupted", "failed") and not retry_interrupted:
                raise CampaignError("campaign step was interrupted; use --retry-interrupted after review")
            dependencies = self.connection.execute(
                "SELECT d.dependency_id, s.status FROM campaign_step_dependencies d "
                "LEFT JOIN campaign_steps s ON s.campaign_id=d.campaign_id AND s.step_id=d.dependency_id "
                "WHERE d.campaign_id=? AND d.step_id=?",
                (self.campaign_id, step_id)).fetchall()
            unfinished = [dependency_id for dependency_id, status in dependencies if status != "completed"]
            if unfinished:
                raise CampaignError("campaign step dependencies are not completed: {}".format(
                    ", ".join(unfinished)))
            self.connection.execute(
                "INSERT INTO campaign_steps(campaign_id, step_id, status, requests_used, updated_at) "
                "VALUES (?, ?, 'running', 0, ?) ON CONFLICT(campaign_id, step_id) DO UPDATE SET "
                "status='running', updated_at=excluded.updated_at",
                (self.campaign_id, step_id, time.time_ns()))
            self._event(step_id, "step_started")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def attest_external_step(self, step_id, operator_note):
        """Record operator-confirmed completion of an adapterless, non-workflow step."""
        if not isinstance(operator_note, str) or not operator_note.strip() or len(operator_note) > 1000:
            raise CampaignError("operator_note must be a nonempty note under 1000 characters")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT status FROM campaign_steps WHERE campaign_id=? AND step_id=?",
                (self.campaign_id, step_id)).fetchone()
            if row is None:
                raise CampaignError("campaign step is not registered")
            tool = self.connection.execute(
                "SELECT tool FROM campaign_step_registry WHERE campaign_id=? AND step_id=?",
                (self.campaign_id, step_id)).fetchone()
            if tool is None:
                raise CampaignError("campaign step is not registered")
            if tool[0] in ("business_workflow", "tech_fingerprint", "api_discovery"):
                raise CampaignError("native campaign steps must be completed through run-step")
            if row[0] != "planned":
                raise CampaignError("only a still-planned external step can be attested")
            dependencies = self.connection.execute(
                "SELECT d.dependency_id, s.status FROM campaign_step_dependencies d "
                "LEFT JOIN campaign_steps s ON s.campaign_id=d.campaign_id AND s.step_id=d.dependency_id "
                "WHERE d.campaign_id=? AND d.step_id=?",
                (self.campaign_id, step_id)).fetchall()
            unfinished = [dependency_id for dependency_id, status in dependencies if status != "completed"]
            if unfinished:
                raise CampaignError("campaign step dependencies are not completed: {}".format(
                    ", ".join(unfinished)))
            self.connection.execute(
                "UPDATE campaign_steps SET status='completed', updated_at=? WHERE campaign_id=? AND step_id=?",
                (time.time_ns(), self.campaign_id, step_id))
            note_digest = hashlib.sha256(operator_note.strip().encode("utf-8")).hexdigest()
            self.connection.execute(
                "INSERT INTO campaign_step_attestations VALUES (?, ?, ?, ?)",
                (self.campaign_id, step_id, note_digest, time.time_ns()))
            self._event(step_id, "step_operator_attested")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def reserve_request(self, step_id, step_budget):
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            campaign = self.connection.execute(
                "SELECT request_budget, requests_used FROM campaigns WHERE campaign_id=?",
                (self.campaign_id,)).fetchone()
            step = self.connection.execute(
                "SELECT requests_used, status FROM campaign_steps WHERE campaign_id=? AND step_id=?",
                (self.campaign_id, step_id)).fetchone()
            if campaign is None or step is None:
                raise CampaignError("campaign step is not registered in the ledger")
            if step[1] != "running":
                raise CampaignError("request reservations require a running campaign step")
            if campaign[1] >= campaign[0]:
                raise CampaignError("campaign-wide request budget exhausted")
            if step[0] >= step_budget:
                raise CampaignError("step request budget exhausted")
            self.connection.execute("UPDATE campaigns SET requests_used=requests_used+1 WHERE campaign_id=?",
                                    (self.campaign_id,))
            self.connection.execute("UPDATE campaign_steps SET requests_used=requests_used+1, updated_at=? "
                                    "WHERE campaign_id=? AND step_id=?",
                                    (time.time_ns(), self.campaign_id, step_id))
            self._event(step_id, "request_reserved")
            self.connection.commit()
            return True
        except Exception:
            self.connection.rollback()
            raise

    def finish_step(self, step_id, status):
        if status not in ("completed", "failed", "interrupted"):
            raise CampaignError("invalid campaign step state")
        self.connection.execute("BEGIN IMMEDIATE")
        self.connection.execute("UPDATE campaign_steps SET status=?, updated_at=? "
                                "WHERE campaign_id=? AND step_id=?",
                                (status, time.time_ns(), self.campaign_id, step_id))
        self._event(step_id, "step_" + status)
        self.connection.commit()

    def summary(self):
        campaign = self.connection.execute(
            "SELECT engagement, request_budget, requests_used FROM campaigns WHERE campaign_id=?",
            (self.campaign_id,)).fetchone()
        if campaign is None:
            raise CampaignError("campaign id is not initialized")
        steps = self.connection.execute(
            "SELECT step_id, status, requests_used FROM campaign_steps WHERE campaign_id=? ORDER BY rowid",
            (self.campaign_id,)).fetchall()
        return {"campaign_id": self.campaign_id, "engagement": campaign[0],
                "requests_used": campaign[2], "request_budget": campaign[1],
                "steps": [{"step_id": row[0], "status": row[1], "requests_used": row[2]}
                          for row in steps],
                "secrets_or_response_bodies_recorded": False}

    def close(self):
        self.connection.close()


def execute_workflow_step(manifest, manifest_path, step_id, confirm_target, request_func,
                          credential_environment=None, budget_reserver=None):
    """Execute one explicitly gated business scenario through an injected transport."""
    plan = validate_manifest(manifest)
    selected = next((step for step in plan["steps"] if step["id"] == step_id), None)
    source_step = next((step for step in manifest["steps"] if step.get("id") == step_id), None)
    if selected is None or source_step is None:
        raise CampaignError("selected step does not exist")
    if selected["tool"] != "business_workflow" or selected["mode"] != "stateful":
        raise CampaignError("run-workflow supports only explicitly gated business_workflow steps")
    if canonical_origin(confirm_target) != selected["origin"]:
        raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
    base_dir = Path(manifest_path).expanduser().resolve().parent
    scenario_path = (base_dir / selected["scenario_file"]).resolve()
    try:
        scenario_path.relative_to(base_dir)
    except ValueError as exc:
        raise CampaignError("scenario_file resolves outside the manifest directory") from exc
    if not scenario_path.is_file():
        raise CampaignError("scenario_file does not exist")
    scenario = _read_json(scenario_path)

    target = next(item for item in plan["targets"] if item["id"] == selected["target"])
    role = next(item for item in target["roles"] if item["name"] == selected["role"])
    module_path = (Path(__file__).resolve().parents[1] / "skills" / "webapp-exploit-hunter" /
                   "scripts" / "business_scenario.py")
    spec = importlib.util.spec_from_file_location("catus_business_scenario", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        scenario_plan = module.validate_scenario(scenario, target["url"],
                                                 max_requests=selected["max_requests"])
    except (ValueError, TypeError) as exc:
        raise CampaignError("business scenario failed validation: {}".format(exc)) from exc

    headers = {}
    env = os.environ if credential_environment is None else credential_environment
    if role.get("credential_env"):
        credential = env.get(role["credential_env"])
        if (not isinstance(credential, str) or not credential or len(credential) > 8192
                or any(ord(char) < 32 or ord(char) == 127 for char in credential)):
            raise CampaignError("selected role credential environment value is missing or invalid")
        headers[role["credential_header"]] = credential

    sent = 0
    exhausted = False

    def bounded_request(url, method="GET", data=None, headers=None):
        nonlocal sent, exhausted
        if sent >= selected["max_requests"]:
            exhausted = True
            return 0, {}, ""
        if budget_reserver is not None:
            try:
                budget_reserver(step_id, selected["max_requests"])
            except CampaignError:
                exhausted = True
                return 0, {}, ""
        sent += 1
        return request_func(url, method=method, data=data, headers=headers or {})

    result = module.execute_scenario(scenario, target["url"], bounded_request, headers=headers)
    statuses = [status for item in result.get("results", [])
                for status in item.get("statuses", []) if isinstance(status, int)]
    if not scenario_plan["mutating"]:
        cleanup_status = "not_required"
    elif result.get("throttled"):
        cleanup_status = "skipped_after_throttle"
    elif 0 in statuses or exhausted:
        cleanup_status = "attempted_or_blocked_unverified"
    elif not scenario.get("cleanup"):
        cleanup_status = "manual_cleanup_required"
    else:
        cleanup_status = "attempted_unverified"
    result["execution"] = {
        "step_id": step_id,
        "requests_sent": sent,
        "request_budget": selected["max_requests"],
        "budget_exhausted": exhausted,
        "declared_request_count": scenario_plan["request_count"],
        "cleanup_status": cleanup_status,
        "credential_values_recorded": False,
        "response_values_recorded": False,
    }
    return result


def execute_fingerprint_step(manifest, step_id, confirm_target, request_reserver):
    """Run the registered single-origin fingerprint adapter under the campaign request cap."""
    plan = validate_manifest(manifest)
    selected = next((step for step in plan["steps"] if step["id"] == step_id), None)
    if selected is None or selected["tool"] != "tech_fingerprint":
        raise CampaignError("selected step does not exist or is not a tech_fingerprint step")
    if canonical_origin(confirm_target) != selected["origin"]:
        raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
    target = next(item for item in plan["targets"] if item["id"] == selected["target"])
    script_dir = Path(__file__).resolve().parents[1] / "skills" / "recon-dominator" / "scripts"
    script_path = script_dir / "tech_fingerprint.py"
    spec = importlib.util.spec_from_file_location("catus_campaign_tech_fingerprint", script_path)
    if spec is None or spec.loader is None:
        raise CampaignError("cannot load the registered technology fingerprint adapter")
    module = importlib.util.module_from_spec(spec)
    previous_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(script_dir))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
        sys.modules.pop("_common", None)
        if previous_common is not None:
            sys.modules["_common"] = previous_common

    requests_sent = 0
    budget_exhausted = False

    def reserve_request():
        nonlocal requests_sent, budget_exhausted
        try:
            request_reserver(step_id, selected["max_requests"])
        except CampaignError:
            budget_exhausted = True
            return False
        requests_sent += 1
        return True

    hostname = urlsplit(target["url"]).netloc
    fingerprint = module.fingerprint_host(hostname, before_request=reserve_request)
    details = fingerprint.get("details", {})
    security_headers = details.get("security_headers", {})
    known_technologies = {technology for mapping in module.HEADER_SIGNATURES.values()
                          for technology in mapping.values()}
    known_technologies.update(module.COOKIE_SIGNATURES.values())
    known_technologies.update(technology for _pattern, technology in module.BODY_SIGNATURES)
    versioned = details.get("versioned_components", [])
    versioned = versioned if isinstance(versioned, list) else []
    safe_versioned = [{"kind": item["kind"], "name": item["name"], "version": item["version"]}
                      for item in versioned[:100] if isinstance(item, dict)
                      and all(isinstance(item.get(field), str) and len(item[field]) <= 160
                              for field in ("kind", "name", "version"))]
    return {
        "tool": "tech_fingerprint",
        "technologies": sorted(set(fingerprint.get("technologies", [])) & known_technologies),
        "waf": [item for item in details.get("waf", []) if item in module.WAF_SIGNATURES.values()],
        "cdn": [item for item in details.get("cdn", []) if item in module.CDN_HEADER_SIGNATURES.values()],
        "versioned_components": safe_versioned,
        "security_headers": {name: {"present": value.get("present") is True}
                             for name, value in security_headers.items() if isinstance(value, dict)},
        "execution": {"step_id": step_id, "requests_sent": requests_sent,
                      "request_budget": selected["max_requests"],
                      "budget_exhausted": budget_exhausted,
                      "response_headers_recorded": False, "response_bodies_recorded": False},
    }


def execute_api_discovery_step(manifest, step_id, confirm_target, request_reserver):
    """Run anonymous, same-origin API discovery under the shared campaign request cap."""
    plan = validate_manifest(manifest)
    selected = next((step for step in plan["steps"] if step["id"] == step_id), None)
    if selected is None or selected["tool"] != "api_discovery":
        raise CampaignError("selected step does not exist or is not an api_discovery step")
    if canonical_origin(confirm_target) != selected["origin"]:
        raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
    target = next(item for item in plan["targets"] if item["id"] == selected["target"])
    role = next(item for item in target["roles"] if item["name"] == selected["role"])
    if role["name"] != "anonymous" or role.get("credential_env"):
        raise CampaignError("native api_discovery currently supports only an anonymous role")

    script_dir = Path(__file__).resolve().parents[1] / "skills" / "api-breaker" / "scripts"
    script_path = script_dir / "api_discovery.py"
    spec = importlib.util.spec_from_file_location("catus_campaign_api_discovery", script_path)
    if spec is None or spec.loader is None:
        raise CampaignError("cannot load the registered API discovery adapter")
    module = importlib.util.module_from_spec(spec)
    previous_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(script_dir))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
        sys.modules.pop("_common", None)
        if previous_common is not None:
            sys.modules["_common"] = previous_common

    requests_sent = 0
    budget_exhausted = False
    scope_violation_blocked = False
    throttled = False
    last_request_at = 0.0
    reserve_lock = threading.Lock()
    opener = urllib.request.build_opener(_NoRedirect())

    def bounded_request(url, method="GET", headers=None, data=None, timeout=8):
        nonlocal requests_sent, budget_exhausted, scope_violation_blocked, throttled, last_request_at
        if throttled:
            return 429, {"Retry-After": "campaign adapter stopped after throttling"}, ""
        try:
            if target_origin(url) != selected["origin"]:
                scope_violation_blocked = True
                return 0, {}, ""
        except CampaignError:
            scope_violation_blocked = True
            return 0, {}, ""
        with reserve_lock:
            try:
                request_reserver(step_id, selected["max_requests"])
            except CampaignError:
                budget_exhausted = True
                return 0, {}, ""
            delay = 0.1 - (time.monotonic() - last_request_at)
            if delay > 0:
                time.sleep(delay)
            requests_sent += 1
            last_request_at = time.monotonic()
        if isinstance(data, str):
            data = data.encode("utf-8")
        response = _bounded_http_request(opener, url, method=method, data=data, headers=headers)
        response_status, response_headers, _body = response
        if response_status == 429 or any(str(name).lower() == "retry-after" for name in response_headers):
            throttled = True
        return response

    original_legacy = module.discover_legacy_versions

    def in_scope_legacy_discovery(discovered, base_url, extra_headers=None, burst_count=30,
                                  enable_wayback=True, domain=None):
        return original_legacy(discovered, base_url, extra_headers, burst_count,
                               enable_wayback=False, domain=None)

    module.http_request = bounded_request
    module.discover_legacy_versions = in_scope_legacy_discovery
    # The stock adapter probes PUT/DELETE/PATCH on discovered paths. The
    # campaign adapter deliberately omits method discovery to avoid writes.
    module.test_http_methods = lambda *_args, **_kwargs: []

    with tempfile.TemporaryDirectory(prefix="campaign-api-") as directory:
        output_path = Path(directory) / "api-discovery.json"
        old_argv = sys.argv
        try:
            sys.argv = ["api_discovery", "--domain", target["url"], "--threads", "1",
                        "--output", str(output_path)]
            with contextlib.redirect_stdout(io.StringIO()):
                module.main()
        finally:
            sys.argv = old_argv
        try:
            raw = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CampaignError("API discovery adapter did not produce valid output") from exc

    discovered = raw.get("discovered_apis", [])
    safe_endpoints = []
    if isinstance(discovered, list):
        for item in discovered[:1000]:
            if not isinstance(item, dict):
                continue
            path = urlsplit(str(item.get("url", ""))).path
            safe_endpoints.append({"path": path[:500], "status": item.get("status"),
                                   "api_type": item.get("api_type", "unknown"),
                                   "auth_required": item.get("auth_required") is True})
    raw_stats = raw.get("stats", {})
    allowed_stats = {"paths_tested", "js_scripts_analyzed", "js_endpoints_probed", "apis_found",
                     "graphql_endpoints", "openapi_docs", "documented_endpoints", "legacy_version_findings"}
    safe_stats = {key: value for key, value in raw_stats.items()
                  if key in allowed_stats and isinstance(value, int) and not isinstance(value, bool)} \
        if isinstance(raw_stats, dict) else {}
    return {
        "tool": "api_discovery",
        "stats": safe_stats,
        "discovered_apis": safe_endpoints,
        "finding_types": sorted({str(item.get("type")) for item in raw.get("findings", [])
                                  if isinstance(item, dict) and isinstance(item.get("type"), str)}),
        "execution": {"step_id": step_id, "requests_sent": requests_sent,
                      "request_budget": selected["max_requests"],
                      "budget_exhausted": budget_exhausted,
                      "throttled": throttled,
                      "off_origin_requests_blocked": scope_violation_blocked,
                      "response_bodies_recorded": False, "credentials_recorded": False,
                      "state_changing_method_probes_enabled": False},
    }


def execute_registered_cli_step(manifest, step_id, confirm_target, state_database,
                                campaign_id, tool_args):
    """Run a fixed registered scanner entrypoint with the SQLite request gate active."""
    plan = validate_manifest(manifest)
    selected = next((step for step in plan["steps"] if step["id"] == step_id), None)
    if selected is None or selected["tool"] not in TOOL_ENTRYPOINTS:
        raise CampaignError("selected step has no campaign-gated CLI entrypoint")
    if canonical_origin(confirm_target) != selected["origin"]:
        raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
    skill_name, entrypoint = TOOL_ENTRYPOINTS[selected["tool"]]
    if skill_name != selected["skill"]:
        raise CampaignError("registered CLI does not match the selected tool's skill")
    script_dir = Path(__file__).resolve().parents[1] / "skills" / skill_name / "scripts"
    script_path = (script_dir / entrypoint).resolve()
    if script_path.parent != script_dir.resolve() or not script_path.is_file():
        raise CampaignError("registered CLI entrypoint is missing or outside its skill")
    if any(not isinstance(arg, str) or "\x00" in arg for arg in tool_args):
        raise CampaignError("tool arguments must be strings without NUL bytes")

    status = {"budget_exhausted": False, "off_origin_requests_blocked": False,
              "gate_errors": False}
    return_code = None
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="campaign-cli-") as directory:
        status_path = Path(directory) / "gate-status.json"
        status_path.write_text(json.dumps(status), encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "CATUS_CAMPAIGN_GATE_DB": str(Path(state_database).expanduser().resolve()),
            "CATUS_CAMPAIGN_GATE_CAMPAIGN": campaign_id,
            "CATUS_CAMPAIGN_GATE_STEP": step_id,
            "CATUS_CAMPAIGN_GATE_ORIGIN": selected["origin"],
            "CATUS_CAMPAIGN_GATE_STATUS": str(status_path),
        })
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent) + (
            os.pathsep + existing_pythonpath if existing_pythonpath else "")
        if selected["tool"] == "cloud_detector" and "--campaign-http-only" not in tool_args:
            tool_args.append("--campaign-http-only")
        if selected["tool"] == "api_authz" and "--campaign-gate-required" not in tool_args:
            tool_args.append("--campaign-gate-required")
        try:
            completed = subprocess.run(
                [sys.executable, str(script_path), *tool_args], cwd=str(script_dir),
                env=env, check=False, timeout=CLI_TIMEOUT_SECONDS,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        try:
            recorded_status = json.loads(status_path.read_text(encoding="utf-8"))
            if isinstance(recorded_status, dict):
                status.update({key: recorded_status.get(key) is True for key in status})
        except (OSError, json.JSONDecodeError):
            status["gate_errors"] = True

    return {"tool": selected["tool"], "entrypoint": entrypoint,
            "execution": {"step_id": step_id, "requests_sent": None,
                          "request_budget": selected["max_requests"],
                          "budget_enforced_by_shared_transport": True,
                          "return_code": return_code, "timed_out": timed_out,
                          **status,
                          "arguments_recorded": False,
                          "response_bodies_recorded": False}}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep a confirmed target origin from redirecting active scenario traffic."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _bounded_http_request(opener, url, method="GET", data=None, headers=None):
    """One no-redirect HTTPS-verified request with bounded response capture."""
    try:
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
            return response.status, dict(response.headers.items()), body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
        except OSError:
            body = b""
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, body.decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, {}, ""


def _read_json(path):
    try:
        encoded = Path(path).read_bytes()
        if len(encoded) > MAX_JSON_BYTES:
            raise CampaignError("JSON input exceeds 10 MiB")
        return json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CampaignError("cannot read JSON file: {}".format(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="validate a manifest and write its bounded plan")
    plan.add_argument("--manifest", required=True)
    plan.add_argument("--output", required=True)
    plan.add_argument("--knowledge-db", help="Optional engagement-scoped SQLite knowledge file")
    plan.add_argument("--engagement", help="Required with --knowledge-db")
    coverage = subparsers.add_parser("coverage", help="evaluate recorded outcomes against test cases")
    coverage.add_argument("--manifest", required=True, help="versioned coverage-case JSON")
    coverage.add_argument("--results", required=True, help="JSON list of case_id/status results")
    coverage.add_argument("--output", required=True)
    authorization = subparsers.add_parser("authorization", help="evaluate role/object results from a campaign plan")
    authorization.add_argument("--plan", required=True)
    authorization.add_argument("--results", required=True, help="JSON list of role/object observations")
    authorization.add_argument("--output", required=True)
    workflow = subparsers.add_parser("run-workflow", aliases=["run-step"],
                                    help="execute one registered campaign adapter")
    workflow.add_argument("--manifest", required=True)
    workflow.add_argument("--step", required=True)
    workflow.add_argument("--confirm-target", required=True,
                          help="Exact origin confirmation; must match the selected step")
    workflow.add_argument("--output", required=True)
    workflow.add_argument("--state-db", help="Optional SQLite ledger for aggregate budget and resume safety")
    workflow.add_argument("--campaign-id", help="Stable campaign identifier; required with --state-db")
    workflow.add_argument("--retry-interrupted", action="store_true",
                          help="Explicitly permit retry after reviewing an interrupted/failed step")
    cli = subparsers.add_parser("run-cli", help="run a registered scanner with shared request-budget enforcement")
    cli.add_argument("--manifest", required=True)
    cli.add_argument("--step", required=True)
    cli.add_argument("--confirm-target", required=True,
                     help="Exact origin confirmation; must match the selected step")
    cli.add_argument("--state-db", required=True)
    cli.add_argument("--campaign-id", required=True)
    cli.add_argument("--retry-interrupted", action="store_true",
                     help="Explicitly permit retry after reviewing an interrupted/failed step")
    cli.add_argument("tool_args", nargs=argparse.REMAINDER,
                     help="Arguments for the fixed scanner entrypoint; separate them with --")
    external = subparsers.add_parser(
        "run-external", help="run a supported network executable through its campaign adapter")
    external.add_argument("--manifest", required=True)
    external.add_argument("--step", required=True)
    external.add_argument("--confirm-target", required=True)
    external.add_argument("--state-db", required=True)
    external.add_argument("--campaign-id", required=True)
    external.add_argument("--retry-interrupted", action="store_true")
    external.add_argument("tool_args", nargs=argparse.REMAINDER,
                          help="One supported executable and its arguments; separate them with --")
    status = subparsers.add_parser("campaign-status", help="show campaign counters and step states")
    status.add_argument("--state-db", required=True)
    status.add_argument("--campaign-id", required=True)
    status.add_argument("--output", help="Optional JSON output path")
    record = subparsers.add_parser("campaign-record-step",
                                   help="attest completion of an adapterless campaign step")
    record.add_argument("--manifest", required=True)
    record.add_argument("--state-db", required=True)
    record.add_argument("--campaign-id", required=True)
    record.add_argument("--step", required=True)
    record.add_argument("--operator-note", required=True,
                        help="Short note identifying the external result reviewed; note text is hashed")
    record.add_argument("--output", help="Optional JSON output path")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            if bool(args.knowledge_db) != bool(args.engagement):
                raise CampaignError("--knowledge-db and --engagement must be supplied together")
            result = validate_manifest(_read_json(args.manifest))
            if args.knowledge_db:
                result = enrich_plan_with_knowledge(result, args.knowledge_db, args.engagement)
        elif args.command == "run-external":
            manifest = _read_json(args.manifest)
            plan = validate_manifest(manifest)
            selected = next((step for step in plan["steps"] if step["id"] == args.step), None)
            if selected is None or selected["tool"] != "external_probe":
                raise CampaignError("selected step is not registered for network executable probes")
            if canonical_origin(args.confirm_target) != selected["origin"]:
                raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
            command = list(args.tool_args)
            if command and command[0] == "--":
                command = command[1:]
            if not command or os.path.basename(command[0]).lower().removesuffix(".exe") not in (
                    "curl", "dig", "nmap"):
                raise CampaignError("run-external supports only curl, dig, and nmap adapters")
            ledger = CampaignLedger(args.state_db, args.campaign_id)
            step_started = False
            try:
                ledger.bind(manifest)
                ledger.start_step(args.step, args.retry_interrupted)
                step_started = True
                previous_used = next(item["requests_used"] for item in ledger.summary()["steps"]
                                     if item["step_id"] == args.step)
                status = {"budget_exhausted": False, "off_origin_requests_blocked": False,
                          "gate_errors": False}
                with tempfile.TemporaryDirectory(prefix="campaign-external-") as directory:
                    status_path = Path(directory) / "gate-status.json"
                    status_path.write_text(json.dumps(status), encoding="utf-8")
                    env = os.environ.copy()
                    env.update({
                        "CATUS_CAMPAIGN_GATE_DB": str(Path(args.state_db).expanduser().resolve()),
                        "CATUS_CAMPAIGN_GATE_CAMPAIGN": args.campaign_id,
                        "CATUS_CAMPAIGN_GATE_STEP": args.step,
                        "CATUS_CAMPAIGN_GATE_ORIGIN": selected["origin"],
                        "CATUS_CAMPAIGN_GATE_STATUS": str(status_path),
                    })
                    existing_pythonpath = env.get("PYTHONPATH", "")
                    env["PYTHONPATH"] = str(Path(__file__).resolve().parent) + (
                        os.pathsep + existing_pythonpath if existing_pythonpath else "")
                    gate_path = Path(__file__).resolve().parent / "campaign_request_gate.py"
                    gate_spec = importlib.util.spec_from_file_location(
                        "catus_campaign_external_gate", gate_path)
                    gate_module = importlib.util.module_from_spec(gate_spec)
                    gate_spec.loader.exec_module(gate_module)
                    gate_names = tuple(key for key in env if key.startswith("CATUS_CAMPAIGN_GATE_"))
                    old_gate_env = {key: os.environ.get(key) for key in gate_names}
                    try:
                        for key in gate_names:
                            os.environ[key] = env[key]
                        safe_command = gate_module.reserve_external_command_from_environment(command)
                    finally:
                        for key, value in old_gate_env.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
                    timed_out = False
                    return_code = None
                    try:
                        completed = subprocess.run(
                            safe_command, env=env, check=False, timeout=CLI_TIMEOUT_SECONDS)
                        return_code = completed.returncode
                    except subprocess.TimeoutExpired:
                        timed_out = True
                    try:
                        recorded = json.loads(status_path.read_text(encoding="utf-8"))
                        if isinstance(recorded, dict):
                            status.update({key: recorded.get(key) is True for key in status})
                    except (OSError, json.JSONDecodeError):
                        status["gate_errors"] = True
                updated = ledger.summary()
                requests_used = next(item["requests_used"] for item in updated["steps"]
                                     if item["step_id"] == args.step)
                execution = {"step_id": args.step, "requests_sent": requests_used - previous_used,
                             "request_budget": selected["max_requests"],
                             "return_code": return_code, "timed_out": timed_out,
                             "arguments_recorded": False, **status}
                run_status = ("failed" if return_code != 0 or timed_out or any(status.values())
                              else "completed")
                ledger.finish_step(args.step, run_status)
                execution["campaign_budget"] = ledger.summary()
                result = {"tool": "external_probe", "executable": os.path.basename(command[0]),
                          "execution": execution}
            except Exception:
                if step_started:
                    ledger.finish_step(args.step, "failed")
                raise
            finally:
                ledger.close()
        elif args.command == "run-cli":
            manifest = _read_json(args.manifest)
            plan = validate_manifest(manifest)
            selected = next((step for step in plan["steps"] if step["id"] == args.step), None)
            if selected is None or selected["tool"] not in TOOL_ENTRYPOINTS:
                raise CampaignError("selected step has no registered campaign-gated CLI entrypoint")
            if canonical_origin(args.confirm_target) != selected["origin"]:
                raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
            if selected["depends_on"] and not args.state_db:
                raise CampaignError("steps with dependencies require the campaign ledger")
            tool_args = list(args.tool_args)
            if tool_args and tool_args[0] == "--":
                tool_args = tool_args[1:]
            if selected["tool"] == "api_authz" and "--allow-mutation-write" in tool_args:
                raise CampaignError("campaign run-cli does not enable mutation probes; use a reviewed workflow")
            if selected["tool"] == "web_cache" and "--confirm-cache-replay" in tool_args:
                raise CampaignError("campaign run-cli does not enable cache replay confirmation")
            ledger = CampaignLedger(args.state_db, args.campaign_id)
            step_started = False
            try:
                ledger.bind(manifest)
                ledger.start_step(args.step, args.retry_interrupted)
                step_started = True
                previous_used = next(item["requests_used"] for item in ledger.summary()["steps"]
                                     if item["step_id"] == args.step)
                result = execute_registered_cli_step(
                    manifest, args.step, args.confirm_target, args.state_db,
                    args.campaign_id, tool_args)
                updated = ledger.summary()
                requests_used = next(item["requests_used"] for item in updated["steps"]
                                     if item["step_id"] == args.step)
                result["execution"]["requests_sent"] = requests_used - previous_used
                execution = result["execution"]
                run_status = ("failed" if execution.get("return_code") != 0
                              or execution.get("timed_out")
                              or execution.get("budget_exhausted")
                              or execution.get("off_origin_requests_blocked")
                              or execution.get("gate_errors") else "completed")
                ledger.finish_step(args.step, run_status)
                result["execution"]["campaign_budget"] = ledger.summary()
            except Exception:
                if step_started:
                    ledger.finish_step(args.step, "failed")
                raise
            finally:
                ledger.close()
        elif args.command in ("run-workflow", "run-step"):
            if bool(args.state_db) != bool(args.campaign_id):
                raise CampaignError("--state-db and --campaign-id must be supplied together")
            if args.retry_interrupted and not args.state_db:
                raise CampaignError("--retry-interrupted requires the campaign ledger")
            manifest = _read_json(args.manifest)
            opener = urllib.request.build_opener(_NoRedirect())
            ledger = None
            plan = validate_manifest(manifest)
            selected = next((step for step in plan["steps"] if step["id"] == args.step), None)
            if selected is None or selected["tool"] not in (
                    "business_workflow", "tech_fingerprint", "api_discovery"):
                raise CampaignError("selected step does not exist or has no native campaign adapter")
            if selected["tool"] in ("tech_fingerprint", "api_discovery") and not args.state_db:
                raise CampaignError("active scanner steps require --state-db and --campaign-id")
            if canonical_origin(args.confirm_target) != selected["origin"]:
                raise CampaignError("--confirm-target must exactly match the selected step's in-scope origin")
            if selected["depends_on"] and not args.state_db:
                raise CampaignError("steps with dependencies require --state-db and --campaign-id")
            if args.state_db:
                ledger = CampaignLedger(args.state_db, args.campaign_id)
                ledger.bind(manifest)
                ledger.start_step(args.step, args.retry_interrupted)
            try:
                if selected["tool"] == "tech_fingerprint":
                    result = execute_fingerprint_step(
                        manifest, args.step, args.confirm_target, ledger.reserve_request)
                elif selected["tool"] == "api_discovery":
                    result = execute_api_discovery_step(
                        manifest, args.step, args.confirm_target, ledger.reserve_request)
                else:
                    result = execute_workflow_step(
                        manifest, args.manifest, args.step, args.confirm_target,
                        lambda url, method="GET", data=None, headers=None: _bounded_http_request(
                            opener, url, method=method, data=data, headers=headers),
                        budget_reserver=ledger.reserve_request if ledger else None)
                if ledger:
                    execution = result["execution"]
                    run_status = ("failed" if execution.get("budget_exhausted")
                                  or execution.get("throttled")
                                  or execution.get("off_origin_requests_blocked") else "completed")
                    ledger.finish_step(args.step, run_status)
                    result["execution"]["campaign_budget"] = ledger.summary()
            except Exception:
                if ledger:
                    ledger.finish_step(args.step, "failed")
                raise
            finally:
                if ledger:
                    ledger.close()
        elif args.command == "campaign-status":
            ledger = CampaignLedger(args.state_db, args.campaign_id)
            try:
                result = ledger.summary()
            finally:
                ledger.close()
        elif args.command == "campaign-record-step":
            manifest = _read_json(args.manifest)
            plan = validate_manifest(manifest)
            selected = next((step for step in plan["steps"] if step["id"] == args.step), None)
            if selected is None:
                raise CampaignError("selected step does not exist")
            if selected["tool"] == "business_workflow":
                raise CampaignError("business_workflow steps must complete through run-workflow")
            ledger = CampaignLedger(args.state_db, args.campaign_id)
            try:
                ledger.bind(manifest)
                ledger.attest_external_step(args.step, args.operator_note)
                result = ledger.summary()
            finally:
                ledger.close()
        else:
            if args.command == "coverage":
                case_doc = _read_json(args.manifest)
                cases = load_coverage_manifest(case_doc)
            else:
                case_doc = _read_json(args.plan)
                cases = case_doc.get("authorization_matrix") if isinstance(case_doc, dict) else None
                if not isinstance(cases, list):
                    raise CampaignError("plan must contain an authorization_matrix list")
            results = _read_json(args.results)
            if not isinstance(results, list):
                raise CampaignError("results must be a JSON list")
            if args.command == "coverage":
                result = evaluate_coverage(cases, results)
            else:
                module_path = Path(__file__).resolve().parent / "role_matrix.py"
                spec = importlib.util.spec_from_file_location("catus_role_matrix", module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                result = module.evaluate_matrix(cases, results)
        output_path = getattr(args, "output", None)
        if output_path:
            Path(output_path).write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
            print(json.dumps({"status": "ok", "output": str(Path(output_path).resolve())}))
        else:
            print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    sys.exit(main())
