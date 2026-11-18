#!/usr/bin/env python3
"""Validate and plan a bounded, evidence-led assessment campaign.

This v1 planner is deliberately offline: it never launches tools or sends
requests. It turns an operator-authored manifest into an ordered plan and
coverage ledger input while enforcing exact-origin scope, role labels,
dependency order, request budgets, and explicit state-change declarations.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
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
    "business_workflow": {"skill": "webapp-exploit-hunter", "stateful": True},
    "chain_analysis": {"skill": "vuln-chain-composer", "stateful": False},
    "report": {"skill": "vuln-chain-composer", "stateful": False},
}


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
                      "declared_request_budget": budget_used, "allow_state_changes": allow_mutations},
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
    return {"counts": counts, "cases": rows,
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


def execute_workflow_step(manifest, manifest_path, step_id, confirm_target, request_func,
                          credential_environment=None):
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
    workflow = subparsers.add_parser("run-workflow", help="execute one explicitly gated business scenario")
    workflow.add_argument("--manifest", required=True)
    workflow.add_argument("--step", required=True)
    workflow.add_argument("--confirm-target", required=True,
                          help="Exact origin confirmation; must match the selected step")
    workflow.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            if bool(args.knowledge_db) != bool(args.engagement):
                raise CampaignError("--knowledge-db and --engagement must be supplied together")
            result = validate_manifest(_read_json(args.manifest))
            if args.knowledge_db:
                result = enrich_plan_with_knowledge(result, args.knowledge_db, args.engagement)
        elif args.command == "run-workflow":
            manifest = _read_json(args.manifest)
            opener = urllib.request.build_opener(_NoRedirect())
            result = execute_workflow_step(
                manifest, args.manifest, args.step, args.confirm_target,
                lambda url, method="GET", data=None, headers=None: _bounded_http_request(
                    opener, url, method=method, data=data, headers=headers))
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
        Path(args.output).write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        print(json.dumps({"status": "ok", "output": str(Path(args.output).resolve())}))
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    sys.exit(main())
