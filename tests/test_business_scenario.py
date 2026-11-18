"""Offline regression matrix for guided business-flow scenarios."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "skills/webapp-exploit-hunter/scripts/business_scenario.py"
SPEC = importlib.util.spec_from_file_location("business_scenario", PATH)
business_scenario = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(business_scenario)


def sample(base_path="/checkout"):
    return {
        "version": 1,
        "name": "coupon-limit",
        "setup": [{"method": "POST", "path": "/reset"}],
        "fixture_note": "Local disposable cart fixture",
        "cleanup": [{"method": "POST", "path": "/reset"}],
        "baseline": {
            "actions": [{"method": "POST", "path": base_path, "body": {"coupon": "SAVE"}}],
            "assertions": [{"pointer": "/coupon_count", "equals": 1}],
        },
        "cases": [{
            "name": "repeat-coupon",
            "actions": [{"method": "POST", "path": base_path, "body": {"coupon": "SAVE"}},
                        {"method": "POST", "path": base_path, "body": {"coupon": "SAVE"}},
                        {"method": "GET", "path": "/cart"}],
            "assertions": [{"pointer": "/coupon_count", "equals": 1}],
        }],
    }


def test_plan_only_reports_budget_without_request_function():
    plan = business_scenario.plan_scenario(sample(), "http://127.0.0.1:8000", 10)
    assert plan["mode"] == "dry_run"
    assert plan["request_count"] == 8
    assert plan["mutating"] is True


@pytest.mark.parametrize("path", ["https://attacker.example/x", "//attacker.example/x", "\\\\attacker.example\\x"])
def test_rejects_cross_origin_actions(path):
    with pytest.raises(business_scenario.ScenarioError, match="same origin|invalid path"):
        business_scenario.validate_scenario(sample(path), "https://example.test", 20)


def test_rejects_missing_cleanup_and_fixture_note_for_writes():
    scenario = sample()
    scenario.pop("cleanup")
    with pytest.raises(business_scenario.ScenarioError, match="cleanup"):
        business_scenario.validate_scenario(scenario, "http://localhost")


def test_request_budget_preflight():
    with pytest.raises(business_scenario.ScenarioError, match="request cap"):
        business_scenario.validate_scenario(sample(), "http://localhost", 6)


def test_baseline_failure_skips_cases_and_cleanup_runs():
    calls = []

    def request(url, method, data, headers):
        calls.append((url, method))
        return 200, {}, json.dumps({"coupon_count": 0})

    result = business_scenario.execute_scenario(sample(), "http://localhost", request)
    assert calls == [("http://localhost/reset", "POST"),
                     ("http://localhost/checkout", "POST"),
                     ("http://localhost/reset", "POST")]
    assert result["results"][1]["skipped"] == "baseline assertions did not pass"
    assert result["validated"] is False


def test_declared_impact_oracle_auto_confirms_only_after_baseline_and_readback():
    scenario = sample()
    scenario["cases"][0]["impact_assertions"] = [
        {"pointer": "/coupon_count", "equals": 2, "safe_value": 1}]

    def vulnerable_request(url, method, data, headers):
        if url.endswith("/cart"):
            return 200, {}, json.dumps({"coupon_count": 2})
        if url.endswith("/checkout"):
            return 200, {}, json.dumps({"coupon_count": 1})
        return 200, {}, "{}"

    result = business_scenario.execute_scenario(scenario, "http://localhost", vulnerable_request)
    case = result["results"][1]
    assert result["validated"] is True
    assert result["confirmed_cases"] == ["repeat-coupon"]
    assert case["validation_method"] == "declared_impact_assertions_after_valid_baseline"
    assert case["proof"]["baseline_passed"] is True
    assert case["proof"]["assertion_values_emitted"] is False


def test_declared_impact_oracle_does_not_confirm_when_readback_is_safe():
    scenario = sample()
    scenario["cases"][0]["impact_assertions"] = [
        {"pointer": "/coupon_count", "equals": 2, "safe_value": 1}]

    def safe_request(url, method, data, headers):
        if url.endswith("/cart"):
            return 200, {}, json.dumps({"coupon_count": 1})
        if url.endswith("/checkout"):
            return 200, {}, json.dumps({"coupon_count": 1})
        return 200, {}, "{}"

    result = business_scenario.execute_scenario(scenario, "http://localhost", safe_request)
    assert result["validated"] is False
    assert result["confirmed_cases"] == []


def test_throttle_stops_followup_requests():
    calls = []

    def request(url, method, data, headers):
        calls.append(url)
        return 429, {}, "{}"

    result = business_scenario.execute_scenario(sample(), "http://localhost", request)
    assert result["throttled"] is True
    assert len(calls) == 1


def dynamic_scenario():
    lane = [
        {"method": "POST", "path": "/orders", "body": {"label": "fixture"},
         "capture": {"name": "order_id", "pointer": "/id"}},
        {"method": "POST", "path": "/confirm", "headers": {"X-Order": "${order_id}"},
         "body": {"id": "${order_id}"}},
        {"method": "GET", "path": "/orders/${order_id}"},
    ]
    return {
        "version": 1, "name": "dynamic-order", "fixture_note": "Disposable local order",
        "cleanup": [{"method": "DELETE", "path": "/orders/${order_id}"}],
        "baseline": {"actions": lane, "assertions": [{"pointer": "/state", "equals": "ready"}]},
        "cases": [{"name": "confirm-order", "actions": lane,
                   "assertions": [{"pointer": "/state", "equals": "ready"}]}],
    }


def test_captured_json_id_reused_in_path_header_body_and_cleanup_without_reporting_value():
    calls = []

    def request(url, method, data, headers):
        calls.append((url, method, data, headers))
        body = '{"id":"id/secret-42","state":"ready"}' if url.endswith("/orders") and method == "POST" else '{"state":"ready"}'
        return 200, {}, body

    output = business_scenario.execute_scenario(dynamic_scenario(), "http://localhost", request)
    serialized = json.dumps(output)
    assert output["results"][0]["assertions_passed"] is True
    assert output["results"][1]["assertions_passed"] is True
    assert ("http://localhost/orders/id%2Fsecret-42", "GET") in [(call[0], call[1]) for call in calls]
    confirm = next(call for call in calls if call[1] == "POST" and call[0].endswith("/confirm"))
    assert json.loads(confirm[2]) == {"id": "id/secret-42"}
    assert confirm[3]["X-Order"] == "id/secret-42"
    assert any(call[0] == "http://localhost/orders/id%2Fsecret-42" and call[1] == "DELETE" for call in calls)
    assert "id/secret-42" not in serialized
    assert output["results"][0]["captures"] == [{"name": "order_id", "available": True}]


def test_missing_capture_skips_dependent_steps_and_cases_and_does_not_leak_values():
    calls = []

    def request(url, method, data, headers):
        calls.append((url, method))
        return 200, {}, '{"state":"ready"}'

    output = business_scenario.execute_scenario(dynamic_scenario(), "http://localhost", request)
    assert calls == [("http://localhost/orders", "POST")]
    assert output["results"][0]["capture_error"] == "capture unavailable: order_id"
    assert output["results"][1]["skipped"] == "baseline assertions did not pass"


def test_unknown_capture_reference_fails_preflight():
    scenario = dynamic_scenario()
    scenario["baseline"]["actions"][0]["path"] = "/orders/${not_captured}"
    with pytest.raises(business_scenario.ScenarioError, match="uncaptured variable"):
        business_scenario.plan_scenario(scenario, "http://localhost")


def test_http_error_cannot_satisfy_baseline_assertion_or_capture_value():
    scenario = dynamic_scenario()

    def request(url, method, data, headers):
        return 500, {}, '{"id":"should-not-capture","state":"ready"}'

    output = business_scenario.execute_scenario(scenario, "http://localhost", request)
    assert output["results"][0]["assertions_passed"] is False
    assert output["results"][0]["captures"] == [{"name": "order_id", "available": False}]
    assert "should-not-capture" not in json.dumps(output)


@pytest.mark.parametrize("captured", ["line1\r\nInjected: yes", "x" * 2049, {"id": "object"}])
def test_rejects_unsafe_or_non_scalar_capture(captured):
    scenario = dynamic_scenario()

    def request(url, method, data, headers):
        return 200, {}, json.dumps({"id": captured, "state": "ready"})

    output = business_scenario.execute_scenario(scenario, "http://localhost", request)
    assert output["results"][0]["captures"] == [{"name": "order_id", "available": False}]


def test_loopback_stateful_execution_keeps_assertions_value_free():
    state = {"coupon_count": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/reset":
                state["coupon_count"] = 0
            elif self.path == "/checkout":
                state["coupon_count"] += 1
            self._reply()

        def do_GET(self):
            self._reply()

        def _reply(self):
            data = json.dumps(state).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        import urllib.request

        def request(url, method, data, headers):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req) as response:
                    return response.status, dict(response.headers), response.read().decode()
            except Exception as exc:  # pragma: no cover - asserted fixture should not fail
                pytest.fail(str(exc))

        output = business_scenario.execute_scenario(
            sample(), f"http://127.0.0.1:{server.server_port}", request
        )
        assert output["results"][0]["assertions_passed"] is True
        assert output["results"][1]["assertions_passed"] is False
        assert "actual" not in json.dumps(output)
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
