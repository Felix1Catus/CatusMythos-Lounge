"""Focused API Breaker scope and active-probe regressions."""

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "api-breaker" / "scripts"


def load_api_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPTS))
    return module


logic_tester = load_api_script("api_breaker_logic_regressions", "logic_tester.py")
rate_limiter = load_api_script("api_breaker_rate_regressions", "rate_limiter.py")
schema_builder = load_api_script("api_breaker_schema_regressions", "schema_builder.py")
api_discovery = load_api_script("api_breaker_discovery_regressions", "api_discovery.py")
api_report = load_api_script("api_breaker_report_regressions", "api_report.py")


class ApiBreakerScopeTests(unittest.TestCase):
    def test_javascript_discovery_fetches_only_same_origin_script_urls(self):
        html = (
            '<script src="/static/app.js"></script>'
            '<script src="assets/runtime.js"></script>'
            '<script src="//cdn.example.test/vendor.js"></script>'
        )
        self.assertEqual(
            api_discovery.extract_script_urls("https://api.example.test/base/", html),
            [
                "https://api.example.test/static/app.js",
                "https://api.example.test/base/assets/runtime.js",
            ],
        )

    def test_javascript_endpoint_extraction_scopes_script_fetch_and_absolute_urls(self):
        calls = []

        def record_request(url, headers=None, **kwargs):
            calls.append(url)
            return 200, {}, (
                "fetch('/api/items'); fetch('https://attacker.invalid/api/leak');"
            )

        with patch.object(api_discovery, "http_request", side_effect=record_request):
            paths = api_discovery.discover_from_js(
                "https://api.example.test",
                [
                    "https://api.example.test/app.js",
                    "https://attacker.invalid/steal.js",
                ],
            )

        self.assertEqual(calls, ["https://api.example.test/app.js"])
        self.assertEqual(paths, ["/api/items"])

    def test_discovery_main_integrates_same_origin_javascript_pass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "discovery.json"
            argv = [
                "api_discovery.py", "--domain", "api.example.test",
                "--output", str(output_path), "--threads", "2",
            ]
            http_calls = []
            probed_paths = []

            def record_http(url, **kwargs):
                http_calls.append(url)
                if url == "https://api.example.test":
                    return 200, {}, (
                        '<script src="/app.js"></script>'
                        '<script src="https://cdn.example.test/vendor.js"></script>'
                    )
                if url == "https://api.example.test/app.js":
                    return 200, {}, "fetch('/api/from-js')"
                return 404, {}, ""

            def record_probe(base_url, path, extra_headers=None):
                probed_paths.append(path)
                if path == "/api/from-js":
                    return {
                        "url": "https://api.example.test/api/from-js",
                        "path": path,
                        "status": 200,
                        "api_type": "rest_json",
                        "version_headers": {},
                    }
                return None

            with patch.object(sys, "argv", argv), patch.object(
                api_discovery, "http_request", side_effect=record_http
            ), patch.object(api_discovery, "probe_path", side_effect=record_probe), patch.object(
                api_discovery, "test_http_methods", return_value=[]
            ), patch.object(api_discovery, "discover_legacy_versions", return_value=[]):
                api_discovery.main()
            saved_text = output_path.read_text(encoding="utf-8")

        self.assertIn("/api/from-js", probed_paths)
        self.assertIn("https://api.example.test/app.js", http_calls)
        self.assertNotIn("https://cdn.example.test/vendor.js", http_calls)
        self.assertTrue(all("attacker.invalid" not in url for url in http_calls))
        saved = json.loads(saved_text)
        self.assertEqual(saved["stats"]["js_scripts_analyzed"], 1)
        self.assertEqual(saved["stats"]["js_endpoints_probed"], 1)

    def test_business_logic_endpoints_are_scoped_and_write_methods_are_preserved(self):
        scoped = logic_tester.scope_business_logic_endpoints(
            "https://api.example.test/v1",
            [
                {"url": "/v1/orders", "method": "post"},
                {"url": "https://attacker.invalid/collect", "method": "POST"},
                {"url": "/v1/products", "method": "GET"},
                None,
            ],
        )

        self.assertEqual(
            scoped,
            [{"url": "https://api.example.test/v1/orders", "method": "POST"}],
        )

    def test_business_logic_classifier_ignores_malformed_entries(self):
        classified = logic_tester.classify_endpoints(
            [None, 12, {"path": None}, {"path": "/api/orders"}]
        )
        self.assertEqual(classified["ecommerce"], [{"path": "/api/orders"}])
        self.assertEqual(sum(map(len, classified.values())), 1)

    def test_price_manipulation_requires_exact_echo_and_reports_candidate(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"price": 1}')):
            self.assertEqual(
                logic_tester.test_price_manipulation(
                    "https://api.example.test/orders", "POST", {}, delay=0
                ),
                [],
            )

        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"price": 0}')):
            findings = logic_tester.test_price_manipulation(
                "https://api.example.test/orders", "POST", {}, delay=0
            )
        self.assertEqual(findings[0]["type"], "price_manipulation_candidate")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertFalse(findings[0]["validated"])

    def test_quantity_success_without_injected_value_echo_is_not_a_finding(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"id": "123"}')):
            findings = logic_tester.test_quantity_overflow(
                "https://api.example.test/orders", "POST", {}, delay=0
            )
        self.assertEqual(findings, [])

    def test_coupon_acceptance_is_unverified_candidate_not_confirmed_vulnerability(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"message": "success"}')):
            findings = logic_tester.test_coupon_stacking(
                "https://api.example.test/orders", "POST", {}, delay=0
            )
        self.assertTrue(findings)
        self.assertTrue(all(f["type"] == "coupon_stacking_candidate" for f in findings))
        self.assertTrue(all(f["severity"] == "INFO" and not f["validated"] for f in findings))

    def test_negative_amount_success_is_unverified_candidate(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"transaction_id": "t-1"}')):
            findings = logic_tester.test_negative_amounts(
                "https://api.example.test/transfers", "POST", {}, delay=0
            )
        self.assertTrue(findings)
        self.assertTrue(all(f["type"] == "negative_amount_candidate" for f in findings))
        self.assertTrue(all(f["severity"] == "INFO" and not f["validated"] for f in findings))

    def test_race_2xx_count_is_candidate_without_state_baseline(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{}')):
            findings = logic_tester.test_race_condition(
                "https://api.example.test/redeem", "POST", {}, delay=0
            )
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f["type"] == "race_condition_candidate" for f in findings))
        self.assertTrue(all(f["severity"] == "INFO" and not f["validated"] for f in findings))

    def test_privilege_field_echo_must_match_the_injected_value(self):
        with patch.object(logic_tester, "http_request", return_value=(200, {}, '{"role": "user"}')):
            findings = logic_tester.test_privilege_escalation(
                "https://api.example.test/profile", "PUT", {}, delay=0
            )
        self.assertEqual(findings, [])

    def test_business_logic_candidate_report_keeps_mapping_without_claiming_impact(self):
        report = api_report.generate_finding_report(
            {
                "type": "price_manipulation_candidate",
                "severity": "INFO",
                "validated": False,
                "evidence": "Injected value was echoed; persisted impact is unverified.",
                "url": "https://api.example.test/orders",
            },
            1,
        )
        self.assertEqual(report["owasp_mapping"]["id"], "API6:2023")
        self.assertIn("Unverified probe candidate", report["impact"])
        self.assertIn("No persisted state change", report["impact"])

    def test_graphql_csrf_probe_requires_cookie_and_explicit_test_object(self):
        with patch.object(schema_builder, "http_request") as request:
            self.assertEqual(
                schema_builder.test_graphql_csrf(
                    "https://api.example.test/graphql", "deleteUser", {"id": "1"}, None
                ),
                [],
            )
            self.assertEqual(
                schema_builder.test_graphql_csrf(
                    "https://api.example.test/graphql", "deleteUser", {}, "session=abc"
                ),
                [],
            )
        request.assert_not_called()

    def test_graphql_csrf_still_submits_get_and_form_with_explicit_canary(self):
        calls = []

        def record_request(url, method="GET", headers=None, data=None, **kwargs):
            calls.append((url, method, headers or {}, data))
            return 200, {}, '{"data":{"updateUser":{"__typename":"User"}}}'

        with patch.object(schema_builder, "http_request", side_effect=record_request):
            findings = schema_builder.test_graphql_csrf(
                "https://api.example.test/graphql",
                "updateUser",
                {"id": "canary-7"},
                "session=authorized-test-session",
            )

        self.assertEqual([call[1] for call in calls], ["GET", "POST"])
        self.assertTrue(all(call[2].get("Cookie") == "session=authorized-test-session" for call in calls))
        self.assertTrue(all('canary-7' in str(call) for call in calls))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["type"] == "graphql_csrf_candidate" for f in findings))
        self.assertTrue(all(f["severity"] == "INFO" and not f["validated"] for f in findings))

    def test_schema_main_skips_graphql_csrf_without_explicit_test_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "schema.json"
            argv = [
                "schema_builder.py", "--api-base", "https://api.example.test",
                "--mutation-field", "updateUser", "--skip-graphql-depth-test",
                "--output", str(output_path),
            ]
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                stack.enter_context(patch.object(schema_builder, "discover_resources", return_value=[]))
                stack.enter_context(patch.object(schema_builder, "http_request", return_value=(200, {}, "{}")))
                stack.enter_context(patch.object(
                    schema_builder,
                    "build_graphql_schema",
                    return_value=({"endpoint_url": "https://api.example.test/graphql"}, []),
                ))
                stack.enter_context(patch.object(schema_builder, "fingerprint_graphql_engine", return_value="unknown"))
                stack.enter_context(patch.object(schema_builder, "test_graphql_nested_field_authz", return_value=[]))
                csrf_probe = stack.enter_context(patch.object(schema_builder, "test_graphql_csrf", return_value=[]))
                schema_builder.main()

        csrf_probe.assert_not_called()

    def test_schema_main_runs_graphql_csrf_with_cookie_and_explicit_test_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "schema.json"
            argv = [
                "schema_builder.py", "--api-base", "https://api.example.test",
                "--mutation-field", "updateUser", "--skip-graphql-depth-test",
                "--cookie", "session=test-cookie", "--csrf-test-id", "canary-7",
                "--output", str(output_path),
            ]
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                stack.enter_context(patch.object(schema_builder, "discover_resources", return_value=[]))
                stack.enter_context(patch.object(schema_builder, "http_request", return_value=(200, {}, "{}")))
                stack.enter_context(patch.object(
                    schema_builder,
                    "build_graphql_schema",
                    return_value=({"endpoint_url": "https://api.example.test/graphql"}, []),
                ))
                stack.enter_context(patch.object(schema_builder, "fingerprint_graphql_engine", return_value="unknown"))
                stack.enter_context(patch.object(schema_builder, "test_graphql_nested_field_authz", return_value=[]))
                csrf_probe = stack.enter_context(patch.object(schema_builder, "test_graphql_csrf", return_value=[]))
                schema_builder.main()

        csrf_probe.assert_called_once_with(
            "https://api.example.test/graphql", "updateUser", {"id": "canary-7"},
            "session=test-cookie", 0,
        )

    def test_logic_cli_rejects_untrusted_input_metadata_as_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            input_path.write_text(
                json.dumps({
                    "meta": {"base_url": "https://attacker.invalid"},
                    "endpoints": [{"url": "https://attacker.invalid/orders"}],
                }),
                encoding="utf-8",
            )
            argv = ["logic_tester.py", "--input", str(input_path), "--token", "secret"]
            with patch.object(sys, "argv", argv), patch.object(logic_tester, "http_request") as request:
                with self.assertRaises(SystemExit) as error:
                    logic_tester.main()

        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()

    def test_logic_cli_rejects_endpoint_outside_trusted_origin_before_requests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            output_path = Path(temp_dir) / "findings.json"
            input_path.write_text(
                json.dumps({"endpoints": [{"url": "/api/orders", "path": "/api/orders"}]}),
                encoding="utf-8",
            )
            argv = [
                "logic_tester.py",
                "--input", str(input_path),
                "--api-base", "https://api.example.test",
                "--endpoint", "https://attacker.invalid/orders",
                "--output", str(output_path),
            ]
            with patch.object(sys, "argv", argv), patch.object(logic_tester, "http_request") as request:
                with self.assertRaises(SystemExit) as error:
                    logic_tester.main()

        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()

    def test_logic_specific_endpoint_still_runs_active_probes_once_without_new_flag(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "findings.json"
            argv = [
                "logic_tester.py",
                "--api-base", "https://api.example.test",
                "--endpoint", "/api/orders",
                "--output", str(output_path),
            ]
            names = (
                "test_price_manipulation",
                "test_quantity_overflow",
                "test_coupon_stacking",
                "test_negative_amounts",
                "test_race_condition",
                "test_privilege_escalation",
            )
            calls = []
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                for name in names:
                    stack.enter_context(
                        patch.object(
                            logic_tester,
                            name,
                            side_effect=lambda *a, _name=name, **k: calls.append(_name) or [],
                        )
                    )
                logic_tester.main()

        self.assertCountEqual(calls, names)
        self.assertEqual(len(calls), len(set(calls)))

    def test_logic_cli_uses_only_explicit_origin_for_imported_endpoints(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            output_path = Path(temp_dir) / "findings.json"
            input_path.write_text(
                json.dumps({
                    "meta": {"base_url": "https://attacker.invalid"},
                    "discovered_apis": [
                        {"url": "https://attacker.invalid/api/orders", "path": "/api/orders"},
                        {"url": "/api/orders", "path": "/api/orders"},
                    ],
                }),
                encoding="utf-8",
            )
            argv = [
                "logic_tester.py", "--input", str(input_path),
                "--api-base", "https://api.example.test", "--token", "secret",
                "--output", str(output_path),
            ]
            calls = []
            probe_names = (
                "test_price_manipulation", "test_quantity_overflow",
                "test_coupon_stacking", "test_race_condition",
            )
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                for name in probe_names:
                    stack.enter_context(
                        patch.object(
                            logic_tester,
                            name,
                            side_effect=lambda url, *a, **k: calls.append(url) or [],
                        )
                    )
                logic_tester.main()

        self.assertTrue(calls)
        self.assertTrue(all(url.startswith("https://api.example.test/") for url in calls))
        self.assertFalse(any("attacker.invalid" in url for url in calls))

    def test_rate_limiter_cli_uses_only_explicit_origin_for_imported_endpoints(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            output_path = Path(temp_dir) / "findings.json"
            input_path.write_text(
                json.dumps({
                    "meta": {"base_url": "https://attacker.invalid"},
                    "discovered_apis": [
                        {"url": "https://attacker.invalid/api/items"},
                        {"url": "/api/items"},
                    ],
                }),
                encoding="utf-8",
            )
            argv = [
                "rate_limiter.py", "--input", str(input_path),
                "--api-base", "https://api.example.test", "--count", "1",
                "--output", str(output_path),
            ]
            calls = []
            result = {
                "total_sent": 1, "status_codes": {"200": 1},
                "rate_limited_at": None, "rate_limit_headers": {},
                "response_times": [],
            }
            with patch.object(sys, "argv", argv), patch.object(
                rate_limiter,
                "send_rapid_requests",
                side_effect=lambda url, *a, **k: calls.append(url) or dict(result),
            ):
                rate_limiter.main()

        self.assertEqual(calls, ["https://api.example.test/api/items"])

    def test_schema_builder_never_requests_imported_off_origin_endpoints(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            output_path = Path(temp_dir) / "schema.json"
            input_path.write_text(
                json.dumps({
                    "meta": {"base_url": "https://attacker.invalid"},
                    "discovered_apis": [
                        {"url": "https://attacker.invalid/api/users", "path": "/api/users"},
                        {"url": "/api/orders", "path": "/api/orders"},
                    ],
                }),
                encoding="utf-8",
            )
            argv = [
                "schema_builder.py", "--input", str(input_path),
                "--api-base", "https://api.example.test", "--output", str(output_path),
            ]
            calls = []

            def record_request(url, *args, **kwargs):
                calls.append(url)
                return 404, {}, ""

            with patch.object(sys, "argv", argv), patch.object(
                schema_builder, "discover_resources", return_value=[]
            ), patch.object(schema_builder, "http_request", side_effect=record_request):
                schema_builder.main()

        self.assertTrue(calls)
        self.assertTrue(all(url.startswith("https://api.example.test/") for url in calls))
        self.assertFalse(any("attacker.invalid" in url for url in calls))

    def test_rate_limit_targets_skip_off_origin_imports(self):
        endpoints, graphql = rate_limiter.scope_rate_limit_targets(
            "https://api.example.test/v1",
            {
                "discovered_apis": [
                    {"url": "/v1/graphql", "api_type": "graphql"},
                    {"url": "https://attacker.invalid/collect", "api_type": "graphql"},
                    None,
                ],
                "endpoints": [{"path": "/v1/orders"}, {"url": "http://api.example.test/v1/http"}],
            },
        )
        self.assertEqual(
            endpoints,
            ["https://api.example.test/v1/graphql", "https://api.example.test/v1/orders"],
        )
        self.assertEqual(graphql, ["https://api.example.test/v1/graphql"])

    def test_rate_limiter_rejects_invalid_request_count_before_network(self):
        argv = ["rate_limiter.py", "--api-base", "https://api.example.test", "--count", "0"]
        with patch.object(sys, "argv", argv), patch.object(rate_limiter, "http_request") as request:
            with self.assertRaises(SystemExit) as error:
                rate_limiter.main()
        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()

    def test_schema_builder_paths_are_scoped_and_absolute_paths_are_canonicalized(self):
        paths = schema_builder.collect_scoped_schema_paths(
            "https://api.example.test/v1",
            [
                {"path": "/v1/users"},
                {"url": "https://attacker.invalid/collect"},
                {"path": "https://api.example.test:444/v1/admin"},
                None,
            ],
            [{"path": "/v1/orders"}, None],
        )
        self.assertEqual(
            paths,
            {"https://api.example.test/v1/users", "https://api.example.test/v1/orders"},
        )

    def test_schema_builder_requires_explicit_scope_for_imported_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "discovery.json"
            input_path.write_text(
                json.dumps({"meta": {"base_url": "https://attacker.invalid"}}),
                encoding="utf-8",
            )
            argv = ["schema_builder.py", "--input", str(input_path), "--token", "secret"]
            with patch.object(sys, "argv", argv), patch.object(schema_builder, "http_request") as request:
                with self.assertRaises(SystemExit) as error:
                    schema_builder.main()
        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
