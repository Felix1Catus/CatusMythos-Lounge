"""Focused API Breaker scope and active-probe regressions."""

import argparse
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
authz_tester = load_api_script("api_breaker_authz_regressions", "authz_tester.py")
auth_analyzer = load_api_script("api_breaker_auth_regressions", "auth_analyzer.py")


class ApiBreakerScopeTests(unittest.TestCase):
    def test_jwt_decoder_rejects_non_object_json_segments(self):
        header_array = auth_analyzer.b64url_encode("[]")
        payload_object = auth_analyzer.b64url_encode("{}")
        header_object = auth_analyzer.b64url_encode("{}")
        payload_array = auth_analyzer.b64url_encode("[]")

        self.assertIsNone(auth_analyzer.decode_jwt(f"{header_array}.{payload_object}.sig"))
        self.assertIsNone(auth_analyzer.decode_jwt(f"{header_object}.{payload_array}.sig"))

    def test_jwt_decoder_rejects_invalid_base64url_and_non_string_tokens(self):
        payload = auth_analyzer.b64url_encode("{}")
        self.assertIsNone(auth_analyzer.decode_jwt(f"!!!!.{payload}.sig"))
        self.assertIsNone(auth_analyzer.decode_jwt(None))

    def test_jwt_report_redacts_sensitive_values_recursively(self):
        claims = {
            "sub": "alice",
            "email": "alice@example.test",
            "nested": [{"api_key": "secret-value", "role": "operator"}],
        }

        redacted = auth_analyzer.redact_claim_values(claims)

        self.assertEqual(redacted["sub"], "alice")
        self.assertEqual(redacted["email"], "[REDACTED]")
        self.assertEqual(redacted["nested"][0]["api_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"][0]["role"], "operator")

    def test_jwt_privilege_claim_finding_redacts_nested_sensitive_values(self):
        decoded = {
            "header": {"alg": "HS256"},
            "payload": {
                "permissions": {
                    "role": "admin",
                    "email": "alice@example.test",
                    "jwk": {"k": "private-material"},
                }
            },
        }

        findings = auth_analyzer.analyze_jwt_claims(decoded)
        privilege = next(item for item in findings if item["type"] == "jwt_privilege_claims")

        self.assertEqual(privilege["claims"]["permissions"]["role"], "admin")
        self.assertEqual(privilege["claims"]["permissions"]["email"], "[REDACTED]")
        self.assertEqual(privilege["claims"]["permissions"]["jwk"], "[REDACTED]")

    def test_jwt_claim_analysis_handles_invalid_expiry_values(self):
        for expiry in (10**1000, float("inf"), float("nan"), True, "tomorrow"):
            with self.subTest(expiry=repr(expiry)):
                findings = auth_analyzer.analyze_jwt_claims({
                    "header": {"alg": "RS256"},
                    "payload": {"exp": expiry},
                })
                self.assertIn("jwt_invalid_expiry", {item["type"] for item in findings})

    def test_jwt_none_bypass_requires_invalid_token_rejection_to_confirm(self):
        decoded = {"header": {"alg": "HS256"}, "payload": {"sub": "alice"}}

        with patch.object(
            auth_analyzer, "http_request",
            side_effect=[(401, {}, ""), (200, {}, '{"user": "alice"}')],
        ):
            findings = auth_analyzer.test_jwt_none_bypass(
                decoded, "https://api.example.test/private", delay=0
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "jwt_none_bypass")
        self.assertTrue(findings[0]["validated"])

    def test_jwt_none_bypass_on_public_endpoint_is_only_candidate(self):
        decoded = {"header": {"alg": "HS256"}, "payload": {"sub": "alice"}}

        with patch.object(
            auth_analyzer, "http_request",
            side_effect=[(200, {}, "public"), (200, {}, "public")] * 4,
        ):
            findings = auth_analyzer.test_jwt_none_bypass(
                decoded, "https://api.example.test/public", delay=0
            )

        self.assertEqual(len(findings), 4)
        self.assertTrue(all(f["type"] == "jwt_none_bypass_candidate" for f in findings))
        self.assertTrue(all(f["validated"] is False for f in findings))

    def test_jwt_crit_probe_compares_acceptance_not_exact_status_code(self):
        decoded = {"header": {"alg": "HS256"}, "payload": {"sub": "alice"}}

        with patch.object(
            auth_analyzer, "http_request",
            side_effect=[
                (401, {}, ""),  # malformed-token control
                (200, {}, '{"user": "alice"}'),  # none-alg control
                (201, {}, '{"user": "alice"}'),  # crit token accepted
            ],
        ):
            findings = auth_analyzer.test_jwt_crit_header_bypass(
                decoded, "https://api.example.test/private", delay=0
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "jwt_crit_not_enforced")
        self.assertTrue(findings[0]["validated"])

    def test_jwt_delay_parser_rejects_nonfinite_and_unbounded_values(self):
        self.assertEqual(auth_analyzer.parse_delay("0.5"), 0.5)
        for value in ("-1", "inf", "nan", "61"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                auth_analyzer.parse_delay(value)

    def test_api_key_position_requires_rejected_unauthenticated_control(self):
        def record_request(url, method="GET", headers=None, **kwargs):
            if headers or "api_key=" in url or "apikey=" in url or "key=" in url or "token=" in url:
                return 200, {}, '{"ok": true}'
            return 401, {}, ""

        with patch.object(auth_analyzer, "http_request", side_effect=record_request):
            findings = auth_analyzer.test_api_key_positions(
                "https://api.example.test",
                "test-key",
                ["https://api.example.test/private"],
                delay=0,
            )

        self.assertEqual(len(findings), 9)
        self.assertTrue(all(item["type"] == "api_key_position" for item in findings))
        self.assertTrue(all(item["validated"] is True for item in findings))

    def test_api_key_on_public_endpoint_is_only_candidate(self):
        with patch.object(auth_analyzer, "http_request", return_value=(200, {}, "public")):
            findings = auth_analyzer.test_api_key_positions(
                "https://api.example.test",
                "test-key",
                ["https://api.example.test/public"],
                delay=0,
            )

        self.assertEqual(len(findings), 9)
        self.assertTrue(all(item["type"] == "api_key_position_candidate" for item in findings))
        self.assertTrue(all(item["validated"] is False for item in findings))

    def test_no_auth_data_is_candidate_until_sensitivity_is_known(self):
        def record_request(url, method="GET", headers=None, **kwargs):
            return 200, {}, "x" * 80

        with patch.object(auth_analyzer, "http_request", side_effect=record_request):
            findings = auth_analyzer.test_no_auth_access(
                "https://api.example.test",
                ["https://api.example.test/private"],
                delay=0,
                auth_token="valid-token",
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "no_auth_required_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_bola_object_urls_replace_templates_and_preserve_query(self):
        base = "https://api.example.test"
        self.assertEqual(
            authz_tester.build_object_url(
                base, "https://api.example.test/api/users?active=true", "a/b ?"
            ),
            "https://api.example.test/api/users/a%2Fb%20%3F?active=true",
        )
        self.assertEqual(
            authz_tester.build_object_url(
                base, "https://api.example.test/api/users/{user_id}?active=true", "42"
            ),
            "https://api.example.test/api/users/42?active=true",
        )

    def test_bola_does_not_append_second_id_to_object_endpoint(self):
        endpoint = {"url": "https://api.example.test/api/users/42", "path": "/api/users/42"}
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(url)
            return 200, {}, '{"id": 42}'

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        self.assertIn("https://api.example.test/api/users/42", calls)
        self.assertNotIn("https://api.example.test/api/users/42/42", calls)

    def test_bola_substitutes_parameter_before_initial_request(self):
        endpoint = {
            "url": "https://api.example.test/api/users/{user_id}?active=true",
            "path": "/api/users/{user_id}",
        }
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(url)
            if "/api/users/1?active=true" in url:
                return 200, {}, '{"id": "1"}'
            return 404, {}, ""

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        self.assertEqual(calls[0], "https://api.example.test/api/users/1?active=true")
        self.assertFalse(any("{user_id}" in url for url in calls))

    def test_bola_status_only_access_is_reported_as_candidate(self):
        endpoint = {"url": "https://api.example.test/api/users/42", "path": "/api/users/42"}

        def record_request(url, method="GET", headers=None, **kwargs):
            if url == endpoint["url"] and headers and headers.get("Authorization") == "Bearer user-a":
                return 200, {}, '{"id": "42"}'
            if url == endpoint["url"]:
                return 200, {}, '{"message": "ok"}'
            return 404, {}, ""

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            findings = authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        endpoint_findings = [item for item in findings if item["url"] == endpoint["url"]]
        self.assertEqual(len(endpoint_findings), 2)
        self.assertTrue(all(item["type"] == "bola_candidate" for item in endpoint_findings))
        self.assertTrue(all(item["severity"] == "info" for item in endpoint_findings))
        self.assertTrue(all(item["validated"] is False for item in endpoint_findings))

    def test_bola_exact_object_read_remains_confirmed(self):
        endpoint = {"url": "https://api.example.test/api/users/42", "path": "/api/users/42"}

        def record_request(url, method="GET", headers=None, **kwargs):
            return 200, {}, '{"id": "42"}'

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            findings = authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        confirmed = [item for item in findings if item["url"] == endpoint["url"]]
        self.assertEqual(len(confirmed), 2)
        self.assertTrue(all(item["type"] == "bola" for item in confirmed))
        self.assertTrue(all(item["validated"] is True for item in confirmed))

    def test_bfla_success_status_is_unverified_candidate(self):
        with patch.object(authz_tester, "http_request", return_value=(200, {}, '{"items": []}')):
            findings = authz_tester.test_bfla(
                "https://api.example.test", "user", delay=0
            )

        self.assertTrue(findings)
        self.assertTrue(all(item["type"] == "bfla_candidate" for item in findings))
        self.assertTrue(all(item["severity"] == "info" for item in findings))
        self.assertTrue(all(item["validated"] is False for item in findings))
        report = api_report.generate_finding_report(findings[0], 1)
        self.assertEqual(report["owasp_mapping"]["id"], "API5:2023")
        self.assertIn("Unverified probe candidate", report["impact"])

    def test_bfla_write_probes_remain_active_but_candidates(self):
        calls = []

        def record_request(url, method="GET", headers=None, data=None, **kwargs):
            calls.append((method, headers or {}))
            return 200, {}, '{"ok": true}'

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            findings = authz_tester.test_bfla(
                "https://api.example.test", "user", delay=0, allow_mutation_write=True
            )

        self.assertIn("DELETE", {method for method, _ in calls})
        self.assertTrue(any(
            method == "POST" and "X-HTTP-Method-Override" in headers
            for method, headers in calls
        ))
        self.assertTrue(findings)
        self.assertTrue(all(item["type"].endswith("_candidate") for item in findings))

    def test_authz_bola_and_bfla_gets_run_against_loopback_fixture(self):
        requests = []

        class FixtureHandler(BaseHTTPRequestHandler):
            def _send(self, status, document):
                body = json.dumps(document).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                authorization = self.headers.get("Authorization")
                requests.append((self.command, self.path, authorization))
                if self.path == "/v1/users" and authorization == "Bearer user-a":
                    self._send(200, {"users": [{"id": "object-7"}]})
                elif self.path == "/v1/users/object-7" and authorization == "Bearer user-b":
                    self._send(200, {"id": "object-7", "owner": "user-a"})
                elif self.path == "/v1/users/object-7" and authorization is None:
                    self._send(403, {"error": "authentication required"})
                elif self.path == "/admin" and authorization == "Bearer regular-user":
                    self._send(200, {"section": "admin dashboard fixture"})
                else:
                    self._send(404, {"error": "not found"})

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            bola_findings = authz_tester.test_bola(
                base_url,
                [{"url": f"{base_url}/v1/users", "path": "/v1/users"}],
                "user-a",
                token_b="user-b",
            )
            bfla_findings = authz_tester.test_bfla(base_url, "regular-user")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        self.assertTrue(any(
            finding["type"] == "bola" and finding["access"] == "different_user"
            and finding["object_id"] == "object-7"
            for finding in bola_findings
        ))
        self.assertTrue(any(
            finding["type"] == "bfla_candidate" and finding["path"] == "/admin"
            for finding in bfla_findings
        ))
        self.assertIn(("GET", "/v1/users/object-7", "Bearer user-b"), requests)
        self.assertIn(("GET", "/admin", "Bearer regular-user"), requests)
        self.assertTrue(all(method == "GET" for method, _, _ in requests))

    def test_authz_delay_parser_rejects_nonfinite_negative_and_excessive_values(self):
        self.assertEqual(authz_tester.parse_delay("0"), 0)
        self.assertEqual(authz_tester.parse_delay("60"), 60)
        for value in ("nan", "inf", "-0.1", "60.1", "oops"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                authz_tester.parse_delay(value)

    def test_authz_response_previews_redact_sensitive_json_and_omit_text(self):
        preview = authz_tester.safe_response_preview(json.dumps({
            "id": "record-7",
            "email": "alice@example.test",
            "profile": {
                "access_token": "credential-value",
                "first_name": "Alice",
                "role": "member",
            },
            "message": "Authorization: Bearer header-token",
        }))

        self.assertIn("record-7", preview)
        self.assertIn("member", preview)
        for sensitive in (
            "alice@example.test", "credential-value", "Alice", "header-token",
        ):
            self.assertNotIn(sensitive, preview)
        self.assertIn("[REDACTED]", preview)
        self.assertTrue(authz_tester.safe_response_preview("<html>private body</html>").startswith(
            "[non-JSON response omitted;"
        ))

    def test_extract_object_ids_handles_deep_or_invalid_json_without_crashing(self):
        deeply_nested = "[" * 1500 + '{"id":"deep-42"}' + "]" * 1500
        self.assertEqual(authz_tester.extract_object_ids(deeply_nested), {"deep-42"})
        self.assertEqual(authz_tester.extract_object_ids(None), set())

    def test_bola_never_reuses_user_a_cookie_for_user_b(self):
        endpoint = {"url": "https://api.example.test/v1/users", "path": "/v1/users"}

        for cookie_b, expected_cookie_b in (("session=user-b", "session=user-b"), (None, None)):
            requests = []

            def record_request(url, method="GET", headers=None, **_kwargs):
                requests.append((url, headers or {}))
                return 200, {}, '{"users":[{"id":"42"}],"id":"42"}'

            with patch.object(authz_tester, "http_request", side_effect=record_request):
                authz_tester.test_bola(
                    "https://api.example.test", [endpoint], "user-a", token_b="user-b",
                    extra_headers={"Cookie": "session=user-a", "X-Tenant": "acme"},
                    delay=0, cookie_b=cookie_b,
                )

            user_a_headers = next(
                headers for url, headers in requests
                if url == endpoint["url"] and headers.get("Authorization") == "Bearer user-a"
            )
            user_b_headers = next(
                headers for url, headers in requests
                if url.endswith("/v1/users/42")
                and headers.get("Authorization") == "Bearer user-b"
            )
            self.assertEqual(user_a_headers.get("Cookie"), "session=user-a")
            self.assertEqual(user_b_headers.get("Cookie"), expected_cookie_b)
            self.assertEqual(user_b_headers.get("X-Tenant"), "acme")
            self.assertTrue(all(
                not headers.get("Cookie") for _, headers in requests
                if "Authorization" not in headers
            ))

    def test_authz_cli_routes_distinct_cookies_and_rejects_invalid_delay(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "authz.json"
            argv = [
                "authz_tester.py", "--api-base", "https://api.example.test",
                "--token", "token-a", "--token-b", "token-b",
                "--cookie", "session=a", "--cookie-b", "session=b",
                "--output", str(output_path),
            ]
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys, "argv", argv))
                bola_probe = stack.enter_context(patch.object(
                    authz_tester, "test_bola", return_value=[]
                ))
                stack.enter_context(patch.object(authz_tester, "test_bfla", return_value=[]))
                authz_tester.main()

        self.assertEqual(bola_probe.call_args.kwargs["cookie_b"], "session=b")
        self.assertEqual(bola_probe.call_args.args[4], {"Cookie": "session=a"})

        for invalid_delay in ("nan", "inf", "-1", "61"):
            with self.subTest(invalid_delay=invalid_delay), patch.object(
                sys,
                "argv",
                ["authz_tester.py", "--api-base", "https://api.example.test",
                 "--token", "token-a", "--delay", invalid_delay],
            ), patch.object(authz_tester, "http_request") as request:
                with self.assertRaises(SystemExit) as error:
                    authz_tester.main()
            self.assertEqual(error.exception.code, 2)
            request.assert_not_called()

    def test_bola_recognizes_uuid_object_endpoint(self):
        object_id = "550e8400-e29b-41d4-a716-446655440000"
        endpoint_url = f"https://api.example.test/api/users/{object_id}"
        endpoint = {"url": endpoint_url, "path": f"/api/users/{object_id}"}
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(url)
            return 200, {}, '{"id": "550e8400-e29b-41d4-a716-446655440000"}'

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        self.assertIn(endpoint_url, calls)
        self.assertNotIn(f"{endpoint_url}/{object_id}", calls)

    def test_bola_collection_id_keeps_existing_query_parameters(self):
        endpoint = {"url": "https://api.example.test/api/users?mine=true", "path": "/api/users"}
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(url)
            if url == endpoint["url"]:
                return 200, {}, '{"users": [{"id": 42}]}'
            return 403, {}, ""

        with patch.object(authz_tester, "http_request", side_effect=record_request):
            authz_tester.test_bola(
                "https://api.example.test", [endpoint], "user-a", token_b="user-b", delay=0
            )

        self.assertIn("https://api.example.test/api/users/42?mine=true", calls)
        self.assertFalse(any("mine=true/42" in url for url in calls))

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

    def test_graphql_delay_and_candidate_id_arguments_are_bounded(self):
        self.assertEqual(schema_builder.parse_delay("0"), 0)
        self.assertEqual(schema_builder.parse_delay("60"), 60)
        for value in ("nan", "inf", "-0.1", "60.1", "oops"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                schema_builder.parse_delay(value)

        self.assertEqual(schema_builder.parse_candidate_ids("a, b,a,,c"), ["a", "b", "c"])
        too_many = ",".join(f"id{i}" for i in range(schema_builder.MAX_CANDIDATE_IDS + 1))
        too_long = "x" * (schema_builder.MAX_CANDIDATE_ID_LENGTH + 1)
        for value in (too_many, too_long, "bad\nvalue"):
            with self.subTest(candidate=value[:20]), self.assertRaises(argparse.ArgumentTypeError):
                schema_builder.parse_candidate_ids(value)

    def test_graphql_depth_fast_transport_failure_is_inconclusive(self):
        with patch.object(schema_builder, "_pick_working_field_pair", return_value=("node", "node")), \
             patch.object(schema_builder, "http_request", return_value=(0, {}, "")) as request, \
             patch.object(schema_builder.time, "monotonic", side_effect=[0.0, 0.01]):
            findings, threshold, pair = schema_builder.test_graphql_depth_complexity_dos(
                "https://api.example.test/graphql", depth_steps=[2]
            )

        self.assertEqual(findings, [])
        self.assertIsNone(threshold)
        self.assertEqual(pair, ("node", "node"))
        request.assert_called_once()

    def test_graphql_depth_server_error_is_candidate_not_confirmed_dos(self):
        with patch.object(schema_builder, "_pick_working_field_pair", return_value=("node", "node")), \
             patch.object(schema_builder, "http_request", return_value=(503, {}, "upstream error")), \
             patch.object(schema_builder.time, "monotonic", side_effect=[0.0, 0.1]):
            findings, _, _ = schema_builder.test_graphql_depth_complexity_dos(
                "https://api.example.test/graphql", depth_steps=[2]
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "graphql_depth_complexity_dos_candidate")
        self.assertEqual(findings[0]["classification"], "server_error_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_graphql_depth_timeout_is_candidate_not_confirmed_dos(self):
        with patch.object(schema_builder, "_pick_working_field_pair", return_value=("node", "node")), \
             patch.object(schema_builder, "http_request", return_value=(0, {}, "")), \
             patch.object(schema_builder.time, "monotonic", side_effect=[0.0, 9.8]):
            findings, _, _ = schema_builder.test_graphql_depth_complexity_dos(
                "https://api.example.test/graphql", depth_steps=[2], timeout=10
            )

        self.assertEqual(findings[0]["classification"], "timeout_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_graphql_introspection_bypass_rejects_non_success_and_marks_acceptance_candidate(self):
        with patch.object(schema_builder, "http_request", return_value=(403, {}, '{"data":{"node":{}}}')) as request:
            self.assertEqual(
                schema_builder.test_graphql_introspection_naming_bypass(
                    "https://api.example.test/graphql", 4, ("node", "node")
                ),
                [],
            )
        request.assert_called_once()

        with patch.object(schema_builder, "http_request", return_value=(200, {}, '{"data":{"node":{}}}')):
            findings = schema_builder.test_graphql_introspection_naming_bypass(
                "https://api.example.test/graphql", 4, ("node", "node")
            )
        self.assertEqual(findings[0]["type"], "graphql_depth_limit_bypass_introspection_naming_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_graphql_introspection_bypass_rejects_invalid_remote_names_without_request(self):
        with patch.object(schema_builder, "http_request") as request:
            findings = schema_builder.test_graphql_introspection_naming_bypass(
                "https://api.example.test/graphql", 4, ("node } mutation { leak", "node")
            )
        self.assertEqual(findings, [])
        request.assert_not_called()

    def test_graphql_nested_authz_requires_valid_control_and_returns_candidate(self):
        schema = {"types": [
            {"name": "Query", "fields": [
                {"name": "me", "type": "User", "args": []},
                {"name": "user", "type": "User", "args": ["id"]},
            ]},
            {"name": "User", "fields": []},
        ]}

        def respond(_url, _method="GET", _headers=None, data=None, **_kwargs):
            query = json.loads(data)["query"]
            if "me {" in query:
                return 200, {}, '{"data":{"me":{"id":"alice","email":null}}}'
            return 200, {}, '{"data":{"user":{"id":"other","email":"other@example.test"}}}'

        with patch.object(schema_builder, "http_request", side_effect=respond):
            findings = schema_builder.test_graphql_nested_field_authz(
                "https://api.example.test/graphql", schema
            )

        self.assertTrue(findings)
        self.assertTrue(all(f["type"] == "graphql_bola_nested_field_candidate" for f in findings))
        self.assertTrue(all(f["severity"] == "info" and not f["validated"] for f in findings))

    def test_graphql_nested_authz_does_not_classify_auth_failures_as_leaks(self):
        schema = {"types": [
            {"name": "Query", "fields": [
                {"name": "me", "type": "User", "args": []},
                {"name": "user", "type": "User", "args": ["id"]},
            ]},
            {"name": "User", "fields": []},
        ]}
        with patch.object(schema_builder, "http_request", return_value=(401, {}, '{"data":{"me":{"email":"x"}}}')):
            findings = schema_builder.test_graphql_nested_field_authz(
                "https://api.example.test/graphql", schema
            )
        self.assertEqual(findings, [])

    def test_graphql_nested_authz_json_quotes_operator_supplied_id(self):
        schema = {"types": [
            {"name": "Query", "fields": [
                {"name": "me", "type": "User", "args": []},
                {"name": "user", "type": "User", "args": ["id"]},
            ]},
            {"name": "User", "fields": []},
        ]}
        attack_string = 'other") { admin } #'
        queries = []

        def respond(_url, _method="GET", _headers=None, data=None, **_kwargs):
            query = json.loads(data)["query"]
            queries.append(query)
            if "me {" in query:
                return 200, {}, '{"data":{"me":{"id":"alice","email":null}}}'
            return 200, {}, '{"data":{"user":{"id":"other","email":"other@example.test"}}}'

        with patch.object(schema_builder, "http_request", side_effect=respond):
            schema_builder.test_graphql_nested_field_authz(
                "https://api.example.test/graphql", schema, candidate_ids=[attack_string]
            )

        self.assertTrue(any(f"id: {json.dumps(attack_string)}" in query for query in queries))

    def test_graphql_mutation_write_remains_opt_in_and_selected_opt_in_sends(self):
        with patch.object(schema_builder, "http_request") as request:
            self.assertEqual(schema_builder.test_graphql_mutation_bola_write(
                "https://api.example.test/graphql", "updateUser", "id", "canary-2"
            ), [])
        request.assert_not_called()

        with patch.object(schema_builder, "http_request", return_value=(
            200, {}, '{"data":{"updateUser":{"__typename":"User"}}}'
        )) as request:
            findings = schema_builder.test_graphql_mutation_bola_write(
                "https://api.example.test/graphql", "updateUser", "id", "canary-2",
                allow_write=True,
            )
        request.assert_called_once()
        self.assertEqual(findings[0]["type"], "graphql_mutation_bola_write_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_graphql_fragment_cycle_acceptance_is_unverified_candidate(self):
        with patch.object(schema_builder, "http_request", return_value=(
            200, {}, '{"data":{"__typename":"Query"}}'
        )):
            findings = schema_builder.test_graphql_fragment_cycle("https://api.example.test/graphql")
        self.assertEqual(findings[0]["type"], "graphql_fragment_cycle_candidate")
        self.assertFalse(findings[0]["validated"])

    def test_graphql_candidate_findings_map_to_owasp_api_categories(self):
        bola = api_report.generate_finding_report({
            "type": "graphql_bola_nested_field_candidate", "severity": "info", "validated": False,
        }, 1)
        dos = api_report.generate_finding_report({
            "type": "graphql_depth_complexity_dos_candidate", "severity": "info", "validated": False,
        }, 2)
        self.assertEqual(bola["owasp_mapping"]["id"], "API1:2023")
        self.assertEqual(dos["owasp_mapping"]["id"], "API4:2023")

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
