import importlib.util
import json
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    original_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
        sys.modules.pop("_common", None)
        if original_common is not None:
            sys.modules["_common"] = original_common
    return module


authz = load_script(
    "api_authz_regressions",
    REPO_ROOT / "skills" / "api-breaker" / "scripts" / "authz_tester.py",
)
mass_assignment = load_script(
    "mass_assignment_regressions",
    REPO_ROOT / "skills" / "api-breaker" / "scripts" / "mass_assignment.py",
)
auth_analyzer = load_script(
    "api_auth_analyzer_regressions",
    REPO_ROOT / "skills" / "api-breaker" / "scripts" / "auth_analyzer.py",
)
sqli_tester = load_script(
    "sqli_regressions",
    REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "sqli_tester.py",
)
findings_importer = load_script(
    "findings_importer_regressions",
    REPO_ROOT / "skills" / "vuln-chain-composer" / "scripts" / "import_findings.py",
)
auth_tester = load_script(
    "auth_tester_regressions",
    REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "auth_tester.py",
)
recon_report = load_script(
    "recon_report_regressions",
    REPO_ROOT / "skills" / "recon-dominator" / "scripts" / "generate_report.py",
)


class TargetedAuditFixTests(unittest.TestCase):
    def test_api_endpoint_scope_rejects_external_and_origin_variants(self):
        base = "https://api.example.test:8443/v1"
        self.assertEqual(
            authz.same_origin_url(base, "/users/1"),
            "https://api.example.test:8443/users/1",
        )
        for candidate in (
            "https://attacker.example/users",
            "http://api.example.test:8443/users",
            "https://api.example.test/users",
            "https://user:pass@api.example.test:8443/users",
            "https://api.example.test:0/users",
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(authz.same_origin_url(base, candidate))

    def test_bola_never_sends_credentials_to_imported_cross_origin_url(self):
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append((url, headers or {}))
            return 404, {}, ""

        with patch.object(authz, "http_request", side_effect=record_request):
            authz.test_bola(
                "https://api.example.test",
                [{"url": "https://attacker.invalid/collect", "path": "/collect"}],
                "sensitive-user-token",
                delay=0,
            )

        self.assertTrue(calls)
        self.assertFalse(any("attacker.invalid" in url for url, _ in calls))
        self.assertTrue(all("api.example.test" in url for url, _ in calls))

    def test_api_key_probes_stay_on_origin_and_encode_query_values(self):
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(url)
            return 401, {}, ""

        with patch.object(auth_analyzer, "http_request", side_effect=record_request):
            auth_analyzer.test_api_key_positions(
                "https://api.example.test/v1",
                "secret&scope=admin",
                ["https://attacker.invalid/collect", "/v1/items"],
            )

        self.assertTrue(calls)
        self.assertFalse(any("attacker.invalid" in url for url in calls))
        query_urls = [url for url in calls if "api_key=" in url]
        self.assertTrue(query_urls)
        self.assertTrue(
            all(
                ("api_key", "secret&scope=admin")
                in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
                for url in query_urls
            )
        )

    def test_no_auth_probes_skip_imported_cross_origin_endpoints(self):
        calls = []

        def record_request(url, **kwargs):
            calls.append(url)
            return 401, {}, ""

        with patch.object(auth_analyzer, "http_request", side_effect=record_request):
            auth_analyzer.test_no_auth_access(
                "https://api.example.test",
                ["https://attacker.invalid/collect", "/api/profile"],
            )

        self.assertEqual(calls, ["https://api.example.test/api/profile"])

    def test_auth_analyzer_does_not_trust_imported_base_url(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scan.json"
            path.write_text(
                json.dumps(
                    {
                        "meta": {"base_url": "https://attacker.invalid"},
                        "endpoints": [{"url": "https://attacker.invalid/profile"}],
                    }
                )
            )
            argv = ["auth_analyzer.py", "--input", str(path), "--token", "sensitive-token"]
            with patch.object(sys, "argv", argv), patch.object(
                auth_analyzer, "http_request"
            ) as request:
                with self.assertRaises(SystemExit) as error:
                    auth_analyzer.main()

        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()

    def test_mass_assignment_does_not_trust_imported_base_url(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "schema.json"
            path.write_text(
                json.dumps(
                    {
                        "meta": {"base_url": "https://attacker.invalid"},
                        "openapi_endpoints": [
                            {"url": "https://attacker.invalid/users", "method": "POST"}
                        ],
                    }
                )
            )
            argv = [
                "mass_assignment.py",
                "--input",
                str(path),
                "--allow-mutation-write",
                "--token",
                "sensitive-token",
            ]
            with patch.object(sys, "argv", argv), patch.object(
                mass_assignment, "http_request"
            ) as request:
                with self.assertRaises(SystemExit) as error:
                    mass_assignment.main()

        self.assertEqual(error.exception.code, 2)
        request.assert_not_called()

    def test_authz_checks_are_read_only_unless_mutation_flag_is_enabled(self):
        calls = []

        def record_request(url, method="GET", headers=None, **kwargs):
            calls.append(method)
            return 200, {}, '{"id": "record-7"}'

        with patch.object(authz, "http_request", side_effect=record_request):
            authz.test_bola(
                "https://api.example.test",
                [{"url": "https://api.example.test/api/users", "path": "/api/users"}],
                "user-a",
                token_b="user-b",
                delay=0,
            )
            authz.test_bfla("https://api.example.test", "user-a", delay=0)
        self.assertTrue(calls)
        self.assertEqual(set(calls), {"GET"})

        calls.clear()
        with patch.object(authz, "http_request", side_effect=record_request):
            authz.test_bola(
                "https://api.example.test",
                [{"url": "https://api.example.test/api/users", "path": "/api/users"}],
                "user-a",
                token_b="user-b",
                delay=0,
                allow_mutation_write=True,
            )
            authz.test_bfla(
                "https://api.example.test", "user-a", delay=0, allow_mutation_write=True
            )
        self.assertIn("DELETE", calls)
        self.assertIn("POST", calls)

    def test_nested_mass_assignment_reflection_search_is_iterative(self):
        response = {"payload": [{"user": {"role": "admin"}}]}
        self.assertEqual(
            mass_assignment.find_reflected_field(response, "role"),
            (True, "admin"),
        )

        deep = {"role": "root"}
        for _ in range(1500):
            deep = [deep]
        self.assertEqual(mass_assignment.find_reflected_field(deep, "role"), (True, "root"))

    def test_mass_assignment_echo_is_candidate_and_does_not_chain(self):
        with patch.object(
            mass_assignment,
            "http_request",
            return_value=(200, {}, '{"role":"admin","password":"fixture-secret"}'),
        ):
            findings = mass_assignment.test_mass_assignment_flat(
                "https://api.example.test/users", "POST", {}, {}, delay=0
            )
        self.assertEqual(findings[0]["type"], "mass_assignment_candidate")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertFalse(findings[0]["validated"])
        self.assertNotIn("fixture-secret", findings[0]["response_preview"])

        normalized = findings_importer.normalize_finding(findings[0], "mass_assignment")
        self.assertEqual(normalized["severity"], "INFO")
        self.assertEqual(normalized["chainable_as"], [])

    def test_nested_mass_assignment_requires_value_echo_not_just_field_name(self):
        with patch.object(
            mass_assignment,
            "http_request",
            return_value=(200, {}, '{"user":{"role":"member"}}'),
        ):
            findings = mass_assignment.test_mass_assignment_nested(
                "https://api.example.test/users", "POST", {}, {}, delay=0
            )
        self.assertEqual(findings, [])

    def test_sql_error_already_in_baseline_is_not_reported_as_injection(self):
        error_response = "You have an error in your SQL syntax; check the manual"

        with patch.object(
            sqli_tester,
            "http_request",
            return_value=(200, {}, error_response, {}),
        ):
            findings = sqli_tester.test_error_based(
                "https://api.example.test/items?id=1", "id", "1"
            )

        self.assertEqual(findings, [])

    def test_finding_importer_uses_recognized_metadata_type_when_filename_is_generic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scan.json"
            path.write_text(
                json.dumps(
                    {
                        "meta": {"type": "ssrf_test", "tool": "scanner"},
                        "findings": [
                            {
                                "url": "https://example.test/fetch",
                                "evidence": "controlled error response",
                                "severity": "INFO",
                            }
                        ],
                    }
                )
            )
            findings = findings_importer.load_findings_from_file(path)

        self.assertEqual(findings[0]["type"], "ssrf")

    def test_finding_importer_skips_invalid_json_shapes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root_array = Path(temp_dir) / "array.json"
            root_array.write_text(json.dumps([{"type": "sqli"}]))
            mixed_findings = Path(temp_dir) / "mixed.json"
            mixed_findings.write_text(
                json.dumps({"meta": [], "findings": [None, "not an object", {"type": "xss"}]})
            )
            malformed_sections = Path(temp_dir) / "sections.json"
            malformed_sections.write_text(
                json.dumps(
                    {
                        "meta": {"type": "subdomain_takeover_scan"},
                        "data": {"port_scan": None, "passive_recon": []},
                        "attack_paths": [None],
                        "public_buckets": [None],
                        "vulnerable": [None],
                        "findings_by_severity": {"HIGH": [None]},
                        "all_results": [None],
                        "relationships": [None],
                        "trust_map": [None],
                    }
                )
            )

            self.assertEqual(findings_importer.load_findings_from_file(root_array), [])
            findings = findings_importer.load_findings_from_file(mixed_findings)
            self.assertEqual(findings_importer.load_findings_from_file(malformed_sections), [])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "xss")

    def test_captcha_response_does_not_become_no_rate_limit_finding(self):
        endpoint = {"url": "https://example.test/login"}
        response = (200, {}, '<div class="g-recaptcha">Verify you are human</div>')
        with patch.object(auth_tester, "http_request", return_value=response):
            findings = auth_tester.test_brute_force_protection([endpoint], {}, delay=0)
        self.assertEqual(findings, [])

    def test_no_challenge_or_lockout_still_reports_missing_brute_force_control(self):
        endpoint = {"url": "https://example.test/login"}
        with patch.object(auth_tester, "http_request", return_value=(200, {}, "Invalid password")):
            findings = auth_tester.test_brute_force_protection([endpoint], {}, delay=0)
        self.assertEqual([finding["type"] for finding in findings], ["no_brute_force_protection"])

    def test_recon_report_includes_generated_dork_queries_without_claiming_results(self):
        report = recon_report.generate_markdown_report(
            {
                "dorking": {
                    "dorks": {
                        "sensitive_files": [
                            {
                                "query": "site:example.test filetype:sql",
                                "url": "https://www.google.com/search?q=example",
                            }
                        ]
                    }
                }
            },
            "example.test",
        )
        self.assertIn("Google Dork Queries (manual review)", report)
        self.assertIn("site:example.test filetype:sql", report)
        self.assertIn("no search results were collected automatically", report)


if __name__ == "__main__":
    unittest.main()
