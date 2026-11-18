"""Offline contract tests for campaign planning and coverage accounting."""
import copy
import importlib.util
import json
import threading
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "assessment_campaign", ROOT / "scripts" / "assessment_campaign.py")
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


def manifest():
    return {
        "schema_version": 1,
        "engagement": "fixture-engagement",
        "scope": {"origins": ["https://app.example.test"], "request_budget": 40},
        "targets": [{"id": "app", "url": "https://app.example.test/login",
                     "roles": [{"name": "anonymous"},
                               {"name": "member", "credential_env": "FIXTURE_MEMBER_TOKEN",
                                "credential_header": "Authorization"}]}],
        "steps": [
            {"id": "recon", "tool": "tech_fingerprint", "target": "app",
             "max_requests": 8},
            {"id": "discover", "tool": "web_crawl", "target": "app",
             "depends_on": ["recon"], "max_requests": 12},
            {"id": "authz", "tool": "api_authz", "target": "app", "role": "member",
             "depends_on": ["discover"], "max_requests": 20},
        ],
    }


def confirmed_evidence_review():
    return {"schema_version": 1, "assessment_state": "confirmed",
            "proof_checks": {"complete": True}}


def workflow_manifest():
    value = manifest()
    value["scope"]["allow_state_changes"] = True
    value["steps"] = [{"id": "workflow", "tool": "business_workflow", "target": "app",
                       "role": "member", "max_requests": 4, "fixture_note": "disposable test fixture",
                       "scenario_file": "flow.json", "cleanup": ["delete disposable fixture"]}]
    return value


def workflow_scenario():
    return {"version": 1, "name": "status-check",
            "baseline": {"actions": [{"method": "GET", "path": "/status"}],
                         "assertions": [{"pointer": "/state", "equals": "ok"}]},
            "cases": [{"name": "repeat-status", "actions": [{"method": "GET", "path": "/status"}],
                       "assertions": [{"pointer": "/state", "equals": "ok"}]}]}


class CampaignManifestTests(unittest.TestCase):
    def test_checked_in_campaign_template_is_valid(self):
        template = json.loads((ROOT / "doctrine" / "templates" / "ASSESSMENT_CAMPAIGN.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(campaign.validate_manifest(template)["engagement"],
                         "replace-with-engagement-label")

    def test_valid_manifest_yields_ordered_plan_and_never_reads_credentials(self):
        value = manifest()
        plan = campaign.validate_manifest(value)
        self.assertEqual([step["id"] for step in plan["steps"]], ["recon", "discover", "authz"])
        self.assertEqual(plan["scope"]["declared_request_budget"], 40)
        self.assertEqual(plan["targets"][0]["roles"][1]["credential_env"], "FIXTURE_MEMBER_TOKEN")
        self.assertNotIn("token-value", json.dumps(plan))
        self.assertEqual(plan["steps"][1]["depends_on"], ["recon"])

    def test_target_paths_are_allowed_but_origin_must_be_explicit(self):
        value = manifest()
        value["targets"][0]["url"] = "https://app.example.test/dvwa/?level=low"
        self.assertEqual(campaign.validate_manifest(value)["targets"][0]["origin"],
                         "https://app.example.test:443")
        value["targets"][0]["url"] = "https://other.example.test/"
        with self.assertRaisesRegex(campaign.CampaignError, "outside"):
            campaign.validate_manifest(value)

    def test_scope_rejects_credentials_subpaths_and_non_http_schemes(self):
        for origin in ("https://user:pass@app.example.test", "https://app.example.test/a",
                       "ftp://app.example.test", "https://app.example.test?x=1"):
            with self.subTest(origin=origin):
                value = manifest()
                value["scope"]["origins"] = [origin]
                with self.assertRaises(campaign.CampaignError):
                    campaign.validate_manifest(value)

    def test_target_rejects_credentials_fragment_and_control_characters(self):
        for target in ("https://user:pass@app.example.test/", "https://app.example.test/#x",
                       "https://app.example.test/\r\nHost:evil"):
            with self.subTest(target=target):
                value = manifest()
                value["targets"][0]["url"] = target
                with self.assertRaises(campaign.CampaignError):
                    campaign.validate_manifest(value)

    def test_step_budget_cannot_exceed_global_budget(self):
        value = manifest()
        value["scope"]["request_budget"] = 39
        with self.assertRaisesRegex(campaign.CampaignError, "exceed"):
            campaign.validate_manifest(value)

    def test_invalid_bool_budget_does_not_pass_as_integer(self):
        value = manifest()
        value["steps"][0]["max_requests"] = True
        with self.assertRaisesRegex(campaign.CampaignError, "integer"):
            campaign.validate_manifest(value)

    def test_unknown_tool_and_arbitrary_command_are_not_executable(self):
        value = manifest()
        value["steps"][0]["tool"] = "powershell"
        value["steps"][0]["command"] = "Remove-Item"
        with self.assertRaisesRegex(campaign.CampaignError, "unsupported"):
            campaign.validate_manifest(value)

    def test_dependencies_must_be_unique_and_previously_declared(self):
        value = manifest()
        value["steps"][0]["depends_on"] = ["future"]
        with self.assertRaisesRegex(campaign.CampaignError, "earlier"):
            campaign.validate_manifest(value)
        value = manifest()
        value["steps"][1]["depends_on"] = ["recon", "recon"]
        with self.assertRaisesRegex(campaign.CampaignError, "unique"):
            campaign.validate_manifest(value)

    def test_unknown_role_cannot_be_assigned_to_step(self):
        value = manifest()
        value["steps"][1]["role"] = "admin"
        with self.assertRaisesRegex(campaign.CampaignError, "undeclared"):
            campaign.validate_manifest(value)

    def test_role_secret_values_are_not_accepted_as_credential_reference(self):
        value = manifest()
        value["targets"][0]["roles"][1]["credential_env"] = "Bearer secret-value"
        with self.assertRaisesRegex(campaign.CampaignError, "environment-variable"):
            campaign.validate_manifest(value)

    def test_authorization_matrix_expands_declared_roles_over_explicit_access_policy(self):
        value = manifest()
        value["authorization_matrices"] = [{"target": "app", "objects": [
            {"id": "invoice-1", "owner_role": "member", "allowed_roles": ["member"]}]}]
        plan = campaign.validate_manifest(value)
        cases = plan["authorization_matrix"]
        self.assertEqual(len(cases), 2)
        anonymous = next(case for case in cases if case["role"] == "anonymous")
        self.assertFalse(anonymous["expected_access"])
        self.assertEqual(anonymous["target"], "app")

    def test_business_context_must_validate_and_match_scoped_host(self):
        value = manifest()
        value["business_context"] = {"schema_version": 1, "assets": [{
            "host": "app.example.test", "service_name": "fixture app", "purpose": "test workflow",
            "evidence": "operator scope note", "impact_evidence": "contains fixture data",
            "business_criticality": "moderate", "data_sensitivity": "internal",
            "affected_scope": "team", "source": "assessment briefing",
        }]}
        result = campaign.validate_manifest(value)
        self.assertEqual(len(result["business_context"]["assets"]), 1)
        value["business_context"]["assets"][0]["host"] = "outside.example.test"
        with self.assertRaisesRegex(campaign.CampaignError, "scoped hostname"):
            campaign.validate_manifest(value)

    def test_duplicate_target_and_step_ids_are_rejected(self):
        value = manifest()
        value["targets"].append(copy.deepcopy(value["targets"][0]))
        with self.assertRaisesRegex(campaign.CampaignError, "duplicate target"):
            campaign.validate_manifest(value)
        value = manifest()
        value["steps"][1]["id"] = "recon"
        with self.assertRaisesRegex(campaign.CampaignError, "step ids"):
            campaign.validate_manifest(value)

    def test_stateful_steps_require_explicit_mutation_gate_and_cleanup(self):
        value = manifest()
        value["steps"][0] = {"id": "workflow", "tool": "business_workflow", "target": "app",
                              "max_requests": 10, "fixture_note": "disposable fixture",
                              "scenario_file": "flows/order.json",
                              "cleanup": ["delete created fixture"]}
        value["steps"] = value["steps"][:1]
        with self.assertRaisesRegex(campaign.CampaignError, "allow_state_changes"):
            campaign.validate_manifest(value)
        value["scope"]["allow_state_changes"] = True
        plan = campaign.validate_manifest(value)
        self.assertEqual(plan["steps"][0]["mode"], "stateful")
        value["steps"][0]["cleanup"] = []
        with self.assertRaisesRegex(campaign.CampaignError, "cleanup"):
            campaign.validate_manifest(value)

    def test_cleanup_labels_reject_control_characters(self):
        value = manifest()
        value["scope"]["allow_state_changes"] = True
        value["steps"] = [{"id": "workflow", "tool": "business_workflow", "target": "app",
                           "max_requests": 10, "fixture_note": "fixture",
                           "scenario_file": "flows/order.json",
                           "cleanup": ["delete\ncreated fixture"]}]
        with self.assertRaisesRegex(campaign.CampaignError, "action labels"):
            campaign.validate_manifest(value)

    def test_stateful_scenario_path_must_not_traverse_out_of_manifest_directory(self):
        value = workflow_manifest()
        value["steps"][0]["scenario_file"] = "../outside.json"
        with self.assertRaisesRegex(campaign.CampaignError, "parent traversal"):
            campaign.validate_manifest(value)

    def test_workflow_execution_requires_exact_origin_and_respects_step_budget(self):
        value = workflow_manifest()
        calls = []
        request = lambda url, **kwargs: (calls.append((url, kwargs)) or (200, {}, '{"state":"ok"}'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "campaign.json"
            (root / "flow.json").write_text(json.dumps(workflow_scenario()), encoding="utf-8")
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "exactly match"):
                campaign.execute_workflow_step(value, manifest_path, "workflow",
                                               "https://other.example.test", request)
            self.assertEqual(calls, [])
            result = campaign.execute_workflow_step(value, manifest_path, "workflow",
                                                    "https://app.example.test", request,
                                                    {"FIXTURE_MEMBER_TOKEN": "Bearer secret-fixture-token"})
        self.assertEqual(result["execution"]["requests_sent"], 2)
        self.assertEqual(result["execution"]["request_budget"], 4)
        self.assertEqual(result["execution"]["cleanup_status"], "not_required")
        self.assertTrue(all(call[1]["headers"]["Authorization"] == "Bearer secret-fixture-token"
                            for call in calls))
        self.assertNotIn("secret-fixture-token", json.dumps(result))
        self.assertNotIn("state\": \"ok", json.dumps(result))

    def test_workflow_preflight_rejects_scenario_that_exceeds_request_budget(self):
        value = workflow_manifest()
        value["steps"][0]["max_requests"] = 1
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "campaign.json"
            (root / "flow.json").write_text(json.dumps(workflow_scenario()), encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "request cap"):
                campaign.execute_workflow_step(value, manifest_path, "workflow",
                                               "https://app.example.test", lambda *a, **kw: calls.append(1))
        self.assertEqual(calls, [])

    def test_campaign_ledger_shares_budget_and_refuses_completed_step_replay(self):
        value = workflow_manifest()
        value["scope"]["request_budget"] = 8
        value["steps"].append({**value["steps"][0], "id": "workflow-two"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "campaign.json"
            (root / "flow.json").write_text(json.dumps(workflow_scenario()), encoding="utf-8")
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            ledger = campaign.CampaignLedger(root / "state.sqlite", "fixture-run")
            ledger.bind(value)
            calls = []
            request = lambda *args, **kwargs: (calls.append(1) or (200, {}, '{"state":"ok"}'))
            ledger.start_step("workflow")
            first = campaign.execute_workflow_step(value, manifest_path, "workflow",
                "https://app.example.test", request, {"FIXTURE_MEMBER_TOKEN": "secret"},
                ledger.reserve_request)
            ledger.finish_step("workflow", "completed")
            self.assertEqual(first["execution"]["requests_sent"], 2)
            with self.assertRaisesRegex(campaign.CampaignError, "already completed"):
                ledger.start_step("workflow")
            ledger.start_step("workflow-two")
            second = campaign.execute_workflow_step(value, manifest_path, "workflow-two",
                "https://app.example.test", request, {"FIXTURE_MEMBER_TOKEN": "secret"},
                ledger.reserve_request)
            ledger.finish_step("workflow-two", "completed")
            summary = ledger.summary()
            ledger.close()
        self.assertEqual(second["execution"]["requests_sent"], 2)
        self.assertFalse(second["execution"]["budget_exhausted"])
        self.assertEqual(len(calls), 4)
        self.assertEqual(summary["requests_used"], 4)
        self.assertNotIn("secret-fixture-token", json.dumps(summary))

    def test_campaign_ledger_binds_campaign_id_to_manifest_and_requires_retry_review(self):
        value = workflow_manifest()
        with tempfile.TemporaryDirectory() as directory:
            ledger = campaign.CampaignLedger(Path(directory) / "state.sqlite", "run-a")
            ledger.bind(value)
            ledger.start_step("workflow")
            with self.assertRaisesRegex(campaign.CampaignError, "unfinished"):
                ledger.start_step("workflow")
            ledger.finish_step("workflow", "interrupted")
            with self.assertRaisesRegex(campaign.CampaignError, "after review"):
                ledger.start_step("workflow")
            ledger.start_step("workflow", retry_interrupted=True)
            changed = copy.deepcopy(value)
            changed["scope"]["request_budget"] += 1
            with self.assertRaisesRegex(campaign.CampaignError, "different engagement or manifest"):
                ledger.bind(changed)
            ledger.close()

    def test_campaign_ledger_atomically_rejects_requests_over_campaign_cap(self):
        value = workflow_manifest()
        value["scope"]["request_budget"] = 4
        value["steps"][0]["max_requests"] = 2
        value["steps"].append({**value["steps"][0], "id": "workflow-two"})
        with tempfile.TemporaryDirectory() as directory:
            ledger = campaign.CampaignLedger(Path(directory) / "state.sqlite", "budget-run")
            ledger.bind(value)
            ledger.start_step("workflow")
            ledger.reserve_request("workflow", 2)
            ledger.reserve_request("workflow", 2)
            ledger.finish_step("workflow", "completed")
            with self.assertRaisesRegex(campaign.CampaignError, "require a running campaign step"):
                ledger.reserve_request("workflow", 2)
            ledger.start_step("workflow-two")
            ledger.reserve_request("workflow-two", 2)
            ledger.reserve_request("workflow-two", 2)
            with self.assertRaisesRegex(campaign.CampaignError, "campaign-wide request budget exhausted"):
                ledger.reserve_request("workflow-two", 2)
            summary = ledger.summary()
            ledger.close()
        self.assertEqual(summary["requests_used"], 4)
        self.assertEqual(summary["request_budget"], 4)

    def test_campaign_ledger_enforces_dependencies_and_operator_attestation(self):
        value = manifest()
        value["steps"][0]["tool"] = "cloud_detector"
        with tempfile.TemporaryDirectory() as directory:
            ledger = campaign.CampaignLedger(Path(directory) / "state.sqlite", "ordered-run")
            ledger.bind(value)
            with self.assertRaisesRegex(campaign.CampaignError, "dependencies are not completed: recon"):
                ledger.start_step("discover")
            with self.assertRaisesRegex(campaign.CampaignError, "dependencies are not completed: recon"):
                ledger.attest_external_step("discover", "Premature completion attempt")
            ledger.attest_external_step("recon", "Reviewed recon-dominator output recon.json")
            ledger.start_step("discover")
            ledger.finish_step("discover", "completed")
            summary = ledger.summary()
            ledger.close()
        self.assertEqual([step["status"] for step in summary["steps"]],
                         ["completed", "completed", "planned"])

    def test_campaign_record_step_cli_attests_registered_external_step(self):
        value = manifest()
        value["steps"] = [{"id": "manual-scan", "tool": "web_idor", "target": "app",
                           "max_requests": 4}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, state_path = root / "campaign.json", root / "state.sqlite"
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(campaign.main([
                "campaign-record-step", "--manifest", str(manifest_path),
                "--state-db", str(state_path), "--campaign-id", "cli-run",
                "--step", "manual-scan", "--operator-note", "Reviewed local scan output",
            ]), 0)
            result = campaign.main(["campaign-status", "--state-db", str(state_path),
                                    "--campaign-id", "cli-run"])
        self.assertEqual(result, 0)

    def test_http_transport_does_not_follow_redirects_out_of_scope(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/out-of-scope")
                    self.end_headers()
                    return
                body = b'{"state":"ok"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        opener = campaign.urllib.request.build_opener(campaign._NoRedirect())
        base = "http://127.0.0.1:{}".format(server.server_address[1])
        self.assertEqual(campaign._bounded_http_request(opener, base + "/ok")[0], 200)
        status, headers, _body = campaign._bounded_http_request(opener, base + "/redirect")
        self.assertEqual(status, 302)
        self.assertIn("Location", headers)

    def test_run_workflow_cli_executes_a_bounded_scenario_on_loopback(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"state":"ok"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:{}/".format(server.server_address[1])
        value = workflow_manifest()
        value["scope"]["origins"] = [base]
        value["targets"][0]["url"] = base
        value["steps"][0]["role"] = "anonymous"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, output_path = root / "campaign.json", root / "run.json"
            (root / "flow.json").write_text(json.dumps(workflow_scenario()), encoding="utf-8")
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(campaign.main(["run-workflow", "--manifest", str(manifest_path),
                                            "--step", "workflow", "--confirm-target", base,
                                            "--output", str(output_path)]), 0)
            result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(result["execution"]["requests_sent"], 2)
        self.assertEqual(result["execution"]["request_budget"], 4)
        self.assertTrue(all(entry["assertions_passed"] for entry in result["results"]))
        self.assertNotIn('"state": "ok"', json.dumps(result))

    def test_run_step_cli_fingerprints_only_confirmed_loopback_origin_with_ledger_budget(self):
        class Handler(BaseHTTPRequestHandler):
            server_version = "nginx"
            sys_version = ""

            def do_GET(self):
                self.send_response(200)
                self.send_header("Set-Cookie", "session=secret-campaign-cookie")
                self.end_headers()
                self.wfile.write(b'<html><meta name="generator" content="secret-campaign-meta">WordPress fixture</html>')

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:{}/".format(server.server_address[1])
        value = manifest()
        value["scope"] = {"origins": [base], "request_budget": 2}
        value["targets"][0]["url"] = base
        value["steps"] = [{"id": "fingerprint", "tool": "tech_fingerprint", "target": "app",
                           "max_requests": 2}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, state_path, output_path = root / "campaign.json", root / "state.sqlite", root / "out.json"
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(campaign.main([
                "run-step", "--manifest", str(manifest_path), "--step", "fingerprint",
                "--confirm-target", base, "--state-db", str(state_path),
                "--campaign-id", "fingerprint-run", "--output", str(output_path),
            ]), 0)
            result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertIn("WordPress", result["technologies"])
        self.assertLessEqual(result["execution"]["requests_sent"], 2)
        self.assertFalse(result["execution"]["response_headers_recorded"])
        self.assertNotIn("secret-campaign-cookie", json.dumps(result))
        self.assertNotIn("secret-campaign-meta", json.dumps(result))

    def test_run_step_cli_api_discovery_caps_same_origin_reads_and_omits_bodies(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"openapi":"3.0.0","paths":{}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=secret-api-cookie")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:{}/".format(server.server_address[1])
        value = manifest()
        value["scope"] = {"origins": [base], "request_budget": 2}
        value["targets"][0]["url"] = base
        value["steps"] = [{"id": "api-discovery", "tool": "api_discovery", "target": "app",
                           "max_requests": 2}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, state_path, output_path = root / "campaign.json", root / "state.sqlite", root / "out.json"
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(campaign.main([
                "run-step", "--manifest", str(manifest_path), "--step", "api-discovery",
                "--confirm-target", base, "--state-db", str(state_path),
                "--campaign-id", "api-run", "--output", str(output_path),
            ]), 0)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            ledger = campaign.CampaignLedger(state_path, "api-run")
            campaign_state = ledger.summary()
            ledger.close()
        self.assertLessEqual(result["execution"]["requests_sent"], 2)
        self.assertTrue(result["discovered_apis"])
        self.assertTrue(result["execution"]["budget_exhausted"])
        self.assertEqual(campaign_state["requests_used"], 2)
        self.assertEqual(campaign_state["steps"][0]["status"], "failed")
        self.assertTrue(result["execution"]["state_changing_method_probes_enabled"] is False)
        self.assertFalse(result["execution"]["response_bodies_recorded"])
        self.assertFalse(result["execution"]["credentials_recorded"])
        self.assertNotIn("secret-api-cookie", json.dumps(result))

    def test_manifest_schema_and_scope_types_are_strict(self):
        value = manifest()
        value["schema_version"] = 2
        with self.assertRaisesRegex(campaign.CampaignError, "schema_version"):
            campaign.validate_manifest(value)
        value = manifest()
        value["scope"]["allow_state_changes"] = "yes"
        with self.assertRaisesRegex(campaign.CampaignError, "must be boolean"):
            campaign.validate_manifest(value)


class CoverageManifestTests(unittest.TestCase):
    def test_coverage_counts_are_separate_and_no_accuracy_is_inferred(self):
        cases = campaign.load_coverage_manifest({"schema_version": 1, "cases": [
            {"id": "case-a", "behavior": "reflected execution", "tool": "web_xss"},
            {"id": "case-b", "behavior": "object ownership"},
            {"id": "case-c", "behavior": "rate limit"},
        ]})
        report = campaign.evaluate_coverage(cases, [
            {"case_id": "case-a", "status": "confirmed", "evidence_review": confirmed_evidence_review()},
            {"case_id": "case-b", "status": "tested_negative"},
            {"case_id": "case-c", "status": "blocked"},
        ])
        self.assertEqual(report["counts"], {"confirmed": 1, "candidate": 0, "tested_negative": 1,
                                             "blocked": 1, "untested": 0, "conflict": 0, "total": 3,
                                             "executed": 2, "execution_coverage_percent": 66.7})
        self.assertIsNone(report["labeled_metrics"])
        self.assertEqual(report["coverage_by_dimension"]["tool"]["web_xss"]["confirmed"], 1)
        self.assertEqual(report["coverage_by_dimension"]["role"]["any"]["tested_negative"], 1)
        self.assertEqual(report["coverage_by_dimension"]["configuration"]["any"]["blocked"], 1)

    def test_candidate_outcome_takes_precedence_over_negative(self):
        cases = campaign.load_coverage_manifest({"schema_version": 1,
                                                  "cases": [{"id": "case-a", "behavior": "x"}]})
        report = campaign.evaluate_coverage(cases, [
            {"case_id": "case-a", "status": "tested_negative"},
            {"case_id": "case-a", "status": "candidate"},
        ])
        self.assertEqual(report["cases"][0]["status"], "candidate")

    def test_unknown_outcomes_do_not_count_as_execution(self):
        cases = campaign.load_coverage_manifest({"schema_version": 1,
                                                  "cases": [{"id": "case-a", "behavior": "x"}]})
        report = campaign.evaluate_coverage(cases, [{"case_id": "case-a", "status": "error"}])
        self.assertEqual(report["counts"]["untested"], 1)
        self.assertEqual(report["counts"]["execution_coverage_percent"], 0)

    def test_invalid_coverage_schema_and_duplicate_ids_are_rejected(self):
        with self.assertRaisesRegex(campaign.CampaignError, "schema_version"):
            campaign.load_coverage_manifest({"schema_version": 2, "cases": []})
        with self.assertRaisesRegex(campaign.CampaignError, "unique"):
            campaign.load_coverage_manifest({"schema_version": 1, "cases": [
                {"id": "same", "behavior": "a"}, {"id": "same", "behavior": "b"}]})

    def test_precision_recall_require_explicit_gold_labels_and_show_unresolved(self):
        case_doc = {"schema_version": 1, "cases": [
            {"id": "tp", "behavior": "vuln", "expected": "vulnerable", "gold_source": "fixture oracle"},
            {"id": "fp", "behavior": "safe", "expected": "not_vulnerable", "gold_source": "fixture oracle"},
            {"id": "fn", "behavior": "miss", "expected": "vulnerable", "gold_source": "fixture oracle"},
            {"id": "tn", "behavior": "safe", "expected": "not_vulnerable", "gold_source": "fixture oracle"},
            {"id": "unresolved", "behavior": "uncertain", "expected": "vulnerable", "gold_source": "fixture oracle"},
        ]}
        cases = campaign.load_coverage_manifest(case_doc)
        results = [{"case_id": "tp", "status": "confirmed", "evidence_review": confirmed_evidence_review()},
                   {"case_id": "fp", "status": "confirmed", "evidence_review": confirmed_evidence_review()},
                   {"case_id": "fn", "status": "tested_negative"},
                   {"case_id": "tn", "status": "tested_negative"},
                   {"case_id": "unresolved", "status": "candidate"}]
        metrics = campaign.evaluate_coverage(cases, results)["labeled_metrics"]
        self.assertEqual(metrics["precision_percent"], 50.0)
        self.assertEqual(metrics["recall_percent"], 50.0)
        self.assertEqual(metrics["unresolved_labeled"], 1)
        self.assertIn("not estimate internet-wide", metrics["scope_note"])

    def test_conflicting_positive_and_negative_records_are_not_counted_as_confirmed(self):
        cases = campaign.load_coverage_manifest({"schema_version": 1,
                                                  "cases": [{"id": "case-a", "behavior": "x"}]})
        report = campaign.evaluate_coverage(cases, [
            {"case_id": "case-a", "status": "confirmed", "evidence_review": confirmed_evidence_review()},
            {"case_id": "case-a", "status": "tested_negative"},
        ])
        self.assertEqual(report["cases"][0]["status"], "conflict")
        self.assertEqual(report["counts"]["confirmed"], 0)

    def test_confirmed_claim_without_complete_evidence_review_is_only_candidate(self):
        cases = campaign.load_coverage_manifest({"schema_version": 1,
                                                  "cases": [{"id": "case-a", "behavior": "x"}]})
        result = campaign.evaluate_coverage(cases, [{"case_id": "case-a", "status": "confirmed"}])
        self.assertEqual(result["cases"][0]["status"], "candidate")

    def test_labeled_case_requires_provenance(self):
        with self.assertRaisesRegex(campaign.CampaignError, "gold_source"):
            campaign.load_coverage_manifest({"schema_version": 1, "cases": [
                {"id": "case-a", "behavior": "x", "expected": "vulnerable"}]})

    def test_coverage_cli_reports_labeled_metrics_and_dimension_gaps(self):
        case_doc = {"schema_version": 1, "cases": [
            {"id": "sqli-vulnerable", "behavior": "error-based SQLi", "tool": "web_sqli",
             "role": "member", "configuration": "fixture-low", "expected": "vulnerable",
             "gold_source": "local fixture oracle"},
            {"id": "sqli-safe", "behavior": "parameterized query", "tool": "web_sqli",
             "role": "anonymous", "configuration": "fixture-low", "expected": "not_vulnerable",
             "gold_source": "local fixture oracle"},
        ]}
        results = [
            {"case_id": "sqli-vulnerable", "status": "confirmed",
             "evidence_review": confirmed_evidence_review()},
            {"case_id": "sqli-safe", "status": "tested_negative"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, results_path, output_path = root / "cases.json", root / "results.json", root / "report.json"
            manifest_path.write_text(json.dumps(case_doc), encoding="utf-8")
            results_path.write_text(json.dumps(results), encoding="utf-8")
            self.assertEqual(campaign.main(["coverage", "--manifest", str(manifest_path),
                                            "--results", str(results_path), "--output", str(output_path)]), 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(report["labeled_metrics"]["precision_percent"], 100.0)
        self.assertEqual(report["labeled_metrics"]["recall_percent"], 100.0)
        self.assertEqual(report["coverage_by_dimension"]["tool"]["web_sqli"]["total"], 2)
        self.assertEqual(report["coverage_by_dimension"]["role"]["member"]["confirmed"], 1)

    def test_cli_plan_writes_validated_plan_without_launching_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "campaign.json", root / "plan.json"
            source.write_text(json.dumps(manifest()), encoding="utf-8")
            self.assertEqual(campaign.main(["plan", "--manifest", str(source), "--output", str(output)]), 0)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["steps"][0]["status"], "planned")

    def test_cli_authorization_evaluates_role_matrix_against_results(self):
        value = manifest()
        value["authorization_matrices"] = [{"target": "app", "objects": [
            {"id": "object-1", "owner_role": "member", "allowed_roles": ["member"]}]}]
        plan = campaign.validate_manifest(value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path, results_path, output_path = root / "plan.json", root / "results.json", root / "out.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            results_path.write_text(json.dumps([{"role": "anonymous", "object_id": "object-1",
                                                "access": "allowed"}]), encoding="utf-8")
            self.assertEqual(campaign.main(["authorization", "--plan", str(plan_path),
                                            "--results", str(results_path), "--output", str(output_path)]), 0)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            case_result = next(row for row in result["cases"] if row["role"] == "anonymous")
            self.assertEqual(case_result["status"], "candidate_violation")

    def test_checked_in_coverage_template_is_valid_but_not_labeled(self):
        template = json.loads((ROOT / "doctrine" / "templates" / "ASSESSMENT_COVERAGE.json")
                              .read_text(encoding="utf-8"))
        cases = campaign.load_coverage_manifest(template)
        self.assertEqual(cases[0]["expected"], "unknown")

    def test_plan_can_attach_sanitized_exact_origin_knowledge_as_advisory(self):
        knowledge_path = ROOT / "scripts" / "target_knowledge.py"
        spec = importlib.util.spec_from_file_location("campaign_test_knowledge", knowledge_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "knowledge.sqlite"
            store = module.KnowledgeStore(db, "fixture-engagement")
            store.observe("https://app.example.test", "technology", "stack",
                          {"technologies": ["fixture-server"]}, "test-fixture", ttl=300)
            plan = campaign.enrich_plan_with_knowledge(campaign.validate_manifest(manifest()),
                                                       db, "fixture-engagement")
            target = plan["targets"][0]
            self.assertEqual(target["knowledge_observations"][0]["value"]["technologies"], ["fixture-server"])
            self.assertIn("context only", target["knowledge_advisory"])
            self.assertEqual(len(plan["steps"]), len(manifest()["steps"]))


if __name__ == "__main__":
    unittest.main()
