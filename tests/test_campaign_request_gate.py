"""Regression matrix for campaign-gated standalone scanner requests."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_assessment_campaign import campaign

ROOT = Path(__file__).resolve().parents[1]


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body>fixture</body></html>")

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, _format, *_args):
        pass


def _manifest(origin, max_requests=60):
    return {
        "schema_version": 1,
        "engagement": "campaign-gate-fixture",
        "scope": {"origins": [origin], "request_budget": max_requests,
                  "network_endpoints": [
                      {"host": "127.0.0.1", "protocol": "tcp", "ports": [int(origin.rsplit(":", 1)[1])]},
                      {"host": "127.0.0.1", "protocol": "udp", "ports": [53]},
                  ]},
        "targets": [{"id": "fixture", "url": origin + "/", "roles": [{"name": "anonymous"}]}],
        "steps": [{"id": "crawl", "tool": "web_crawl", "target": "fixture",
                   "max_requests": max_requests}],
    }


class CampaignRequestGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:{}".format(self.server.server_port)
        self.manifest = _manifest(self.origin)
        self.database = self.root / "campaign.sqlite"
        self.ledger = campaign.CampaignLedger(self.database, "gate-fixture")
        self.ledger.bind(self.manifest)
        self.ledger.start_step("crawl")
        self.status = self.root / "gate-status.json"
        self._old_env = {key: os.environ.get(key) for key in (
            "CATUS_CAMPAIGN_GATE_DB", "CATUS_CAMPAIGN_GATE_CAMPAIGN",
            "CATUS_CAMPAIGN_GATE_STEP", "CATUS_CAMPAIGN_GATE_ORIGIN",
            "CATUS_CAMPAIGN_GATE_STATUS")}
        self._configure_gate()

    def tearDown(self):
        self._restore_environment()
        self.ledger.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def _configure_gate(self):
        os.environ.update({
            "CATUS_CAMPAIGN_GATE_DB": str(self.database),
            "CATUS_CAMPAIGN_GATE_CAMPAIGN": "gate-fixture",
            "CATUS_CAMPAIGN_GATE_STEP": "crawl",
            "CATUS_CAMPAIGN_GATE_ORIGIN": self.origin,
            "CATUS_CAMPAIGN_GATE_STATUS": str(self.status),
        })

    def _restore_environment(self):
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _gate_module(self):
        import importlib.util
        path = ROOT / "scripts" / "campaign_request_gate.py"
        spec = importlib.util.spec_from_file_location("campaign_request_gate_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_gate_charges_only_allowed_origin_without_persisting_url(self):
        gate = self._gate_module()
        gate.reserve_from_environment(self.origin + "/private?token=not-recorded", "GET")
        state = self.ledger.summary()
        self.assertEqual(state["requests_used"], 1)
        self.assertEqual(state["steps"][0]["requests_used"], 1)
        events = self.ledger.connection.execute(
            "SELECT event FROM campaign_events WHERE campaign_id=?", ("gate-fixture",)).fetchall()
        self.assertIn(("request_reserved",), events)
        event_text = json.dumps(events)
        self.assertNotIn("private", event_text)
        self.assertNotIn("token", event_text)

    def test_gate_refuses_off_origin_and_records_only_a_status_flag(self):
        gate = self._gate_module()
        with self.assertRaisesRegex(gate.CampaignGateError, "off-origin"):
            gate.reserve_from_environment("http://127.0.0.1:1/elsewhere", "GET")
        self.assertEqual(self.ledger.summary()["requests_used"], 0)
        self.assertTrue(json.loads(self.status.read_text(encoding="utf-8"))["off_origin_requests_blocked"])

    def test_gate_enforces_registered_step_ceiling(self):
        gate = self._gate_module()
        for index in range(60):
            gate.reserve_from_environment(self.origin + "/{}".format(index), "GET")
        with self.assertRaisesRegex(gate.CampaignGateError, "budget exhausted"):
            gate.reserve_from_environment(self.origin + "/overflow", "GET")
        self.assertEqual(self.ledger.summary()["requests_used"], 60)
        self.assertTrue(json.loads(self.status.read_text(encoding="utf-8"))["budget_exhausted"])

    def test_socket_probe_and_curl_are_metered_but_unadapted_network_binaries_fail_closed(self):
        gate = self._gate_module()
        gate.reserve_socket_from_environment("127.0.0.1", self.server.server_port)
        self.assertEqual(self.ledger.summary()["requests_used"], 1)
        gate.reserve_external_command_from_environment(["curl", self.origin + "/one"])
        self.assertEqual(self.ledger.summary()["requests_used"], 2)
        with self.assertRaisesRegex(gate.CampaignGateError, "redirects"):
            gate.reserve_external_command_from_environment(["curl", "-L", self.origin + "/redirect"])
        with self.assertRaisesRegex(gate.CampaignGateError, "retries"):
            gate.reserve_external_command_from_environment(
                ["curl", "--retry", "4", self.origin + "/retry"])
        with self.assertRaisesRegex(gate.CampaignGateError, "globbing"):
            gate.reserve_external_command_from_environment(["curl", self.origin + "/item/{1,2}"])
        safe_nmap = gate.reserve_external_command_from_environment(
            ["nmap", "-p", str(self.server.server_port), "127.0.0.1"])
        self.assertEqual(safe_nmap[1:5], ["-sT", "-Pn", "-n", "--max-retries"])
        self.assertEqual(self.ledger.summary()["requests_used"], 3)
        with self.assertRaisesRegex(gate.CampaignGateError, "out-of-scope network endpoint"):
            gate.reserve_external_command_from_environment(["nmap", "-p", "9000", "127.0.0.1"])
        with self.assertRaisesRegex(gate.CampaignGateError, "one scoped hostname"):
            gate.reserve_external_command_from_environment(["dig", "CNAME", "127.0.0.1"])
        safe_dig = gate.reserve_external_command_from_environment(
            ["dig", "CNAME", "127.0.0.1", "@127.0.0.1", "+short"])
        self.assertIn("+tries=1", safe_dig)
        self.assertIn("+time=3", safe_dig)
        self.assertEqual(self.ledger.summary()["requests_used"], 4)
        with self.assertRaisesRegex(gate.CampaignGateError, "one scoped hostname"):
            gate.reserve_external_command_from_environment(
                ["dig", "CNAME", "127.0.0.1", "TXT", "@127.0.0.1"])
        with self.assertRaisesRegex(gate.CampaignGateError, "whois adapter is unavailable"):
            gate.reserve_external_command_from_environment(["whois", "127.0.0.1"])

    def test_python_child_blocks_external_network_binary_before_launch(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "scripts") + os.pathsep + env.get("PYTHONPATH", "")
        code = (
            "import subprocess; "
            "from campaign_request_gate import CampaignGateError; "
            "try_run = False; "
            "\ntry:\n subprocess.run(['nmap','--top-ports','100','127.0.0.1'])"
            "\nexcept CampaignGateError:\n try_run = True\n"
            "assert try_run"
        )
        result = subprocess.run([sys.executable, "-c", code], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_common_transport_counts_same_origin_redirects(self):
        import importlib.util
        common_path = ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "_common.py"
        spec = importlib.util.spec_from_file_location("campaign_gate_web_common", common_path)
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        script_root = str(ROOT / "scripts")
        sys.path.insert(0, script_root)
        try:
            with common.scoped_urlopen(self.origin + "/redirect") as response:
                self.assertEqual(response.status, 200)
        finally:
            sys.path.remove(script_root)
        self.assertEqual(self.ledger.summary()["requests_used"], 2)

    def test_existing_registry_schema_is_migrated_and_ceiling_bound(self):
        legacy = self.root / "legacy.sqlite"
        connection = sqlite3.connect(legacy)
        connection.execute("CREATE TABLE campaign_step_registry (campaign_id TEXT NOT NULL, "
                           "step_id TEXT NOT NULL, tool TEXT NOT NULL, "
                           "PRIMARY KEY (campaign_id, step_id))")
        connection.commit()
        connection.close()
        ledger = campaign.CampaignLedger(legacy, "legacy-gate")
        try:
            ledger.bind(self.manifest)
            value = ledger.connection.execute(
                "SELECT max_requests FROM campaign_step_registry WHERE campaign_id=? AND step_id=?",
                ("legacy-gate", "crawl")).fetchone()[0]
            self.assertEqual(value, 60)
        finally:
            ledger.close()

    def test_registered_cli_uses_the_common_transport_gate_end_to_end(self):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        output_path = self.root / "crawl.json"
        self._restore_environment()
        self.ledger.finish_step("crawl", "failed")
        result = campaign.main([
            "run-cli", "--manifest", str(manifest_path), "--step", "crawl",
            "--confirm-target", self.origin, "--state-db", str(self.database),
            "--campaign-id", "gate-fixture", "--retry-interrupted", "--", "--target", self.origin,
            "--depth", "0", "--max-pages", "1", "--output", str(output_path),
        ])
        self.assertEqual(result, 0)
        self.assertTrue(output_path.is_file())
        state = self.ledger.summary()
        self.assertGreater(state["requests_used"], 0)
        self.assertLessEqual(state["requests_used"], 60)
        self.assertEqual(state["steps"][0]["status"], "completed")

    def test_cloud_cli_campaign_mode_uses_only_the_scoped_http_probe(self):
        manifest = _manifest(self.origin, max_requests=1)
        manifest["steps"][0].update({"id": "cloud", "tool": "cloud_detector"})
        database = self.root / "cloud.sqlite"
        ledger = campaign.CampaignLedger(database, "cloud-fixture")
        ledger.bind(manifest)
        manifest_path = self.root / "cloud-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        output_path = self.root / "cloud.json"
        self._restore_environment()
        try:
            result = campaign.main([
                "run-cli", "--manifest", str(manifest_path), "--step", "cloud",
                "--confirm-target", self.origin, "--state-db", str(database),
                "--campaign-id", "cloud-fixture", "--", "--domain", "127.0.0.1",
                "--output", str(output_path),
            ])
            self.assertEqual(result, 0)
            self.assertEqual(ledger.summary()["requests_used"], 1)
            self.assertEqual(ledger.summary()["steps"][0]["status"], "completed")
        finally:
            ledger.close()

    def test_run_external_executes_metered_curl_against_loopback(self):
        if not shutil.which("curl"):
            self.skipTest("curl executable is unavailable")
        manifest = _manifest(self.origin, max_requests=2)
        manifest["steps"][0].update({"id": "external", "tool": "external_probe"})
        database = self.root / "external.sqlite"
        manifest_path = self.root / "external-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self._restore_environment()
        result = campaign.main([
            "run-external", "--manifest", str(manifest_path), "--step", "external",
            "--confirm-target", self.origin, "--state-db", str(database),
            "--campaign-id", "external-fixture", "--", "curl", "--silent", self.origin + "/",
        ])
        self.assertEqual(result, 0)
        ledger = campaign.CampaignLedger(database, "external-fixture")
        try:
            self.assertEqual(ledger.summary()["requests_used"], 1)
            self.assertEqual(ledger.summary()["steps"][0]["status"], "completed")
        finally:
            ledger.close()

    def test_api_authz_registered_cli_requires_and_uses_campaign_gate(self):
        manifest = _manifest(self.origin, max_requests=100)
        manifest["scope"]["request_budget"] = 100
        manifest["steps"][0].update({"id": "authz", "tool": "api_authz", "max_requests": 100})
        database = self.root / "authz.sqlite"
        ledger = campaign.CampaignLedger(database, "authz-cli-fixture")
        ledger.bind(manifest)
        manifest_path = self.root / "authz-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        output_path = self.root / "authz.json"
        self._restore_environment()
        try:
            result = campaign.main([
                "run-cli", "--manifest", str(manifest_path), "--step", "authz",
                "--confirm-target", self.origin, "--state-db", str(database),
                "--campaign-id", "authz-cli-fixture", "--", "--api-base", self.origin,
                "--token", "fixture-token", "--output", str(output_path),
            ])
            self.assertEqual(result, 0)
            self.assertEqual(ledger.summary()["requests_used"], 68)
            self.assertEqual(ledger.summary()["steps"][0]["status"], "completed")
            self.assertTrue(output_path.is_file())
        finally:
            ledger.close()

    def test_direct_http_client_adapters_reserve_each_request(self):
        import importlib.util

        script_root = str(ROOT / "scripts")
        sys.path.insert(0, script_root)
        loaded = []
        try:
            specs = [
                ("gate_cache_direct", ROOT / "skills" / "web-cache-auditor" / "scripts" / "cache_audit.py"),
                ("gate_dom_direct", ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "dom_xss_auditor.py"),
                ("gate_prompt_direct", ROOT / "skills" / "16-ai-llm-security" / "scripts" / "prompt_injection_tester.py"),
                ("gate_rag_direct", ROOT / "skills" / "16-ai-llm-security" / "scripts" / "rag_security_tester.py"),
                ("gate_consumption_direct", ROOT / "skills" / "16-ai-llm-security" / "scripts" / "unbounded_consumption_tester.py"),
                ("gate_mcp_direct", ROOT / "skills" / "16-ai-llm-security" / "scripts" / "mcp_security_tester.py"),
            ]
            for name, path in specs:
                spec = importlib.util.spec_from_file_location(name, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                loaded.append(module)
            if any(getattr(module, "requests", None) is None for module in loaded[2:]):
                self.skipTest("optional requests dependency is needed for direct-client gate coverage")

            loaded[0].request_get(self.origin + "/cache")
            loaded[1].fetch_text(self.origin + "/document")
            loaded[2].send(self.origin + "/llm", "message", "probe", {}, "", timeout=2)
            loaded[3]._post(self.origin + "/rag", {}, {}, 2)
            loaded[4]._post(self.origin + "/usage", {}, {}, 2)
            loaded[5].send_jsonrpc(self.origin + "/mcp", "tools/list", {}, {}, 2)
            self.assertEqual(self.ledger.summary()["requests_used"], 6)
        finally:
            sys.path.remove(script_root)

    def test_registered_authz_cli_rejects_mutation_mode(self):
        manifest = _manifest(self.origin, max_requests=100)
        manifest["scope"]["request_budget"] = 100
        manifest["steps"][0].update({"id": "authz", "tool": "api_authz", "max_requests": 100})
        manifest_path = self.root / "authz-mutation.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(SystemExit) as error:
            campaign.main([
                "run-cli", "--manifest", str(manifest_path), "--step", "authz",
                "--confirm-target", self.origin, "--state-db", str(self.root / "reject.sqlite"),
                "--campaign-id", "reject-mutation", "--", "--api-base", self.origin,
                "--token", "fixture-token", "--allow-mutation-write",
            ])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
