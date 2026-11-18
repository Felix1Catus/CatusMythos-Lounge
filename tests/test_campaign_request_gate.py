"""Regression matrix for campaign-gated standalone scanner requests."""

import json
import os
import sqlite3
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

    def log_message(self, _format, *_args):
        pass


def _manifest(origin, max_requests=60):
    return {
        "schema_version": 1,
        "engagement": "campaign-gate-fixture",
        "scope": {"origins": [origin], "request_budget": max_requests},
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


if __name__ == "__main__":
    unittest.main()
