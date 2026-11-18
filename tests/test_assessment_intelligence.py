"""Regression matrix for app-observation reuse and test prioritization."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "assessment_intelligence", ROOT / "scripts" / "assessment_intelligence.py")
intelligence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intelligence)


class AssessmentIntelligenceTests(unittest.TestCase):
    def test_crawler_api_and_browser_routes_merge_and_drop_off_origin_secrets(self):
        document = {
            "endpoints": [{"url": "https://app.example.test/orders?token=secret", "method": "GET"},
                          {"url": "https://evil.example.test/steal", "method": "POST"}],
            "discovered_apis": [{"url": "https://app.example.test/api/orders", "method": "GET",
                                 "status": 200, "auth_required": True}],
            "pages": [{"url": "https://app.example.test/checkout", "forms": [
                {"action": "https://app.example.test/orders", "method": "POST"}],
                "links": ["https://app.example.test/orders"]}],
        }
        rows = intelligence.normalize_observations(document, "https://app.example.test")
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(set(by_path), {"/orders", "/api/orders", "/checkout"})
        self.assertEqual(by_path["/orders"]["methods_tested"], ["GET", "POST"])
        self.assertTrue(by_path["/api/orders"]["auth_required"])
        self.assertNotIn("secret", str(rows))

    def test_normalizer_uses_effective_port_and_rejects_bad_shapes(self):
        rows = intelligence.normalize_observations(
            {"endpoints": [{"url": "https://app.example.test:443/a"}]},
            "https://app.example.test")
        self.assertEqual(rows[0]["path"], "/a")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            intelligence.normalize_observations([], "https://app.example.test")

    def test_prioritization_puts_stateful_authz_candidates_first_and_never_drops_unresolved(self):
        cases = [
            {"id": "static", "preconditions": [], "expected_evidence": []},
            {"id": "state-auth", "preconditions": ["role owner workflow state"],
             "expected_evidence": ["unauthorized object access"]},
            {"id": "done", "preconditions": [], "expected_evidence": []},
        ]
        rows = intelligence.prioritize_cases(cases, [
            {"case_id": "state-auth", "status": "candidate"},
            {"case_id": "done", "status": "tested_negative"},
        ])
        self.assertEqual([row["case_id"] for row in rows], ["state-auth", "static"])
        self.assertEqual(rows[0]["priority"], 100)

    def test_knowledge_cli_ingests_saved_browser_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "browser.json"
            source.write_text(json.dumps({"pages": [{"url": "https://app.example.test/cart",
                                                       "forms": [{"action": "https://app.example.test/cart",
                                                                  "method": "POST"}], "links": []}]}),
                              encoding="utf-8")
            database = root / "knowledge.sqlite"
            result = subprocess.run([
                sys.executable, str(ROOT / "scripts" / "target_knowledge.py"),
                "--db", str(database), "--engagement", "fixture", "--target",
                "https://app.example.test", "--ingest", str(source),
            ], capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"ingested": 1', result.stdout)


if __name__ == "__main__":
    unittest.main()
