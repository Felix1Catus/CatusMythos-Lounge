"""Regression coverage for richer observations and portable offline bundles."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop("_common", None)
        if old_common is not None:
            sys.modules["_common"] = old_common
    return module


kb = load("target_knowledge_v2", ROOT / "scripts" / "target_knowledge.py")
authz = load("target_knowledge_authz", ROOT / "skills" / "api-breaker" / "scripts" / "authz_tester.py")
rate = load("target_knowledge_rate", ROOT / "skills" / "api-breaker" / "scripts" / "rate_limiter.py")
idor = load("target_knowledge_idor", ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "idor_tester.py")


class KnowledgeV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "knowledge.sqlite"
        self.store = kb.KnowledgeStore(self.db, "engagement-a", clock=lambda: 1000.0)
        self.url = "https://api.example.test/v1/items/1"

    def test_auth_observations_record_role_and_status_without_credentials(self):
        context = self.store.record_auth_outcome(
            self.url, "viewer", 403, {"Authorization": "Bearer secret-token"}, "fixture")
        rows = self.store.query(self.url, "auth", resource="/v1/items/1")
        self.assertEqual(rows[0]["context"], context)
        self.assertEqual(rows[0]["value"], {"role": "viewer", "status": 403, "outcome": "denied"})
        self.assertNotIn(b"secret-token", self.db.read_bytes())
        self.assertNotEqual(context, kb.digest({"Authorization": "Bearer another-token"}))

    def test_rate_limit_observations_normalize_only_allowlisted_headers(self):
        self.store.record_rate_limit(
            self.url, "GET", {"200": 3, "429": 1},
            {"Retry-After": "5", "X-RateLimit-Remaining": "0", "Set-Cookie": "secret"},
            requests_sent=4, delay=0.25, auth_headers={"Cookie": "secret-cookie"}, source="fixture")
        row = self.store.query(self.url, "rate_limit", resource="/v1/items/1")[0]
        self.assertTrue(row["value"]["rate_limit_observed"])
        self.assertEqual(row["value"]["headers"], {
            "retry_after_seconds": 5.0, "x-ratelimit-remaining": 0,
        })
        raw = self.db.read_bytes()
        self.assertNotIn(b"secret-cookie", raw)
        self.assertNotIn(b"secret\"", raw)

    def test_auth_role_and_context_are_required_and_scoped(self):
        with self.assertRaises(ValueError):
            self.store.record_auth_outcome(self.url, "", 401)
        self.store.record_auth_outcome(self.url, "viewer", 401, {"Cookie": "a"}, "fixture")
        self.assertEqual(self.store.query(self.url, "auth", context=kb.digest({"Cookie": "b"})), [])

    def test_rate_limit_rejects_unbounded_or_malformed_summary(self):
        for status_codes in [{"429": -1}, {"9999": 1}, {"200": True}]:
            with self.subTest(status_codes=status_codes), self.assertRaises(ValueError):
                self.store.record_rate_limit(self.url, "GET", status_codes)

    def test_bundle_roundtrip_preserves_origin_engagement_provenance_and_expiry(self):
        self.store.record_auth_outcome(self.url, "viewer", 401, {"Authorization": "secret"}, "authz")
        self.store.record_rate_limit(self.url, "GET", {"429": 1}, {"Retry-After": "4"},
                                     requests_sent=10, delay=0, source="rate-test")
        bundle = self.store.export_bundle(self.url)
        clone = kb.KnowledgeStore(Path(self.temp.name) / "clone.sqlite", "engagement-a", clock=lambda: 1000.0)
        self.assertEqual(clone.import_bundle(bundle, self.url), 2)
        self.assertEqual(len(clone.query(self.url, "auth")), 1)
        imported_rate = clone.query(self.url, "rate_limit")[0]
        self.assertEqual(imported_rate["source"], "rate-test")
        self.assertEqual(imported_rate["expires_at"], 1900.0)

    def test_bundle_rejects_wrong_engagement_origin_expired_or_unsafe_rows(self):
        self.store.record_auth_outcome(self.url, "viewer", 401, {}, "authz")
        bundle = self.store.export_bundle(self.url)
        other_engagement = kb.KnowledgeStore(Path(self.temp.name) / "other.sqlite", "other")
        with self.assertRaisesRegex(ValueError, "engagement"):
            other_engagement.import_bundle(bundle, self.url)
        with self.assertRaisesRegex(ValueError, "origin"):
            self.store.import_bundle(bundle, "https://other.example.test/")
        tampered = json.loads(json.dumps(bundle))
        tampered["observations"][0]["value"] = {"token": "do-not-import"}
        with self.assertRaisesRegex(ValueError, "not allowed"):
            self.store.import_bundle(tampered, self.url)
        self.store.record_rate_limit(self.url, "GET", {"200": 1}, source="rate")
        malformed_rate = self.store.export_bundle(self.url)
        rate_row = next(row for row in malformed_rate["observations"] if row["kind"] == "rate_limit")
        rate_row["value"]["status_codes"] = {"9999": 1}
        isolated = kb.KnowledgeStore(Path(self.temp.name) / "isolated.sqlite", "engagement-a", clock=lambda: 1000.0)
        with self.assertRaisesRegex(ValueError, "not allowed"):
            isolated.import_bundle(malformed_rate, self.url)
        self.assertEqual(isolated.query(self.url), [])
        expired = json.loads(json.dumps(bundle))
        expired["observations"][0]["expires_at"] = 999
        self.assertEqual(other_engagement.import_bundle({**expired, "engagement": "other"}, self.url), 0)

    def test_bundle_import_does_not_replace_a_newer_local_observation(self):
        old = kb.KnowledgeStore(Path(self.temp.name) / "old.sqlite", "engagement-a", clock=lambda: 1000.0)
        old.record_auth_outcome(self.url, "viewer", 401, {"Authorization": "same"}, "old-source")
        bundle = old.export_bundle(self.url)
        current = kb.KnowledgeStore(Path(self.temp.name) / "current.sqlite", "engagement-a", clock=lambda: 1001.0)
        current.record_auth_outcome(self.url, "viewer", 403, {"Authorization": "same"}, "new-source")
        self.assertEqual(current.import_bundle(bundle, self.url), 0)
        row = current.query(self.url, "auth")[0]
        self.assertEqual(row["value"]["status"], 403)
        self.assertEqual(row["source"], "new-source")

    def test_bundle_cli_exports_and_imports_offline(self):
        self.store.clock = time.time
        self.store.record_auth_outcome(self.url, "viewer", 403, {}, "fixture")
        bundle_path = Path(self.temp.name) / "knowledge.json"
        db2 = Path(self.temp.name) / "second.sqlite"
        flags = ["--engagement", "engagement-a", "--target", self.url]
        exported = __import__("subprocess").run(
            [sys.executable, str(ROOT / "scripts" / "target_knowledge.py"), "--db", str(self.db),
             *flags, "--export", str(bundle_path)], capture_output=True, text=True, timeout=15)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        imported = __import__("subprocess").run(
            [sys.executable, str(ROOT / "scripts" / "target_knowledge.py"), "--db", str(db2),
             *flags, "--import", str(bundle_path)], capture_output=True, text=True, timeout=15)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(json.loads(imported.stdout)["imported"], 1)

    def test_authz_cli_publishes_n_role_observations(self):
        output = Path(self.temp.name) / "authz.json"
        endpoints = Path(self.temp.name) / "api.json"
        endpoints.write_text(json.dumps({"endpoints": [{"url": self.url, "path": "/v1/items/1"}]}), encoding="utf-8")
        args = ["authz_tester.py", "--input", str(endpoints), "--api-base", "https://api.example.test", "--role", "viewer:token-a",
                "--role", "admin:token-b", "--knowledge-db", str(self.db), "--engagement", "engagement-a",
                "--output", str(output)]
        with mock.patch.object(authz, "http_request", return_value=(401, {}, "")), \
             mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
            authz.main()
        roles = {row["value"]["role"] for row in self.store.query("https://api.example.test", "auth")}
        self.assertEqual(roles, {"viewer", "admin"})
        self.assertNotIn(b"token-a", self.db.read_bytes())

    def test_rate_limiter_cli_publishes_normalized_results(self):
        output = Path(self.temp.name) / "rate.json"
        args = ["rate_limiter.py", "--api-base", "https://api.example.test", "--endpoint", "/v1/items/1",
                "--count", "4", "--knowledge-db", str(self.db), "--engagement", "engagement-a",
                "--output", str(output)]
        result = {"total_sent": 4, "status_codes": {"200": 3, "429": 1},
                  "rate_limit_observed": True, "rate_limited_at": 4,
                  "rate_limit_headers": {"Retry-After": "3", "Set-Cookie": "secret"},
                  "response_times": []}
        with mock.patch.object(rate, "send_rapid_requests", return_value=result), \
             mock.patch.object(rate, "test_rate_limit_bypass", return_value=[]), \
             mock.patch.object(rate, "test_path_mutation_bypass", return_value=[]), \
             mock.patch.object(rate, "http_request", return_value=(404, {}, "")), \
             mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
            rate.main()
        rows = self.store.query("https://api.example.test/v1/items/1", "rate_limit")
        self.assertEqual(rows[0]["value"]["headers"]["retry_after_seconds"], 3.0)
        self.assertNotIn(b"secret\"", self.db.read_bytes())

    def test_idor_consumes_matching_auth_context_for_reporting_without_skipping_probes(self):
        self.store.clock = time.time
        headers = {"Authorization": "Bearer user-token"}
        self.store.record_auth_outcome(self.url, "viewer", 403, headers, "authz")
        endpoints = Path(self.temp.name) / "endpoints.json"
        endpoints.write_text(json.dumps([{"url": self.url, "param": "id", "id": "1"}]), encoding="utf-8")
        output = Path(self.temp.name) / "idor.json"
        args = ["idor_tester.py", "--endpoints", str(endpoints), "--header", "Authorization: Bearer user-token",
                "--skip-methods", "--skip-vertical", "--knowledge-db", str(self.db),
                "--engagement", "engagement-a", "--output", str(output)]
        with mock.patch.object(idor, "http_request", return_value=(403, {}, "denied")) as request, \
             mock.patch.object(idor, "generate_test_ids", return_value=[]), \
             mock.patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
            idor.main()
        rendered = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(len(rendered["target_knowledge"]), 1)
        self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
