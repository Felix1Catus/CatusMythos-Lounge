"""Offline regression matrix for the API/cloud shared-knowledge integrations."""
import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
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


knowledge = load("v2_target_knowledge", ROOT / "scripts" / "target_knowledge.py")
api = load("v2_api_discovery", ROOT / "skills" / "api-breaker" / "scripts" / "api_discovery.py")
cloud = load("v2_cloud_detector", ROOT / "skills" / "cloud-pivot-finder" / "scripts" / "cloud_detector.py")


class TestApiInventoryCache(unittest.TestCase):
    def test_sanitizes_inventory_and_restores_only_same_origin_paths(self):
        entries = [{
            "url": "https://api.example.test/v1/users", "path": "/v1/users", "status": 401,
            "content_type": "application/json", "api_type": "rest_json", "response_length": 48,
            "auth_required": True, "methods_tested": ["GET"],
            "version_headers": {"x-api-version": "2025-01"}, "body": "private response",
        }]
        safe = api._cacheable_api_inventory(entries)
        self.assertNotIn("url", safe[0])
        self.assertNotIn("body", safe[0])
        restored = api._restore_api_inventory("https://api.example.test", safe)
        self.assertEqual(restored[0]["url"], "https://api.example.test/v1/users")
        self.assertEqual(api._restore_api_inventory("https://api.example.test", [{"path": "//evil.test/x"}]), [])

    def test_query_values_and_empty_results_are_not_cached(self):
        queried = [{"url": "https://api.example.test/?token=secret", "path": "/?token=secret",
                    "status": 200, "api_type": "unknown"}]
        self.assertIsNone(api._cacheable_api_inventory(queried))
        self.assertIsNone(api._cacheable_api_inventory([]))

    def test_header_context_is_hashed_and_isolated(self):
        first = knowledge.digest({"Authorization": "Bearer secret-one"})
        second = knowledge.digest({"Authorization": "Bearer secret-two"})
        self.assertNotEqual(first, second)
        self.assertNotIn("secret-one", first)
        self.assertEqual(len(first), 64)

    def test_inventory_roundtrip_is_engagement_and_ttl_scoped(self):
        class Clock:
            now = 1000

            def __call__(self):
                return self.now

        clock = Clock()
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.KnowledgeStore(Path(directory) / "knowledge.sqlite", "eng-a", clock=clock)
            context = knowledge.digest({"Authorization": "Bearer secret"})
            safe = [{"path": "/v1/users", "status": 200, "api_type": "rest_json"}]
            store.observe("https://api.example.test", "api_inventory", "discovered-endpoints", safe,
                          "api-breaker/api_discovery", ttl=900, context=context, resource="/api")
            self.assertEqual(len(store.query("https://api.example.test", "api_inventory", context=context,
                                             resource="/api")), 1)
            self.assertEqual(store.query("https://api.example.test", "api_inventory", context="other"), [])
            self.assertEqual(knowledge.KnowledgeStore(
                Path(directory) / "knowledge.sqlite", "eng-b", clock=clock
            ).query("https://api.example.test"), [])
            clock.now += 901
            self.assertEqual(store.query("https://api.example.test", "api_inventory"), [])

    def test_refresh_forget_is_narrowly_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.KnowledgeStore(Path(directory) / "knowledge.sqlite", "eng-a")
            store.observe("https://api.example.test", "api_inventory", "discovered-endpoints", [{"path": "/x"}],
                          "fixture", context="auth-a", resource="/api")
            store.observe("https://api.example.test", "api_inventory", "discovered-endpoints", [{"path": "/y"}],
                          "fixture", context="auth-b", resource="/api")
            self.assertEqual(store.forget("https://api.example.test", "api_inventory", "discovered-endpoints",
                                          context="auth-a", resource="/api"), 1)
            self.assertEqual(store.query("https://api.example.test", "api_inventory", context="auth-a"), [])
            self.assertEqual(len(store.query("https://api.example.test", "api_inventory", context="auth-b")), 1)

    def test_api_discovery_main_reuses_then_refreshes_inventory_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "knowledge.sqlite"
            endpoint = {
                "url": "https://api.example.test/v1/users", "path": "/v1/users", "status": 401,
                "content_type": "application/json", "api_type": "rest_json", "response_length": 48,
                "auth_required": True, "methods_tested": ["GET"], "version_headers": {},
            }
            with mock.patch.object(api, "API_PATHS", ["/v1/users"]), \
                 mock.patch.object(api, "probe_path", return_value=endpoint) as probe, \
                 mock.patch.object(api, "discover_script_urls", return_value=[]), \
                 mock.patch.object(api, "discover_from_js", return_value=[]), \
                 mock.patch.object(api, "discover_legacy_versions", return_value=[]), \
                 mock.patch.object(sys, "argv", ["api_discovery.py", "--domain", "https://api.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--output", str(root / "first.json")]):
                api.main()
            self.assertEqual(probe.call_count, 1)

            with mock.patch.object(api, "API_PATHS", ["/v1/users"]), \
                 mock.patch.object(api, "probe_path", side_effect=AssertionError("fresh path probe")), \
                 mock.patch.object(api, "discover_script_urls", side_effect=AssertionError("fresh JS fetch")), \
                 mock.patch.object(api, "discover_legacy_versions", return_value=[]), \
                 mock.patch.object(sys, "argv", ["api_discovery.py", "--domain", "https://api.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--output", str(root / "cached.json")]):
                api.main()
            cached_output = __import__("json").loads((root / "cached.json").read_text(encoding="utf-8"))
            self.assertTrue(cached_output["meta"]["knowledge_reused_api_inventory"])
            self.assertEqual(cached_output["stats"]["paths_tested"], 0)

            with mock.patch.object(api, "API_PATHS", ["/v1/users"]), \
                 mock.patch.object(api, "probe_path", return_value=endpoint) as refreshed_probe, \
                 mock.patch.object(api, "discover_script_urls", return_value=[]), \
                 mock.patch.object(api, "discover_from_js", return_value=[]), \
                 mock.patch.object(api, "discover_legacy_versions", return_value=[]), \
                 mock.patch.object(sys, "argv", ["api_discovery.py", "--domain", "https://api.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--knowledge-refresh", "--output", str(root / "refresh.json")]):
                api.main()
            self.assertEqual(refreshed_probe.call_count, 1)


class TestCloudProviderCache(unittest.TestCase):
    def test_positive_observation_strips_resolved_ip_and_marks_reuse(self):
        live = {
            "hostname": "app.example.test", "ip": "192.0.2.10",
            "providers_detected": ["AWS"],
            "cloud_services": [
                {"type": "ip_whois", "ip": "192.0.2.10", "provider": "AWS"},
                {"type": "header", "hostname": "app.example.test", "provider": "AWS", "header_match": "x-amz-"},
            ],
        }
        safe = cloud._cloud_observation(live)
        self.assertNotIn("ip", safe)
        self.assertNotIn("192.0.2.10", str(safe))
        restored = cloud._restore_cloud_observation("app.example.test", safe)
        self.assertIsNone(restored["ip"])
        self.assertTrue(restored["knowledge_reused"])
        self.assertEqual(restored["providers_detected"], ["AWS"])

    def test_empty_provider_result_is_never_cached(self):
        self.assertIsNone(cloud._cloud_observation({"providers_detected": [], "cloud_services": []}))

    def test_hostname_context_rejects_urls_and_paths(self):
        self.assertEqual(cloud._knowledge_target("app.example.test"), "https://app.example.test/")
        with self.assertRaises(ValueError):
            cloud._knowledge_target("https://app.example.test/path")

    def test_cloud_observation_roundtrip_and_refresh_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = knowledge.KnowledgeStore(Path(directory) / "knowledge.sqlite", "eng-a")
            target = cloud._knowledge_target("app.example.test")
            value = {"providers_detected": ["GCP"], "cloud_services": [{"type": "header", "provider": "GCP"}]}
            store.observe(target, "cloud_provider", "provider-detection", value,
                          "cloud-pivot-finder/cloud_detector", ttl=3600, resource="/")
            rows = store.query(target, "cloud_provider", key="provider-detection", resource="/")
            self.assertEqual(cloud._restore_cloud_observation("app.example.test", rows[0]["value"])["providers_detected"],
                             ["GCP"])
            self.assertEqual(store.forget(target, "cloud_provider", "provider-detection", resource="/"), 1)
            self.assertEqual(store.query(target, "cloud_provider"), [])

    def test_cloud_detector_main_reuses_and_refreshes_positive_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "knowledge.sqlite"
            result = {
                "hostname": "app.example.test", "ip": "192.0.2.10",
                "providers_detected": ["AWS"],
                "cloud_services": [{"type": "ip_whois", "ip": "192.0.2.10", "provider": "AWS"}],
            }
            with mock.patch.object(cloud, "analyze_host", return_value=result) as analyze, \
                 mock.patch.object(sys, "argv", ["cloud_detector.py", "--domain", "app.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--output", str(root / "first.json")]):
                cloud.main()
            self.assertEqual(analyze.call_count, 1)

            with mock.patch.object(cloud, "analyze_host", side_effect=AssertionError("fresh cloud probe")), \
                 mock.patch.object(sys, "argv", ["cloud_detector.py", "--domain", "app.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--output", str(root / "cached.json")]):
                cloud.main()
            cached_output = __import__("json").loads((root / "cached.json").read_text(encoding="utf-8"))
            self.assertEqual(cached_output["meta"]["knowledge_reused_hosts"], 1)
            self.assertIsNone(cached_output["results"][0]["ip"])

            with mock.patch.object(cloud, "analyze_host", return_value=result) as refreshed, \
                 mock.patch.object(sys, "argv", ["cloud_detector.py", "--domain", "app.example.test",
                                                  "--knowledge-db", str(db), "--engagement", "eng-a",
                                                  "--knowledge-refresh", "--output", str(root / "refresh.json")]):
                cloud.main()
            self.assertEqual(refreshed.call_count, 1)


if __name__ == "__main__":
    unittest.main()
