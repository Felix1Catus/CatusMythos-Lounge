"""Local vulnerable-app benchmark for API authorization and workflow discovery."""

import importlib.util
import sys
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_SCRIPTS = ROOT / "skills" / "api-breaker" / "scripts"
WEB_SCRIPTS = ROOT / "skills" / "webapp-exploit-hunter" / "scripts"
FIXTURES = ROOT / "tests" / "fixtures"


def _load(name, path, script_dir):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(script_dir))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
    return module


fixture = _load("assessment_benchmark_fixture", FIXTURES / "assessment_benchmark_app.py", FIXTURES)
authz = _load("assessment_benchmark_authz", API_SCRIPTS / "authz_tester.py", API_SCRIPTS)
workflow = _load("assessment_benchmark_workflow", WEB_SCRIPTS / "workflow_tester.py", WEB_SCRIPTS)


class AssessmentBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = fixture.serve()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:{}".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_n_role_authorization_detects_fixture_bola_and_bfla(self):
        roles = authz.build_role_matrix([("alice", "alice"), ("member", "member"), ("admin", "admin")])
        bola = authz.test_bola_matrix(
            self.base, [{"path": "/api/orders/101", "url": self.base + "/api/orders/101"}],
            roles, delay=0)
        bfla = authz.test_bfla_matrix(self.base, roles, delay=0)
        self.assertTrue(any(item["type"] == "bola" and item["validated"] for item in bola))
        self.assertTrue(any(item["type"] == "bfla_candidate" and item["role"] != "admin"
                            and not item["validated"] for item in bfla))

    def test_browser_observation_handoff_discovers_workflow_skip_candidate(self):
        report = {"pages": [{"url": self.base + "/checkout/start", "forms": [
            {"action": self.base + "/checkout/review", "method": "POST"}]},
            {"url": self.base + "/checkout/review", "forms": [
                {"action": self.base + "/checkout/confirm", "method": "POST"}]}]}
        crawl = workflow.browser_report_to_crawl(report, self.base)
        flows = workflow.discover_workflows(crawl)
        self.assertTrue(flows)
        candidates = [finding for flow in flows for finding in
                      workflow.test_step_skip(flow, delay=0)]
        self.assertTrue(any(item["type"] == "workflow_step_skip_candidate" for item in candidates))


if __name__ == "__main__":
    unittest.main()
