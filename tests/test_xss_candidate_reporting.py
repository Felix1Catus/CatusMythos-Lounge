import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
WEBAPP_SCRIPTS = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts"
sys.path.insert(0, str(WEBAPP_SCRIPTS))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


xss_tester = load_module("xss_tester_for_tests", WEBAPP_SCRIPTS / "xss_tester.py")
IMPORTER_PATH = REPO_ROOT / "skills" / "vuln-chain-composer" / "scripts" / "import_findings.py"
sys.path.insert(0, str(IMPORTER_PATH.parent))
findings_importer = load_module("import_findings_for_tests", IMPORTER_PATH)
generate_poc = load_module("generate_poc_for_redirect_tests", WEBAPP_SCRIPTS / "generate_poc.py")


class XssCandidateReportingTests(unittest.TestCase):
    def test_unescaped_reflection_is_an_unverified_info_candidate(self):
        body = "<html><script>alert('0r1z0n')</script></html>"
        with patch.object(xss_tester, "http_request", return_value=(200, {"Content-Type": "text/html"}, body)):
            findings = xss_tester.test_xss_payloads(
                "https://example.test/search?q=old", "q", ["html_body"]
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "reflected_xss_candidate")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertFalse(findings[0]["validated"])

    def test_candidate_is_not_chainable_before_validation(self):
        candidate = findings_importer.normalize_finding({
            "type": "reflected_xss_candidate",
            "severity": "INFO",
            "confidence": "low",
            "validated": False,
            "url": "https://example.test/search?q=x",
        }, "xss_tester")
        confirmed = findings_importer.normalize_finding({
            "type": "reflected_xss",
            "severity": "HIGH",
            "confidence": "high",
            "validated": True,
            "url": "https://example.test/search?q=x",
        }, "browser_validation")
        self.assertEqual(candidate["chainable_as"], [])
        self.assertEqual(candidate["severity"], "INFO")
        self.assertIn("session_theft", confirmed["chainable_as"])

    def test_static_dom_candidate_defaults_to_info_and_is_not_chainable(self):
        candidate = findings_importer.normalize_finding({
            "type": "dom_xss_candidate",
            "confidence": "low",
        }, "dom_xss_auditor")
        self.assertEqual(candidate["severity"], "INFO")
        self.assertEqual(candidate["chainable_as"], [])

    def test_generated_web_pocs_compile_and_use_scoped_redirects(self):
        finding = {
            "type": "sqli",
            "url": "https://example.test/search?q=x",
            "param": "q",
            "payload": "' OR 1=1 --",
            "method": "GET",
        }
        for generator in (
            generate_poc.generate_script_sqli,
            generate_poc.generate_script_xss,
            generate_poc.generate_script_ssrf,
            generate_poc.generate_script_race,
        ):
            with self.subTest(generator=generator.__name__):
                script = generator(finding)
                compile(script, generator.__name__ + ".py", "exec")
                self.assertIn("ScopedRedirectHandler", script)
                self.assertIn("scoped_urlopen(req", script)
                self.assertNotIn("urllib.request.urlopen(req", script)

    def test_ssrf_poc_replays_only_the_confirmed_payload_and_method(self):
        finding = {
            "url": "https://example.test/fetch?url=old",
            "param": "url",
            "payload": "http://127.0.0.1:8080/health",
            "method": "POST",
        }
        script = generate_poc.generate_script_ssrf(finding)
        compile(script, "ssrf_poc.py", "exec")
        self.assertIn("METHOD = 'POST'", script)
        self.assertIn("PAYLOAD = 'http://127.0.0.1:8080/health'", script)
        self.assertNotIn("169.254.169.254", script)
        self.assertNotIn("file:///etc/passwd", script)


if __name__ == "__main__":
    unittest.main()
