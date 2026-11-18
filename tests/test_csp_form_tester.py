"""Offline regression tests for the mocked CSP script-source probe."""

import importlib.util
from pathlib import Path
import sys
import unittest
import urllib.parse


SCRIPT = Path(__file__).resolve().parents[1] / "skills/webapp-exploit-hunter/scripts/csp_form_tester.py"
SPEC = importlib.util.spec_from_file_location("weh_csp_form_tester", SCRIPT)
tester = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tester
sys.path.insert(0, str(SCRIPT.parent))
try:
    SPEC.loader.exec_module(tester)
finally:
    sys.path.remove(str(SCRIPT.parent))


class TestCspSourceSelection(unittest.TestCase):
    def test_origin_rejects_credentials_and_invalid_port(self):
        self.assertIsNone(tester.origin("https://user:pass@app.example.test/page"))
        self.assertIsNone(tester.origin("https://app.example.test:bad/page"))

    def test_selects_explicit_external_host(self):
        selected = tester.select_allowlisted_script_url(
            "script-src 'self' https://cdn.example.test/library/ 'unsafe-inline'",
            "https://app.example.test/page",
            "proof-1",
        )
        self.assertEqual(
            selected,
            "https://cdn.example.test/library/__catus_csp_canary__.js?proof-1",
        )

    def test_falls_back_to_default_src(self):
        selected = tester.select_allowlisted_script_url(
            "default-src 'self' https://trusted.example.test",
            "https://app.example.test/page",
        )
        self.assertEqual(urllib.parse.urlsplit(selected).hostname, "trusted.example.test")

    def test_does_not_test_self_only_policy(self):
        self.assertIsNone(tester.select_allowlisted_script_url(
            "script-src 'self'", "https://app.example.test/page",
        ))

    def test_does_not_treat_target_origin_as_external_source(self):
        self.assertIsNone(tester.select_allowlisted_script_url(
            "script-src 'self' https://app.example.test",
            "https://app.example.test/page",
        ))

    def test_invalid_target_is_rejected(self):
        self.assertIsNone(tester.select_allowlisted_script_url("script-src *", "file:///tmp/x"))
if __name__ == "__main__":
    unittest.main()
