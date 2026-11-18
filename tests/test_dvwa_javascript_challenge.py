"""Offline tests for the DVWA client-side JavaScript challenge verifier."""

import importlib.util
from pathlib import Path
import sys
import unittest
from contextlib import contextmanager
from urllib.parse import parse_qs


SCRIPT = Path(__file__).resolve().parents[1] / "skills/webapp-exploit-hunter/scripts/javascript_challenge_tester.py"
SPEC = importlib.util.spec_from_file_location("dvwa_javascript_challenge_tester", SCRIPT)
tester = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tester
sys.path.insert(0, str(SCRIPT.parent))
try:
    SPEC.loader.exec_module(tester)
finally:
    sys.path.remove(str(SCRIPT.parent))


@contextmanager
def patched(obj, name, value):
    original = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


class TestTokenTransforms(unittest.TestCase):
    def test_low_rot13_md5(self):
        self.assertEqual(tester.compute_dvwa_token("low"), "38581812b435834ebf84ebcc2c6424d6")

    def test_medium_reverse_token(self):
        self.assertEqual(tester.compute_dvwa_token("medium"), "XXsseccusXX")

    def test_high_nested_sha256(self):
        self.assertEqual(
            tester.compute_dvwa_token("high"),
            "ec7ef8687050b6fe803867ea696734c67b541dfafb286a0b1239f42ac5b0aa84",
        )

    def test_impossible_has_no_client_challenge(self):
        self.assertIsNone(tester.compute_dvwa_token("impossible"))


class TestChallengeRequest(unittest.TestCase):
    def test_acceptance_requires_well_done_response(self):
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append((method, data, headers))
            if method == "GET":
                return 200, {}, '<input name="phrase"><input name="token">'
            return 200, {}, '<p style="color:red">Well done!</p>'

        with patched(tester, "http_request", fake):
            result = tester.test_dvwa_javascript_challenge(
                "https://dvwa.test/vulnerabilities/javascript/", "security=low; PHPSESSID=demo",
            )
        self.assertTrue(result["validated"])
        post_values = parse_qs(calls[1][1].decode())
        self.assertEqual(post_values["phrase"], ["success"])
        self.assertEqual(post_values["send"], ["Submit"])
        self.assertIn("PHPSESSID=demo", calls[1][2]["Cookie"])

    def test_form_mismatch_is_inconclusive_without_post(self):
        calls = []

        def fake(*args, **kwargs):
            calls.append((args, kwargs))
            return 200, {}, "not the challenge form"

        with patched(tester, "http_request", fake):
            result = tester.test_dvwa_javascript_challenge("https://dvwa.test/challenge", "security=low")
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(len(calls), 1)

    def test_unknown_level_sends_no_requests(self):
        def fail(*_args, **_kwargs):
            raise AssertionError("unexpected HTTP request")

        with patched(tester, "http_request", fail):
            result = tester.test_dvwa_javascript_challenge("https://dvwa.test/challenge", "")
        self.assertEqual(result["status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
