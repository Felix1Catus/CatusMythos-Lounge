"""Regression tests for improvement #6: automatic, bounded WAF-bypass
escalation from sqli_tester.py/xss_tester.py into waf_bypass_tester.py's
own differential tests, via the new shared
skills/webapp-exploit-hunter/scripts/_waf_escalation.py helper.

Covers, offline/mocked only (no real sockets -- every network touch goes
through either a monkeypatched module-global ``http_request`` or an
injected fake ``waf_bypass_module`` stand-in for waf_bypass_tester.py):

- ``classify_block()``: rate limiting vs. attack filtering vs. neither,
  including the documented rate-limit-takes-precedence tie-break and the
  transport-failure (status 0) case.
- ``run_bounded_escalation()``: the fixed probe budget (never exceeds the
  requested budget, drops the second sub-test rather than truncating the
  first), the empty-param/zero-budget short circuits, and the metadata
  (``origin``/``auto_escalated_from``/``param``/``method``/``note``) added
  to each returned finding without clobbering fields the finding already
  has.
- ``EscalationTracker``: duplicate-escalation suppression per (url, param)
  and the running probe/escalation tally.
- A static recursion guard: waf_bypass_tester.py must never import this
  helper, since the call graph is strictly one-directional.
- End-to-end integration in ``sqli_tester.test_error_based`` and
  ``xss_tester.test_xss_payloads``: an attack-filter block with nothing
  confirmed triggers exactly one bounded escalation; a bare rate-limit
  block (429) never does, even though it still looks "blocked" for the
  pre-existing mutation-retry/in-category-bypass triggers (which are left
  completely unchanged); escalation is budget-off (0) by default at the
  function level, so every pre-existing caller/test is unaffected; a
  shared tracker prevents a second escalation on the same (url, param).
"""

import importlib.util
import sys
import threading
import unittest
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts"


def load_script(name, filename):
    """Load a scripts/*.py file as a fresh module, with the scripts
    directory temporarily on sys.path so its sibling imports (_common,
    _waf_escalation, waf_bypass_tester) resolve -- same technique, and the
    same "_common" pop/restore discipline, as
    tests/test_webapp_legacy_testers.py's own loader (duplicated here so
    this file stays self-contained). The pop/restore matters because
    "_common" is the same bare module name every pipeline skill's own
    byte-synced _common.py copy uses; without it, a module cached here
    could otherwise leak into another skill's test file loaded later in
    the same pytest process."""
    path = SCRIPTS / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
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


waf_escalation = load_script("weh_waf_escalation", "_waf_escalation.py")
sqli = load_script("weh_sqli_tester_wafesc", "sqli_tester.py")
xss = load_script("weh_xss_tester_wafesc", "xss_tester.py")


@contextmanager
def patched(module, attr, value):
    sentinel = object()
    original = getattr(module, attr, sentinel)
    setattr(module, attr, value)
    try:
        yield
    finally:
        if original is sentinel:
            delattr(module, attr)
        else:
            setattr(module, attr, original)


class FakeWafBypassModule:
    """Stand-in for waf_bypass_tester.py: records calls instead of making
    any real HTTP request, and returns canned findings shaped like that
    module's real ones (no "param"/"method"/"origin" keys -- those are
    exactly what run_bounded_escalation() is responsible for adding)."""

    def __init__(self, pollution_findings=None, inspection_findings=None):
        self.pollution_calls = []
        self.inspection_calls = []
        self._pollution_findings = pollution_findings if pollution_findings is not None else [
            {"type": "wafbypass_parameter_pollution", "url": "https://t.test/", "parameter": "q",
             "severity": "MEDIUM", "evidence": "fake pollution evidence", "poc_curl": "curl -- fake"},
        ]
        self._inspection_findings = inspection_findings if inspection_findings is not None else []

    def test_parameter_pollution(self, base_url, param, headers=None):
        self.pollution_calls.append((base_url, param, headers))
        return [dict(f) for f in self._pollution_findings]

    def test_inspection_size_limit(self, base_url, param, max_padding=8192, step=512, headers=None):
        self.inspection_calls.append((base_url, param, max_padding, step, headers))
        return [dict(f) for f in self._inspection_findings]


# ---------------------------------------------------------------------------
# classify_block
# ---------------------------------------------------------------------------
class TestClassifyBlock(unittest.TestCase):
    def test_429_is_rate_limit(self):
        self.assertEqual(waf_escalation.classify_block(429, ""), "rate_limit")

    def test_retry_after_header_is_rate_limit_regardless_of_status(self):
        self.assertEqual(
            waf_escalation.classify_block(503, "service unavailable", {"Retry-After": "30"}),
            "rate_limit")

    def test_retry_after_header_case_insensitive_key(self):
        self.assertEqual(
            waf_escalation.classify_block(200, "ok", {"retry-after": "5"}),
            "rate_limit")

    def test_body_phrase_is_rate_limit(self):
        self.assertEqual(waf_escalation.classify_block(200, "Too Many Requests, slow down"), "rate_limit")

    def test_403_is_attack_filter(self):
        self.assertEqual(waf_escalation.classify_block(403, "Access Denied"), "attack_filter")

    def test_406_is_attack_filter(self):
        self.assertEqual(waf_escalation.classify_block(406, ""), "attack_filter")

    def test_block_body_signature_is_attack_filter(self):
        self.assertEqual(waf_escalation.classify_block(200, "Request blocked by mod_security"), "attack_filter")

    def test_ordinary_response_is_none(self):
        self.assertIsNone(waf_escalation.classify_block(200, "welcome to the site"))

    def test_transport_failure_is_none(self):
        # A failed connection is not evidence of either kind of block --
        # escalating on it would just waste probe budget on a target that
        # may simply be unreachable.
        self.assertIsNone(waf_escalation.classify_block(0, "Connection refused"))

    def test_rate_limit_takes_precedence_over_attack_filter_body(self):
        # Some WAFs render one page for both; the documented precedence is
        # rate-limit first, since escalating WAF-bypass probes at an
        # already-rate-limited target is actively counterproductive.
        body = "403 Forbidden -- Access Denied: too many requests, please slow down"
        self.assertEqual(waf_escalation.classify_block(403, body), "rate_limit")

    def test_none_body_and_headers_do_not_crash(self):
        self.assertIsNone(waf_escalation.classify_block(200, None, None))


# ---------------------------------------------------------------------------
# run_bounded_escalation
# ---------------------------------------------------------------------------
class TestRunBoundedEscalation(unittest.TestCase):
    def test_zero_budget_makes_no_calls(self):
        fake = FakeWafBypassModule()
        findings, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=0, waf_bypass_module=fake)
        self.assertEqual(findings, [])
        self.assertEqual(probes_used, 0)
        self.assertEqual(fake.pollution_calls, [])
        self.assertEqual(fake.inspection_calls, [])

    def test_negative_budget_treated_as_zero(self):
        fake = FakeWafBypassModule()
        findings, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=-5, waf_bypass_module=fake)
        self.assertEqual((findings, probes_used), ([], 0))

    def test_empty_param_makes_no_calls(self):
        fake = FakeWafBypassModule()
        findings, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "", source="test", budget=10, waf_bypass_module=fake)
        self.assertEqual((findings, probes_used), ([], 0))
        self.assertEqual(fake.pollution_calls, [])

    def test_budget_two_runs_only_parameter_pollution(self):
        fake = FakeWafBypassModule()
        findings, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=2, waf_bypass_module=fake)
        self.assertEqual(probes_used, 2)
        self.assertEqual(len(fake.pollution_calls), 1)
        self.assertEqual(fake.inspection_calls, [])  # dropped, not truncated into
        self.assertTrue(findings)

    def test_budget_four_runs_both_bounded_tests(self):
        fake = FakeWafBypassModule()
        findings, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=waf_escalation.DEFAULT_PROBE_BUDGET,
            waf_bypass_module=fake)
        self.assertEqual(probes_used, 4)
        self.assertEqual(fake.pollution_calls, [("https://t.test/?q=1", "q", None)])
        self.assertEqual(len(fake.inspection_calls), 1)
        base_url, param, max_padding, step, headers = fake.inspection_calls[0]
        self.assertIsNone(headers)
        self.assertEqual((base_url, param), ("https://t.test/?q=1", "q"))
        # Pinning max_padding == step caps the real inspection test at
        # exactly one padded attempt (2 requests worst case) instead of an
        # open-ended sweep.
        self.assertEqual(max_padding, step)

    def test_budget_never_exceeded_even_with_surplus(self):
        fake = FakeWafBypassModule()
        _, probes_used = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=99, waf_bypass_module=fake)
        self.assertLessEqual(probes_used, 99)
        self.assertEqual(probes_used, 4)  # still the fixed, bounded total

    def test_findings_are_tagged_without_clobbering_existing_fields(self):
        fake = FakeWafBypassModule(pollution_findings=[
            {"type": "wafbypass_parameter_pollution", "url": "https://t.test/", "parameter": "q",
             "severity": "MEDIUM", "evidence": "e", "poc_curl": "curl -- keep-me",
             "param": "already-set", "method": "ALREADY-SET"},
        ])
        findings, _ = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="sqli_tester:test_error_based", budget=2, waf_bypass_module=fake)
        f = findings[0]
        self.assertEqual(f["origin"], "auto_waf_escalation")
        self.assertEqual(f["auto_escalated_from"], "sqli_tester:test_error_based")
        self.assertIn("sqli_tester:test_error_based", f["note"])
        self.assertIn("not the original injection payload", f["note"])
        # setdefault semantics: existing param/method must survive untouched.
        self.assertEqual(f["param"], "already-set")
        self.assertEqual(f["method"], "ALREADY-SET")
        # poc_curl from waf_bypass_tester's own finding must be preserved.
        self.assertEqual(f["poc_curl"], "curl -- keep-me")

    def test_findings_get_param_method_defaults_when_absent(self):
        fake = FakeWafBypassModule()  # default pollution finding has no param/method keys
        findings, _ = waf_escalation.run_bounded_escalation(
            "https://t.test/?q=1", "q", source="test", budget=2, waf_bypass_module=fake)
        self.assertEqual(findings[0]["param"], "q")
        self.assertEqual(findings[0]["method"], "GET")

    def test_injected_module_bypasses_the_real_lazy_loader(self):
        """Confirms the injection seam actually prevents touching the real
        waf_bypass_tester.py (and therefore the network) when a caller
        supplies waf_bypass_module -- this is what every other test in this
        file (and the sqli/xss integration tests below) relies on to stay
        offline."""
        def boom():
            raise AssertionError("the real waf_bypass_tester loader must not run when a module is injected")

        fake = FakeWafBypassModule()
        with patched(waf_escalation, "_load_waf_bypass_tester", boom):
            findings, probes_used = waf_escalation.run_bounded_escalation(
                "https://t.test/?q=1", "q", source="test", budget=4, waf_bypass_module=fake)
        self.assertTrue(findings)
        self.assertEqual(probes_used, 4)


# ---------------------------------------------------------------------------
# EscalationTracker
# ---------------------------------------------------------------------------
class TestEscalationTracker(unittest.TestCase):
    def test_should_escalate_true_initially(self):
        tracker = waf_escalation.EscalationTracker()
        self.assertTrue(tracker.should_escalate("https://t.test/", "q"))

    def test_record_escalation_suppresses_the_same_pair(self):
        tracker = waf_escalation.EscalationTracker()
        tracker.record_escalation("https://t.test/", "q", 4)
        self.assertFalse(tracker.should_escalate("https://t.test/", "q"))

    def test_different_pairs_are_independent(self):
        tracker = waf_escalation.EscalationTracker()
        tracker.record_escalation("https://t.test/", "q", 4)
        self.assertTrue(tracker.should_escalate("https://t.test/", "other_param"))
        self.assertTrue(tracker.should_escalate("https://other.test/", "q"))

    def test_counts_accumulate(self):
        tracker = waf_escalation.EscalationTracker()
        tracker.record_escalation("https://t.test/", "q", 4)
        tracker.record_escalation("https://t.test/", "r", 2)
        self.assertEqual(tracker.escalation_count, 2)
        self.assertEqual(tracker.total_probes_used, 6)

    def test_record_with_zero_probes_still_marks_seen(self):
        # A budget-exhausted or nothing-found escalation attempt must still
        # count as "already escalated" for this pair -- otherwise a caller
        # could retry it every time through a loop.
        tracker = waf_escalation.EscalationTracker()
        tracker.record_escalation("https://t.test/", "q", 0)
        self.assertFalse(tracker.should_escalate("https://t.test/", "q"))
        self.assertEqual(tracker.escalation_count, 1)
        self.assertEqual(tracker.total_probes_used, 0)


# ---------------------------------------------------------------------------
# Static recursion guard
# ---------------------------------------------------------------------------
class TestNoRecursion(unittest.TestCase):
    def test_waf_bypass_tester_does_not_import_the_escalation_helper(self):
        """The call graph must stay one-directional: sqli_tester.py /
        xss_tester.py -> _waf_escalation.py -> waf_bypass_tester.py. If
        waf_bypass_tester.py ever imported _waf_escalation back, its own
        differential tests could trigger a second round of escalation --
        this is a static source guard against that ever being introduced."""
        source = (SCRIPTS / "waf_bypass_tester.py").read_text(encoding="utf-8")
        self.assertNotIn("_waf_escalation", source)


# ---------------------------------------------------------------------------
# sqli_tester.py integration
# ---------------------------------------------------------------------------
def sqli_fake(status, body, elapsed=0.05, response_headers=None):
    def _fake(url, method="GET", data=None, headers=None, timeout=10):
        return status, response_headers or {}, body, elapsed
    return _fake


class TestSqliAutoEscalationIntegration(unittest.TestCase):
    def test_attack_filter_block_with_no_confirmation_escalates_once(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied")):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["origin"], "auto_waf_escalation")
        self.assertEqual(findings[0]["auto_escalated_from"], "sqli_tester:test_error_based")
        self.assertEqual(tracker.escalation_count, 1)
        self.assertEqual(len(fake_wbt.pollution_calls), 1)

    def test_rate_limit_block_never_escalates(self):
        """A 429 still counts as 'blocked' for the pre-existing
        mutation-retry trigger (_looks_blocked), but must never reach the
        external waf_bypass_tester escalation -- escalating differential
        probes at a rate limiter wastes requests without helping."""
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(sqli, "http_request", sqli_fake(429, "Too Many Requests")):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=1,
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])
        self.assertEqual(fake_wbt.inspection_calls, [])
        self.assertEqual(tracker.escalation_count, 0)

    def test_retry_after_header_prevents_attack_filter_escalation(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied", response_headers={"Retry-After": "30"})):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])
        self.assertEqual(tracker.escalation_count, 0)

    def test_escalation_forwards_auth_headers(self):
        fake_wbt = FakeWafBypassModule()
        auth_headers = {"Authorization": "Bearer local-test"}
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied")):
            sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=2, waf_bypass_module=fake_wbt, extra_headers=auth_headers)
        self.assertEqual(fake_wbt.pollution_calls[0][2], auth_headers)

    def test_post_requests_do_not_run_get_only_differential_tests(self):
        fake_wbt = FakeWafBypassModule()
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied")):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", method="POST", max_mutations=0,
                waf_escalation_budget=4, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])

    def test_disabled_by_default_at_function_level(self):
        """Regression safety: omitting the new kwargs entirely (as every
        pre-existing caller/test does) must behave exactly like before --
        no escalation, no need to even supply a waf_bypass_module."""
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied")):
            findings = sqli.test_error_based("https://t.test/?id=1", "id", "1", max_mutations=0)
        self.assertEqual(findings, [])

    def test_shared_tracker_prevents_duplicate_escalation(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(sqli, "http_request", sqli_fake(403, "Access Denied")):
            first = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
            second = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertTrue(first)
        self.assertEqual(second, [])  # second call for the same (url, param) must not re-escalate
        self.assertEqual(tracker.escalation_count, 1)
        self.assertEqual(len(fake_wbt.pollution_calls), 1)

    def test_confirmed_finding_never_escalates(self):
        """A real confirmed SQLi finding must short-circuit before the
        escalation check is even reached -- escalating on top of an
        already-confirmed finding would be pure noise."""
        calls = {"n": 0}

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls["n"] += 1
            if calls["n"] == 1:
                return 200, {}, "ordinary baseline", 0.05
            return 500, {}, "You have an error in your SQL syntax near 'NULL'", 0.05

        fake_wbt = FakeWafBypassModule()
        with patched(sqli, "http_request", fake):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0,
                waf_escalation_budget=4, waf_bypass_module=fake_wbt)
        self.assertTrue(findings)
        self.assertNotEqual(findings[0].get("origin"), "auto_waf_escalation")
        self.assertEqual(fake_wbt.pollution_calls, [])


# ---------------------------------------------------------------------------
# xss_tester.py integration
# ---------------------------------------------------------------------------
def xss_fake(status, body, response_headers=None):
    def _fake(url, method="GET", data=None, headers=None, timeout=10):
        return status, response_headers or {}, body
    return _fake


class TestXssAutoEscalationIntegration(unittest.TestCase):
    def test_attack_filter_block_with_no_confirmation_escalates_once(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(xss, "http_request", xss_fake(403, "Access Denied")):
            findings = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["origin"], "auto_waf_escalation")
        self.assertEqual(findings[0]["auto_escalated_from"], "xss_tester:test_xss_payloads")
        self.assertEqual(tracker.escalation_count, 1)
        self.assertEqual(len(fake_wbt.pollution_calls), 1)

    def test_rate_limit_block_never_escalates(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(xss, "http_request", xss_fake(429, "Too Many Requests")):
            findings = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])
        self.assertEqual(tracker.escalation_count, 0)

    def test_retry_after_header_prevents_attack_filter_escalation(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(xss, "http_request", xss_fake(
                403, "Access Denied", response_headers={"Retry-After": "30"})):
            findings = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])
        self.assertEqual(tracker.escalation_count, 0)

    def test_escalation_forwards_auth_headers(self):
        fake_wbt = FakeWafBypassModule()
        auth_headers = {"Authorization": "Bearer local-test"}
        with patched(xss, "http_request", xss_fake(403, "Access Denied")):
            xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=2, waf_bypass_module=fake_wbt, extra_headers=auth_headers)
        self.assertEqual(fake_wbt.pollution_calls[0][2], auth_headers)

    def test_post_requests_do_not_run_get_only_differential_tests(self):
        fake_wbt = FakeWafBypassModule()
        with patched(xss, "http_request", xss_fake(403, "Access Denied")):
            findings = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"], method="POST",
                waf_escalation_budget=4, waf_bypass_module=fake_wbt)
        self.assertEqual(findings, [])
        self.assertEqual(fake_wbt.pollution_calls, [])

    def test_disabled_by_default_at_function_level(self):
        with patched(xss, "http_request", xss_fake(403, "Access Denied")):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"])
        self.assertEqual(findings, [])

    def test_shared_tracker_prevents_duplicate_escalation(self):
        fake_wbt = FakeWafBypassModule()
        tracker = waf_escalation.EscalationTracker()
        with patched(xss, "http_request", xss_fake(403, "Access Denied")):
            first = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
            second = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, escalation_tracker=tracker, waf_bypass_module=fake_wbt)
        self.assertTrue(first)
        self.assertEqual(second, [])
        self.assertEqual(tracker.escalation_count, 1)
        self.assertEqual(len(fake_wbt.pollution_calls), 1)

    def test_confirmed_xss_never_escalates(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "<p>echo <script>alert('0r1z0n')</script> more</p>"

        fake_wbt = FakeWafBypassModule()
        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads(
                "https://t.test/?q=1", "q", ["html_body"],
                waf_escalation_budget=4, waf_bypass_module=fake_wbt)
        self.assertTrue(findings)
        self.assertNotEqual(findings[0].get("origin"), "auto_waf_escalation")
        self.assertEqual(fake_wbt.pollution_calls, [])


class TestRealWafBypassLoaderLoopback(unittest.TestCase):
    def test_real_module_loads_and_runs_only_against_loopback(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.request_count += 1
                if self.headers.get("Authorization") != "Bearer loopback-test":
                    self.send_error(401)
                    return
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
                values = query.get("q", [])
                if "filler" in query and any("<script>" in value for value in values):
                    status, body = 200, "script"
                elif len(values) > 1 and "wafbypasstest" in ",".join(values):
                    status, body = 200, "wafbypasstest"
                else:
                    status, body = 403, "Access Denied"
                encoded = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.request_count = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        scripts_path = str(SCRIPTS)
        sys.path.insert(0, scripts_path)
        try:
            base_url = f"http://127.0.0.1:{server.server_port}/"
            findings, probes_used = waf_escalation.run_bounded_escalation(
                base_url, "q", source="loopback-test", budget=4,
                headers={"Authorization": "Bearer loopback-test"})
        finally:
            sys.path.remove(scripts_path)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(probes_used, 4)
        self.assertEqual(server.request_count, 4)
        self.assertEqual(
            {finding["type"] for finding in findings},
            {"wafbypass_parameter_pollution", "wafbypass_inspection_size_limit"},
        )
        self.assertTrue(all(finding["origin"] == "auto_waf_escalation" for finding in findings))


if __name__ == "__main__":
    unittest.main()
