"""Regression tests for webapp-exploit-hunter's legacy active testers.

HANDOVER listed these as "targeted fixes only, no full per-script test
matrix": ssrf, ssti, race, idor, waf_bypass, lfi, upload, and xss testers
(plus the pure helpers of auth/sqli, which have only targeted coverage in
test_targeted_audit_fixes.py). This matrix locks their detection logic
offline -- every network-touching function is exercised through a
monkeypatched module-global ``http_request`` (the ``from _common import``
name each script owns), never a real socket.

One real bug found and fixed this pass:

**race_tester PoC/meta thread-count desync.** ``threads`` was clamped to
``max(2, min(args.threads, 50))`` for the actual burst, but the PoC-generation
loop reassigned ``threads = args.threads``, so a ``--threads 500`` run tested
with 50 while emitting an xargs/xargs -P 500 PoC (and meta) claiming 500 --
the reproduction did not match what was tested. Fixed via a pure
``_clamp_threads()`` used for both.
"""
import base64
import importlib.util
import json
import random
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts"


def load_script(name, filename):
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


ssrf = load_script("weh_ssrf_tester", "ssrf_tester.py")
ssti = load_script("weh_ssti_tester", "ssti_tester.py")
race = load_script("weh_race_tester", "race_tester.py")
idor = load_script("weh_idor_tester", "idor_tester.py")
waf = load_script("weh_waf_bypass_tester", "waf_bypass_tester.py")
lfi = load_script("weh_lfi_tester", "lfi_tester.py")
upload = load_script("weh_upload_tester", "upload_tester.py")
xss = load_script("weh_xss_tester", "xss_tester.py")
auth = load_script("weh_auth_tester", "auth_tester.py")
sqli = load_script("weh_sqli_tester", "sqli_tester.py")


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


def resp3(status=200, body="", headers=None):
    """3-tuple responder for scripts importing http_request."""
    headers = headers or {}
    def _fake(url, method="GET", data=None, headers=None, timeout=10):
        return status, headers, body
    return _fake


def resp4(status=200, body="", headers=None):
    """4-tuple responder for scripts importing http_request_timed."""
    headers = headers or {}
    def _fake(url, method="GET", data=None, headers=None, timeout=10):
        return status, headers, body, 0.1
    return _fake


# ---------------------------------------------------------------------------
# race_tester
# ---------------------------------------------------------------------------
class TestRaceClampThreads(unittest.TestCase):
    def test_lower_bound_is_two(self):
        self.assertEqual(race._clamp_threads(1), 2)
        self.assertEqual(race._clamp_threads(0), 2)

    def test_upper_bound_is_fifty(self):
        self.assertEqual(race._clamp_threads(500), 50)
        self.assertEqual(race._clamp_threads(51), 50)

    def test_in_range_unchanged(self):
        for n in (2, 20, 50):
            self.assertEqual(race._clamp_threads(n), n)


class TestRaceAnalyze(unittest.TestCase):
    def _cfg(self, name="double_spend"):
        return race.SCENARIOS[name]

    def test_multiple_successes_is_vulnerable(self):
        results = [{"status": 200, "body": "a", "body_length": 1, "elapsed": 0.1},
                   {"status": 200, "body": "a", "body_length": 1, "elapsed": 0.1},
                   {"status": 409, "body": "dup", "body_length": 3, "elapsed": 0.1}]
        analysis = race.analyze_results(results, self._cfg())
        self.assertTrue(analysis["is_vulnerable"])
        self.assertEqual(analysis["successful_responses"], 2)

    def test_single_success_not_vulnerable(self):
        results = [{"status": 200, "body": "a", "body_length": 1, "elapsed": 0.1},
                   {"status": 409, "body": "d", "body_length": 1, "elapsed": 0.1},
                   {"status": 409, "body": "d", "body_length": 1, "elapsed": 0.1}]
        self.assertFalse(race.analyze_results(results, self._cfg())["is_vulnerable"])

    def test_all_success_no_rejections_is_vulnerable(self):
        results = [{"status": 200, "body": "x", "body_length": 1, "elapsed": 0.1} for _ in range(4)]
        analysis = race.analyze_results(results, self._cfg())
        self.assertTrue(analysis["is_vulnerable"])
        self.assertTrue(any("lacks concurrency control" in e for e in analysis["evidence"]))

    def test_unique_bodies_flagged_even_without_expect_single(self):
        cfg = race.SCENARIOS["file_toctou"]  # expect_single_success: False
        results = [{"status": 200, "body": "one", "body_length": 3, "elapsed": 0.1},
                   {"status": 200, "body": "two", "body_length": 3, "elapsed": 0.1}]
        analysis = race.analyze_results(results, cfg)
        self.assertTrue(analysis["is_vulnerable"])
        self.assertTrue(any("inconsistencies" in e for e in analysis["evidence"]))

    def test_status_distribution(self):
        results = [{"status": 200, "body": "", "body_length": 0, "elapsed": 0},
                   {"status": 200, "body": "", "body_length": 0, "elapsed": 0},
                   {"status": 429, "body": "", "body_length": 0, "elapsed": 0}]
        self.assertEqual(race._status_distribution(results), {"200": 2, "429": 1})

    def test_scenarios_have_required_keys(self):
        for name, cfg in race.SCENARIOS.items():
            for key in ("description", "severity", "success_codes", "fail_codes",
                        "expect_single_success"):
                self.assertIn(key, cfg, name)


class TestRaceSendParallel(unittest.TestCase):
    def test_results_sorted_by_index(self):
        seen = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            seen.append(url)
            return 200, {}, "ok", 0.05

        with patched(race, "http_request", fake):
            results = race.send_parallel_requests("https://t.test/x", "GET", None, {}, 4)
        self.assertEqual([r["index"] for r in results], [0, 1, 2, 3])
        self.assertTrue(all(r["status"] == 200 for r in results))


# ---------------------------------------------------------------------------
# idor_tester
# ---------------------------------------------------------------------------
class TestIdorPure(unittest.TestCase):
    def test_detect_id_type(self):
        self.assertEqual(idor.detect_id_type("12345"), "numeric")
        self.assertEqual(idor.detect_id_type("550e8400-e29b-41d4-a716-446655440000"), "uuid")
        self.assertEqual(idor.detect_id_type("deadbeefdeadbeef"), "hex")
        self.assertEqual(idor.detect_id_type("my-account"), "slug")

    def test_generate_test_ids_numeric(self):
        ids = idor.generate_test_ids("100", "numeric")
        values = [v for _cat, v in ids]
        self.assertIn("101", values)
        self.assertIn("99", values)
        cats = {cat for cat, _v in ids}
        self.assertIn("encoding_base64", cats)
        self.assertIn("encoding_hex", cats)

    def test_generate_test_ids_uuid_modifies_last_segment(self):
        original = "550e8400-e29b-41d4-a716-446655440000"
        ids = idor.generate_test_ids(original, "uuid")
        prefixes = {v.rsplit("-", 1)[0] for _c, v in ids}
        self.assertEqual(prefixes, {"550e8400-e29b-41d4-a716"})
        self.assertNotIn(original, [v for _c, v in ids])

    def test_generate_test_ids_slug(self):
        values = [v for _c, v in idor.generate_test_ids("my-account", "slug")]
        self.assertIn("admin", values)

    def test_replace_id_in_url_query(self):
        out = idor.replace_id_in_url("https://t.test/api?user_id=5&x=1", "user_id", "6")
        self.assertIn("user_id=6", out)
        self.assertIn("x=1", out)

    def test_replace_id_in_url_path_marker(self):
        out = idor.replace_id_in_url("https://t.test/api/users/123", "path:123", "456")
        self.assertEqual(out, "https://t.test/api/users/456")

    def test_replace_id_in_url_no_match_returns_none(self):
        self.assertIsNone(idor.replace_id_in_url("https://t.test/api", "missing", "1"))


class TestIdorHorizontal(unittest.TestCase):
    def test_different_200_body_flagged(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "user_id=101" in url or "user_id=99" in url:
                return 200, {}, '{"name": "Someone Else", "email": "other@test.test"}'
            return 200, {}, '{"name": "My Account", "email": "me@test.test"}'

        with patched(idor, "http_request", fake):
            findings = idor.test_horizontal_idor(
                "https://t.test/api?user_id=100", "user_id", "100", "numeric", delay=0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "idor_candidate")
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertFalse(findings[0]["validated"])

    def test_error_page_body_not_flagged(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            # Non-digit user_id values are the base64/hex encoding probes,
            # which the tester flags on ANY 200 -- return 403 so the only
            # 200s carry the error-page body under test.
            import urllib.parse as _up
            qs = _up.parse_qs(_up.urlparse(url).query)
            val = qs.get("user_id", [""])[0]
            if not val.isdigit():
                return 403, {}, "Forbidden"
            return 200, {}, '{"error": "not found: this user does not exist"}'

        with patched(idor, "http_request", fake):
            findings = idor.test_horizontal_idor(
                "https://t.test/api?user_id=100", "user_id", "100", "numeric", delay=0)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ssrf_tester
# ---------------------------------------------------------------------------
class TestSsrf(unittest.TestCase):
    def test_is_ssrf_param(self):
        self.assertTrue(ssrf.is_ssrf_param("URL"))
        self.assertTrue(ssrf.is_ssrf_param("callback"))
        self.assertFalse(ssrf.is_ssrf_param("username"))

    def test_metadata_hit_is_critical(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "169.254.169.254" in url:
                return 200, {}, '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}'
            return 200, {}, "normal page"

        with patched(ssrf, "http_request", fake):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertTrue(findings)
        meta = [f for f in findings if "metadata" in f["category"]]
        self.assertTrue(meta)
        self.assertEqual(meta[0]["severity"], "CRITICAL")

    def test_no_indicators_no_findings(self):
        with patched(ssrf, "http_request", resp3(200, "nothing interesting here")):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertEqual(findings, [])

    def test_ordinary_html_baseline_is_not_a_false_positive(self):
        """Regression: SSRF_SUCCESS_PATTERNS["localhost"] includes a bare
        r"<html" -- present in virtually every real page. Before the fix,
        EVERY tested parameter against an ordinary site was flagged as
        SSRF the moment any payload's response (identical to the baseline)
        was checked, since the pattern-match path never excluded anything
        already present in the baseline."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "<html><body>Welcome to our ordinary site</body></html>"

        with patched(ssrf, "http_request", fake):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertEqual(findings, [])

    def test_indicator_absent_from_baseline_still_confirms(self):
        """The fix must not suppress genuine findings -- a leak that is
        NEW relative to the baseline must still be reported."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "169.254.169.254" in url:
                return 200, {}, "<html>AccessKeyId leaked here</html>"
            return 200, {}, "<html>ordinary baseline page</html>"

        with patched(ssrf, "http_request", fake):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertTrue(findings)
        self.assertTrue(findings[0]["confirmed_against_baseline"])

    def test_detect_ssrf_indicators_returns_every_hit(self):
        hits = ssrf.detect_ssrf_indicators("AccessKeyId and <title>Welcome</title> present")
        categories = {h["category"] for h in hits}
        self.assertIn("cloud_metadata", categories)
        self.assertIn("localhost", categories)

    def test_echoed_metadata_path_is_not_ssrf_proof(self):
        import urllib.parse

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            payload = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("url", [""])[0]
            return 200, {}, f"<html><body>{payload}</body></html>"

        with patched(ssrf, "http_request", fake):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertEqual(findings, [])

    def test_body_size_difference_is_only_an_unverified_candidate(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "127.0.0.1" in url:
                return 200, {}, "response changed " + ("x" * 300)
            return 200, {}, "ordinary baseline"

        with patched(ssrf, "http_request", fake):
            findings = ssrf.test_ssrf("https://t.test/fetch?url=x", "url", delay=0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "ssrf_candidate")
        self.assertFalse(findings[0]["validated"])


# ---------------------------------------------------------------------------
# ssti_tester
# ---------------------------------------------------------------------------
class TestSsti(unittest.TestCase):
    def test_reflection_detected(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "<html><body>value: ssti0r1z0ntest</body></html>"

        with patched(ssti, "http_request", fake):
            self.assertTrue(ssti.test_reflection("https://t.test/?q=1", "q"))

    def test_no_reflection(self):
        with patched(ssti, "http_request", resp3(200, "<html>static</html>")):
            self.assertFalse(ssti.test_reflection("https://t.test/?q=1", "q"))

    def test_engine_fingerprint_jinja(self):
        import urllib.parse

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            value = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("q", [""])[0]
            if "CATUSdeadbeefcafeA" in value:
                return 200, {}, "result: CATUSdeadbeefcafeA49ZdeadbeefcafeEND"
            return 200, {}, "nope"

        with patched(ssti, "http_request", fake), patched(ssti.secrets, "token_hex", lambda _n: "deadbeefcafe"):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["engine_detected"], "Jinja2")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_reflected_template_expression_is_not_execution(self):
        import urllib.parse

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            value = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("q", [""])[0]
            return 200, {}, f"<main>{value}</main>"

        with patched(ssti, "http_request", fake), patched(ssti.secrets, "token_hex", lambda _n: "deadbeefcafe"):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertEqual(findings, [])

    def test_engine_error_message_also_confirms(self):
        # Baseline (the plain, unmodified GET -- queried exactly once, with
        # the URL untouched) must be clean; only a payload-bearing request
        # returns the engine error, so the finding reflects something the
        # PAYLOAD caused, not a page that always shows this error.
        target = "https://t.test/?q=1"

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if url == target:
                return 200, {}, "<html>ordinary baseline page</html>"
            return 500, {}, "jinja2.exceptions.TemplateSyntaxError: unexpected char"

        with patched(ssti, "http_request", fake):
            findings = ssti.fingerprint_engine(target, "q", delay=0)
        self.assertTrue(findings)

    def test_error_already_in_baseline_is_not_confirmed(self):
        """Regression for the fix: a page that returns the SAME engine
        error for every request (including the unmodified baseline) must
        NOT be reported -- nothing distinguishes the payload's effect from
        the page's own static behavior."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 500, {}, "jinja2.exceptions.TemplateSyntaxError: unexpected char"

        with patched(ssti, "http_request", fake):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertEqual(findings, [])

    def test_expected_output_already_on_baseline_page_not_confirmed(self):
        """Regression for the fix: MATH_MARKER "49" (the {{7*7}} expected
        output) appearing on the UNMODIFIED page for an unrelated reason
        (a price, an age) must not be reported as SSTI."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "<html>Price: $49.99 today only</html>"

        with patched(ssti, "http_request", fake):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertEqual(findings, [])

    def test_polyglot_no_signal(self):
        # Body deliberately avoids every engine-name substring ("erb" hides
        # inside ordinary words like "verbatim", so pick words carefully).
        with patched(ssti, "http_request", resp3(200, "input shown back, nothing changed")):
            hit, _body = ssti.test_polyglot("https://t.test/?q=1", "q")
        self.assertFalse(hit)


# ---------------------------------------------------------------------------
# waf_bypass_tester
# ---------------------------------------------------------------------------
class TestWafPure(unittest.TestCase):
    def test_looks_blocked_by_status(self):
        self.assertTrue(waf._looks_blocked(403, ""))
        self.assertTrue(waf._looks_blocked(429, ""))
        self.assertFalse(waf._looks_blocked(200, ""))
        self.assertFalse(waf._looks_blocked(0, "anything"))  # transport error != blocked

    def test_looks_blocked_by_body(self):
        self.assertTrue(waf._looks_blocked(200, "Request Blocked by Cloudflare"))
        self.assertFalse(waf._looks_blocked(200, "normal page"))

    def test_passed_and_reconstructed(self):
        self.assertTrue(waf._looks_passed_and_reconstructed(200, "reflected wafbypasstest(1)", ["wafbypasstest"]))
        # Blocked variant is never a pass.
        self.assertFalse(waf._looks_passed_and_reconstructed(403, "wafbypasstest", ["wafbypasstest"]))
        # Unreflected 200 is not a pass either.
        self.assertFalse(waf._looks_passed_and_reconstructed(200, "unrelated", ["wafbypasstest"]))


class TestWafParameterPollution(unittest.TestCase):
    def test_differential_fires_only_on_blocked_baseline(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            # quote() leaves "/" unescaped in the encoded trigger.
            if url.endswith("q=%3Cscript%3Ewafbypasstest%281%29%3C/script%3E"):
                return 403, {}, "Access Denied"
            if "wafbypasstest" in url:
                return 200, {}, "echo wafbypasstest(1) back"
            return 200, {}, "home"

        with patched(waf, "http_request", fake):
            findings = waf.test_parameter_pollution("https://t.test/page", "q")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "wafbypass_parameter_pollution")

    def test_unblocked_baseline_no_finding(self):
        with patched(waf, "http_request", resp3(200, "all fine")):
            self.assertEqual(waf.test_parameter_pollution("https://t.test/page", "q"), [])


# ---------------------------------------------------------------------------
# lfi_tester
# ---------------------------------------------------------------------------
class TestLfiPure(unittest.TestCase):
    def test_is_lfi_param(self):
        self.assertTrue(lfi.is_lfi_param("template"))
        self.assertFalse(lfi.is_lfi_param("quantity"))

    def test_extract_referenced_path(self):
        body = '{"meme_path": "../data/memes/abc.txt"}'
        self.assertEqual(lfi._extract_referenced_path(body), "../data/memes/abc.txt")
        self.assertIsNone(lfi._extract_referenced_path("plain text"))

    def test_parse_proc_net_tcp(self):
        content = (
            "  sl  local_address rem_address   st tx_queue rx_queue\n"
            "   0: 0100007F:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0\n"
            "   1: 0100007F:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0\n"
            "   2: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0\n"
        )
        targets = lfi.parse_proc_net_tcp(content)
        # '0100007F:0539' -> 127.0.0.1:1337; port-0 line skipped; dup deduped.
        self.assertEqual(targets, [{"ip": "127.0.0.1", "port": 1337}])

    def test_inject_param_get(self):
        url, data = lfi._inject_param("https://t.test/?file=a", "file", "../../../../etc/passwd")
        self.assertIsNone(data)
        # urlencode escapes "/" -- assert on the filename, not the raw path.
        self.assertIn("passwd", url)


class TestLfiTest(unittest.TestCase):
    def test_passwd_read_is_critical(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "passwd" in url:  # urlencode escapes the "/" in the payload
                return 200, {}, "root:x:0:0:root:/root:/bin/sh\n"
            return 200, {}, "file not found"

        with patched(lfi, "http_request", fake):
            findings = lfi.test_lfi("https://t.test/?file=x", "file", delay=0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "lfi")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["target_file"], "etc/passwd")

    def test_no_read_no_finding(self):
        with patched(lfi, "http_request", resp3(200, "file not found")):
            self.assertEqual(lfi.test_lfi("https://t.test/?file=x", "file", delay=0), [])


# ---------------------------------------------------------------------------
# upload_tester
# ---------------------------------------------------------------------------
class TestUploadMultipart(unittest.TestCase):
    def test_body_contains_filename_field_and_content(self):
        body, boundary = upload.build_multipart_body("shell.php", "<?php echo 1; ?>",
                                                     "image/jpeg", "avatar")
        self.assertIn(b'filename="shell.php"', body)
        self.assertIn(b'name="avatar"', body)
        self.assertIn(b"Content-Type: image/jpeg", body)
        self.assertIn(b'<?php echo 1; ?>', body)
        self.assertTrue(body.startswith(f"--{boundary}".encode()))

    def test_extract_upload_path_json_and_location(self):
        paths = upload.extract_upload_path('{"url": "/uploads/x.php"}', {})
        self.assertEqual(paths, ["/uploads/x.php"])
        paths = upload.extract_upload_path("ok", {"Location": "/files/y.php"})
        self.assertEqual(paths, ["/files/y.php"])


class TestUploadCheckExecution(unittest.TestCase):
    _BASE = "https://t.test/upload"

    def test_executed(self):
        with patched(upload, "http_request", resp4(200, "pre ORIZON_UPLOAD_TEST post")):
            executed, url = upload.check_execution(self._BASE, ["/uploads/x.php"], {})
        self.assertTrue(executed)
        self.assertEqual(url, "https://t.test/uploads/x.php")

    def test_accessible_but_not_executed(self):
        with patched(upload, "http_request", resp4(200, 'raw "<?php ORIZON_UPLOAD_TEST ?>"')):
            executed, _url = upload.check_execution(self._BASE, ["/uploads/x.php"], {})
        self.assertIs(executed, False)

    def test_not_found_returns_none(self):
        with patched(upload, "http_request", resp4(404, "gone")):
            executed, url = upload.check_execution(self._BASE, ["/uploads/x.php"], {})
        self.assertIsNone(executed)
        self.assertIsNone(url)


class TestUploadFastcgi(unittest.TestCase):
    def test_record_header_round_trip(self):
        record = upload._fcgi_record(upload._FCGI_PARAMS, 7, b"abc")  # 3 bytes -> 5 padding
        self.assertEqual(record[0], 1)  # version
        self.assertEqual(record[1], upload._FCGI_PARAMS)
        self.assertEqual(record[2:4], b"\x00\x07")  # request id
        clen = int.from_bytes(record[4:6], "big")
        plen = record[6]
        self.assertEqual(clen, 3)
        self.assertEqual(plen, 5)
        self.assertEqual(len(record), 8 + clen + plen)

    def test_name_value_short_lengths(self):
        nv = upload._fcgi_name_value("AB", "CDE")
        self.assertEqual(nv, b"\x02\x03ABC DE".replace(b" ", b""))  # 2,3,"AB","CDE"

    def test_name_value_long_length_uses_4byte_form(self):
        nv = upload._fcgi_name_value("K" * 200, "V")
        self.assertEqual(nv[0], 0x80)  # top bit set -> 4-byte length form
        self.assertEqual(int.from_bytes(nv[0:4], "big") & 0x7FFFFFFF, 200)


class TestUploadStackDetect(unittest.TestCase):
    def test_nginx_guess_and_permissive_probe(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "__orizon_probe__" in url:
                return 200, {}, "x", 0.1
            return 200, {"Server": "nginx/1.25.3"}, "x", 0.1

        with patched(upload, "http_request", fake):
            info = upload.detect_php_handler_stack("https://t.test/", {})
        self.assertEqual(info["stack_guess"], "nginx+fpm")
        self.assertTrue(info["path_info_permissive"])

    def test_404_probe_is_not_permissive(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "__orizon_probe__" in url:
                return 404, {}, "x", 0.1
            return 200, {"Server": "Apache"}, "x", 0.1

        with patched(upload, "http_request", fake):
            info = upload.detect_php_handler_stack("https://t.test/", {})
        self.assertEqual(info["stack_guess"], "apache")
        self.assertFalse(info["path_info_permissive"])

    def test_transport_failure_is_not_permissive(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "__orizon_probe__" in url:
                return 0, {}, "connection failed", 0.1
            return 200, {"Server": "nginx"}, "x", 0.1

        with patched(upload, "http_request", fake):
            info = upload.detect_php_handler_stack("https://t.test/", {})
        self.assertEqual(info["stack_guess"], "nginx+fpm")
        self.assertFalse(info["path_info_permissive"])

    def test_unexpected_request_error_is_not_silently_swallowed(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "__orizon_probe__" in url:
                raise RuntimeError("unexpected request-layer error")
            return 200, {"Server": "nginx"}, "x", 0.1

        with patched(upload, "http_request", fake):
            with self.assertRaisesRegex(RuntimeError, "unexpected request-layer error"):
                upload.detect_php_handler_stack("https://t.test/", {})


# ---------------------------------------------------------------------------
# xss_tester
# ---------------------------------------------------------------------------
class TestXssContext(unittest.TestCase):
    def test_attribute_context(self):
        body = '<input value="' + xss.CANARY + '">'
        self.assertIn("html_attribute", xss.detect_reflection_context(body, xss.CANARY))

    def test_script_context(self):
        # No quotes around the canary: a trailing quote would classify it as
        # html_attribute (the attribute check runs first).
        body = "<script>var x = " + xss.CANARY + ";</script>"
        self.assertIn("javascript_context", xss.detect_reflection_context(body, xss.CANARY))

    def test_body_context(self):
        body = "<p>hello " + xss.CANARY + " world</p>"
        self.assertIn("html_body", xss.detect_reflection_context(body, xss.CANARY))

    def test_absent_returns_empty(self):
        self.assertEqual(xss.detect_reflection_context("nothing here", xss.CANARY), [])


class TestXssPayloads(unittest.TestCase):
    def test_candidate_is_unvalidated_info(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "<p>echo <script>alert('0r1z0n')</script> more</p>"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "reflected_xss_candidate")
        self.assertEqual(f["severity"], "INFO")
        self.assertFalse(f["validated"])
        self.assertEqual(f["confidence"], "low")

    def test_post_payload_preserves_form_context_and_reports_candidate(self):
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(data)
            return 200, {}, "<p><img src=x onerror=alert('0r1z0n')></p>"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads(
                "https://t.test/guestbook", "message", ["html_body"], "POST",
                form_data={"name": "Catus", "Sign": "Sign"},
            )
        self.assertTrue(findings)
        self.assertEqual(findings[0]["type"], "stored_xss_candidate")
        self.assertIn("name=Catus", calls[0])
        self.assertIn("Sign=Sign", calls[0])
        self.assertIn("name=Catus", findings[0]["poc_curl"])
        self.assertIn("Sign=Sign", findings[0]["poc_curl"])

    def test_encoded_reflection_not_flagged(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "&lt;script&gt;alert(&#39;0r1z0n&#39;)&lt;/script&gt;"

        with patched(xss, "http_request", fake):
            self.assertEqual(xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"]), [])


class TestXssLooksBlocked(unittest.TestCase):
    def test_block_status_codes(self):
        self.assertTrue(xss._looks_blocked(403, ""))
        self.assertTrue(xss._looks_blocked(429, ""))

    def test_block_signature_phrase(self):
        self.assertTrue(xss._looks_blocked(200, "Request Blocked by Cloudflare"))

    def test_ordinary_response_not_blocked(self):
        self.assertFalse(xss._looks_blocked(200, "ordinary page content"))

    def test_transport_error_not_blocked(self):
        # status 0 means the request itself failed -- that's not evidence of
        # a WAF; escalating on it would just be wasted requests.
        self.assertFalse(xss._looks_blocked(0, "anything"))


class TestXssAutoEscalation(unittest.TestCase):
    def test_escalates_to_waf_bypass_after_block_signal(self):
        """Regression: previously --waf-bypass had to be set by hand before
        the tool would ever try its own bypass payload set. A filtered
        context-specific payload must now trigger automatic escalation."""
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(url)
            if "ScRiPt" in url:  # one of the waf_bypass payloads
                return 200, {}, "echoed <ScRiPt>alert('0r1z0n')</ScRiPt> back"
            return 403, {}, "Access Denied"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["auto_escalated"])
        self.assertEqual(findings[0]["context"], "waf_bypass")
        # Escalation must have actually sent requests beyond the context set.
        self.assertGreater(len(calls), len(xss.PAYLOADS["html_body"]))

    def test_no_escalation_without_block_signal(self):
        """A genuinely unreflected (not blocked) parameter must not trigger
        extra WAF-bypass requests -- that would be noise, not adaptation."""
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(url)
            return 200, {}, "ordinary unrelated page content"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"])
        self.assertEqual(findings, [])
        self.assertEqual(len(calls), len(xss.PAYLOADS["html_body"]))  # no escalation attempts

    def test_escalation_exhausted_returns_empty(self):
        """Block signal observed, but even WAF-bypass payloads never reflect
        -- the function must terminate cleanly with no finding, not loop."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 403, {}, "Access Denied"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"])
        self.assertEqual(findings, [])

    def test_explicit_waf_bypass_flag_runs_regardless_of_block_signal(self):
        """--waf-bypass (try_bypass=True) is an explicit override: it must
        still include those payloads even with no block signal at all,
        preserving the pre-existing opt-in behavior."""
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "ScRiPt" in url:
                return 200, {}, "echoed <ScRiPt>alert('0r1z0n')</ScRiPt> back"
            return 200, {}, "ordinary page, nothing blocked"

        with patched(xss, "http_request", fake):
            findings = xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"], try_bypass=True)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("auto_escalated", findings[0])  # explicit opt-in, not auto-escalation


# ---------------------------------------------------------------------------
# auth_tester / sqli_tester pure helpers
# ---------------------------------------------------------------------------
class TestAuthJwtDecode(unittest.TestCase):
    def test_decode_valid_segment(self):
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "u1"}).encode()).rstrip(b"=").decode()
        self.assertEqual(auth.decode_jwt_part(payload), {"sub": "u1"})

    def test_decode_invalid_returns_none(self):
        self.assertIsNone(auth.decode_jwt_part("!!!not-base64!!!"))


class TestSqliDetectErrors(unittest.TestCase):
    def test_mysql_error(self):
        hits = sqli.detect_sql_errors(
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["dbms"], "MySQL")

    def test_clean_body(self):
        self.assertEqual(sqli.detect_sql_errors("welcome to the site"), [])

    def test_post_form_payload_keeps_siblings_and_submit_action(self):
        encoded = sqli._post_form_data(
            "ip", "127.0.0.1'", {"Submit": "Submit", "token": "fixture-token"})
        import urllib.parse
        self.assertEqual(dict(urllib.parse.parse_qsl(encoded)), {
            "Submit": "Submit", "token": "fixture-token", "ip": "127.0.0.1'",
        })


class TestSqliLooksBlocked(unittest.TestCase):
    def test_block_status_codes(self):
        self.assertTrue(sqli._looks_blocked(403, ""))
        self.assertTrue(sqli._looks_blocked(406, ""))

    def test_block_signature_phrase(self):
        self.assertTrue(sqli._looks_blocked(200, "mod_security triggered"))

    def test_ordinary_response_not_blocked(self):
        self.assertFalse(sqli._looks_blocked(200, "welcome to the site"))

    def test_transport_error_not_blocked(self):
        self.assertFalse(sqli._looks_blocked(0, "anything"))


class TestSqliMutations(unittest.TestCase):
    _KEYWORD_RE = sqli._SQL_KEYWORD_RE

    def test_mutate_case_preserves_keywords_case_insensitively(self):
        payload = "' UNION SELECT NULL--"
        mutated = sqli._mutate_case(payload, random.Random(1))
        self.assertEqual(mutated.upper(), payload.upper())  # same chars, only case changed
        self.assertTrue(self._KEYWORD_RE.search(mutated))

    def test_mutate_inline_comment_splits_or_wraps_one_keyword(self):
        payload = "' UNION SELECT NULL--"
        mutated = sqli._mutate_inline_comment(payload, random.Random(2))
        self.assertIn("/*", mutated)
        self.assertNotEqual(mutated, payload)

    def test_mutate_inline_comment_noop_without_keyword(self):
        self.assertEqual(sqli._mutate_inline_comment("no keywords here", random.Random(1)), "no keywords here")

    def test_mutate_whitespace_replaces_spaces_with_comment(self):
        mutated = sqli._mutate_whitespace("UNION SELECT NULL", random.Random(1))
        self.assertNotIn(" ", mutated)
        self.assertIn("/**/", mutated)

    def test_mutate_whitespace_noop_without_spaces(self):
        self.assertEqual(sqli._mutate_whitespace("NOSPACESHERE", random.Random(1)), "NOSPACESHERE")

    def test_mutate_sqli_payload_starts_fresh_from_original_each_call(self):
        # Matches prompt_injection_tester.py's convention: every mutation
        # attempt derives from the ORIGINAL payload, never compounds.
        payload = "' UNION SELECT NULL--"
        rng = random.Random(42)
        first = sqli.mutate_sqli_payload(payload, rng)
        second = sqli.mutate_sqli_payload(payload, rng)
        # Both must still be recognizably derived from the same original
        # (same keyword set survives case/comment mutation).
        for variant in (first, second):
            self.assertTrue(self._KEYWORD_RE.search(variant.replace("/**/", " ").replace("/*!50000", "").replace("*/", "")))


class TestSqliAdaptiveRetry(unittest.TestCase):
    def test_blocked_baseline_mutation_confirms_finding(self):
        """The base payload gets blocked; a mutated variant on the very next
        attempt slips through and triggers a real DB error -- the adaptive
        retry must catch this where a single static attempt would have
        missed it. Call 1 is the baseline read (clean), call 2 is the first
        payload's base attempt (blocked), call 3 is its first mutation
        (errors) -- the loop must stop there with exactly those 3 calls."""
        calls = {"n": 0}

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls["n"] += 1
            if calls["n"] == 1:
                return 200, {}, "ordinary baseline page", 0.05
            if calls["n"] == 2:
                return 403, {}, "Access Denied", 0.05
            return 500, {}, "You have an error in your SQL syntax near 'NULL'", 0.05

        with patched(sqli, "http_request", fake):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=3, seed=7)
        self.assertTrue(findings)
        self.assertTrue(findings[0]["waf_evasion_used"])
        self.assertEqual(len(findings[0]["attempts"]), 2)
        self.assertEqual(calls["n"], 3)

    def test_no_signal_stops_without_exhausting_mutation_budget(self):
        """A payload that is neither an error nor a block must not trigger
        any mutation retries -- one request, move to the next payload."""
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(url)
            return 200, {}, "ordinary page, nothing happened", 0.05

        with patched(sqli, "http_request", fake):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=3, seed=1)
        self.assertEqual(findings, [])
        # Exactly one attempt per ERROR_PAYLOADS entry plus one baseline read.
        self.assertEqual(len(calls), len(sqli.ERROR_PAYLOADS) + 1)

    def test_max_mutations_zero_disables_retry(self):
        """--max-mutations 0 must behave exactly like the pre-existing
        single-attempt-per-payload code: blocked or not, no retries."""
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(url)
            return 403, {}, "Access Denied", 0.05

        with patched(sqli, "http_request", fake):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=0, seed=1)
        self.assertEqual(findings, [])
        self.assertEqual(len(calls), len(sqli.ERROR_PAYLOADS) + 1)

    def test_blocked_and_mutations_exhausted_moves_to_next_payload(self):
        """Every mutation of a payload still gets blocked -- the loop must
        terminate at the mutation budget and continue to the next payload
        rather than retrying forever."""
        current = [0]

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            current[0] += 1
            return 403, {}, "Access Denied", 0.05

        with patched(sqli, "http_request", fake):
            findings = sqli.test_error_based(
                "https://t.test/?id=1", "id", "1", max_mutations=2, seed=3)
        self.assertEqual(findings, [])
        # baseline + len(ERROR_PAYLOADS) * (1 base + 2 mutations)
        self.assertEqual(current[0], 1 + len(sqli.ERROR_PAYLOADS) * 3)


if __name__ == "__main__":
    unittest.main()
