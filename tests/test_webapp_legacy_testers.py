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
        self.assertEqual(findings[0]["type"], "idor")
        self.assertEqual(findings[0]["severity"], "HIGH")

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
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if "7%2A7" in url or "7*7" in url:  # {{7*7}} urlencoded
                return 200, {}, "result: 49"
            return 200, {}, "nope"

        with patched(ssti, "http_request", fake):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["engine_detected"], "Jinja2")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_engine_error_message_also_confirms(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 500, {}, "jinja2.exceptions.TemplateSyntaxError: unexpected char"

        with patched(ssti, "http_request", fake):
            findings = ssti.fingerprint_engine("https://t.test/?q=1", "q", delay=0)
        self.assertTrue(findings)

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

    def test_encoded_reflection_not_flagged(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 200, {}, "&lt;script&gt;alert(&#39;0r1z0n&#39;)&lt;/script&gt;"

        with patched(xss, "http_request", fake):
            self.assertEqual(xss.test_xss_payloads("https://t.test/?q=1", "q", ["html_body"]), [])


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


if __name__ == "__main__":
    unittest.main()
