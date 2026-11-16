import argparse
import importlib.util
import json
import re
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "skills" / "web-cache-auditor" / "scripts" / "cache_audit.py"
SPEC = importlib.util.spec_from_file_location("cache_audit", SCRIPT_PATH)
cache_audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cache_audit
SPEC.loader.exec_module(cache_audit)


class _TestHandler(BaseHTTPRequestHandler):
    requests_seen = 0

    def do_GET(self):
        type(self).requests_seen += 1
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/outside")
            self.end_headers()
            return
        body = b"x" * (cache_audit.BODY_LIMIT + 10)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class CacheAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:{}".format(cls.server.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _without_environment_proxy(self):
        original = urllib.request.build_opener

        def build_opener(*handlers):
            return original(urllib.request.ProxyHandler({}), *handlers)

        return patch.object(cache_audit.urllib.request, "build_opener", side_effect=build_opener)

    def test_cache_buster_preserves_existing_path_and_query(self):
        target = "https://example.test/a%2fb?x=1&"
        self.assertEqual(
            cache_audit.add_cache_buster(target, "token value"),
            target + "_catus_cache_probe=token%20value",
        )
        self.assertEqual(
            cache_audit.add_cache_buster("https://example.test/a&", "nonce"),
            "https://example.test/a&?_catus_cache_probe=nonce",
        )

    def test_query_probe_preserves_raw_query_and_skips_sensitive_or_existing_keys(self):
        self.assertEqual(
            cache_audit.add_query_parameter(
                "https://example.test/a%2fb?x=1&", "utm_content", "canary value"
            ),
            "https://example.test/a%2fb?x=1&utm_content=canary%20value",
        )
        self.assertEqual(
            cache_audit.query_probe_parameter_names("https://example.test/public"),
            list(cache_audit.QUERY_PARAMETER_CANDIDATES),
        )
        self.assertNotIn(
            "utm_content",
            cache_audit.query_probe_parameter_names("https://example.test/public?UTM_content=present"),
        )
        self.assertEqual(
            cache_audit.query_probe_parameter_names("https://example.test/profile?token=secret"),
            [],
        )
        for key in ("accessToken", "api-key", "session_id", "clientSecret"):
            with self.subTest(sensitive_key=key):
                self.assertEqual(
                    cache_audit.query_probe_parameter_names(
                        "https://example.test/profile?{}=value".format(key)
                    ),
                    [],
                )

    def test_target_validation_rejects_credentials_and_non_http(self):
        for target in ("ftp://example.test/file", "https://user:pass@example.test/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                cache_audit.validate_target(target)

    def test_timeout_and_delay_inputs_are_finite_and_bounded(self):
        self.assertEqual(cache_audit._positive_float("0.1"), 0.1)
        self.assertEqual(
            cache_audit._positive_float(str(cache_audit.MAX_REQUEST_TIMEOUT)),
            cache_audit.MAX_REQUEST_TIMEOUT,
        )
        self.assertEqual(cache_audit._nonnegative_float("0"), 0.0)
        self.assertEqual(cache_audit._nonnegative_float(str(cache_audit.MAX_DELAY)), cache_audit.MAX_DELAY)

        for value in ("0", "-1", "nan", "inf", "-inf", "30.1", "1e10000"):
            with self.subTest(timeout=value), self.assertRaises(argparse.ArgumentTypeError):
                cache_audit._positive_float(value)
        for value in ("-0.1", "nan", "inf", "-inf", "5.1", "1e10000"):
            with self.subTest(delay=value), self.assertRaises(argparse.ArgumentTypeError):
                cache_audit._nonnegative_float(value)
        with self.assertRaises(ValueError):
            cache_audit.request_get("http://127.0.0.1/", timeout=float("inf"))

    def test_cli_rejects_nonfinite_and_oversized_timing_before_request(self):
        for option, value in (
            ("--timeout", "nan"),
            ("--timeout", "30.1"),
            ("--delay", "inf"),
            ("--delay", "5.1"),
        ):
            with self.subTest(option=option, value=value), patch.object(
                cache_audit, "request_get"
            ) as request:
                with self.assertRaises(SystemExit) as error:
                    cache_audit.main(["--target", "https://example.test/public", option, value])
            self.assertEqual(error.exception.code, 2)
            request.assert_not_called()

    def test_target_report_redacts_query_values(self):
        self.assertEqual(
            cache_audit.safe_target_label("https://example.test/path?token=secret"),
            "https://example.test/path?[redacted]",
        )

    def test_probe_set_avoids_host_and_client_ip_override(self):
        headers = {name.lower() for name, _ in cache_audit.probe_headers("canary.invalid")}
        self.assertNotIn("host", headers)
        self.assertNotIn("x-forwarded-for", headers)

    def test_cache_evidence_is_a_hint(self):
        self.assertEqual(cache_audit.cache_state({"CF-Cache-Status": "HIT", "Age": "10"})[0], "hit")
        self.assertEqual(cache_audit.cache_state({"X-Cache": "MISS"})[0], "miss")
        self.assertEqual(cache_audit.cache_state({"X-Cache": "TCP_HIT"})[0], "hit")
        self.assertEqual(cache_audit.cache_state({"X-Cache": "UNHIT"})[0], "unknown")
        self.assertEqual(cache_audit.cache_state({"Cache-Control": "private, no-store"})[0], "unknown")

    def test_request_does_not_follow_redirect(self):
        _TestHandler.requests_seen = 0
        with self._without_environment_proxy():
            response = cache_audit.request_get(self.base_url + "/redirect")
        self.assertEqual(response["status"], 302)
        self.assertEqual(_TestHandler.requests_seen, 1)

    def test_response_body_is_bounded(self):
        with self._without_environment_proxy():
            response = cache_audit.request_get(self.base_url + "/large")
        self.assertEqual(len(response["body"]), cache_audit.BODY_LIMIT)
        self.assertTrue(response["body_truncated"])

    def test_staging_replay_uses_same_unique_url_and_omits_body(self):
        seen = {}
        calls = []

        def fake_request(url, headers=None, timeout=8.0):
            headers = headers or {}
            calls.append((url, dict(headers)))
            marker = None
            for value in headers.values():
                match = re.search(r"catus-probe-[a-f0-9]+\.invalid", value, re.I)
                if match:
                    marker = match.group(0)
                    break
            if marker:
                seen[url] = marker
                body = marker.encode("ascii")
                response_headers = {}
            elif url in seen:
                body = seen[url].encode("ascii")
                response_headers = {"X-Cache": "HIT"}
            else:
                body = b"baseline"
                response_headers = {}
            return {
                "status": 200,
                "headers": response_headers,
                "body": body,
                "body_truncated": False,
                "elapsed_ms": 0,
                "error": None,
            }

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "cache.json"
            with patch.object(cache_audit, "request_get", side_effect=fake_request):
                code = cache_audit.main([
                    "--target", "https://example.test/profile?token=secret",
                    "--probe-unkeyed", "--confirm-cache-replay", "--delay", "0",
                    "--output", str(output_path),
                ])
            report = json.loads(output_path.read_text(encoding="utf-8"))
            serialized = output_path.read_text(encoding="utf-8")
            sys.path.insert(0, str(REPO_ROOT / "skills" / "vuln-chain-composer" / "scripts"))
            import import_findings
            normalized = import_findings.load_findings_from_file(str(output_path))

        self.assertEqual(code, 0)
        self.assertEqual(len(report["probes"]), 7)
        self.assertEqual(len(report["findings"]), 7)
        self.assertEqual(len(calls), 15)  # one baseline, seven canaries, seven clean replays
        for index, probe in enumerate(report["probes"]):
            probe_url, probe_headers = calls[1 + index * 2]
            replay_url, replay_headers = calls[2 + index * 2]
            self.assertEqual(probe_url, replay_url)
            self.assertTrue(probe_headers)
            self.assertFalse(replay_headers)
            self.assertTrue(probe["cache_replay"]["likely_cache_reuse"])
        self.assertNotIn("token=secret", serialized)
        self.assertNotIn("body", report["baseline"])
        for probe in report["probes"]:
            self.assertNotIn("body", probe["response"])
            self.assertNotIn("body", probe["cache_replay"])
        self.assertEqual(len(normalized), 7)
        self.assertEqual({finding["severity"] for finding in normalized}, {"INFO"})
        self.assertEqual(
            {finding["confidence"] for finding in normalized}, {"likely_cache_reuse"}
        )

    def test_query_parameter_canary_reappears_from_local_unkeyed_cache(self):
        cached = {}
        requests = []
        query_markers = []

        class QueryCacheHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = cache_audit.urllib.parse.urlsplit(self.path)
                query = dict(cache_audit.urllib.parse.parse_qsl(
                    parsed.query, keep_blank_values=True
                ))
                nonce = query.get("_catus_cache_probe")
                key = (parsed.path, nonce)
                if "utm_content" in query:
                    body = query["utm_content"].encode("utf-8")
                    query_markers.append(query["utm_content"])
                    cached[key] = body
                    cache_status = "MISS"
                elif key in cached:
                    body = cached[key]
                    cache_status = "HIT"
                else:
                    body = b"ordinary fixture response"
                    cache_status = "MISS"
                requests.append((parsed.path, dict(query), self.headers.get("X-Forwarded-Host")))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Cache", cache_status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), QueryCacheHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        target = "http://127.0.0.1:{}/public".format(server.server_address[1])
        try:
            with tempfile.TemporaryDirectory() as directory, self._without_environment_proxy():
                output_path = Path(directory) / "query-cache.json"
                code = cache_audit.main([
                    "--target", target, "--probe-unkeyed", "--confirm-cache-replay",
                    "--delay", "0", "--output", str(output_path),
                ])
                serialized = output_path.read_text(encoding="utf-8")
                report = json.loads(serialized)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        self.assertEqual(code, 0)
        query_probe = next(
            probe for probe in report["probes"]
            if probe.get("input_type") == "query_parameter"
            and probe.get("query_parameter") == "utm_content"
        )
        self.assertEqual(query_probe["response"]["marker_locations"], ["body"])
        self.assertTrue(query_probe["cache_replay"]["canary_reappeared_without_query_parameter"])
        self.assertEqual(query_probe["cache_replay"]["cache_state_hint"], "hit")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["input_type"], "query_parameter")
        self.assertEqual(report["findings"][0]["parameter"], "utm_content")
        self.assertEqual(len(requests), 14)  # baseline, seven headers, five query probes, one replay
        self.assertTrue(query_markers)
        self.assertNotIn(query_markers[0], serialized)


if __name__ == "__main__":
    unittest.main()
