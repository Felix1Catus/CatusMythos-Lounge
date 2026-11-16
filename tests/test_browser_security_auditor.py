"""Regression tests for browser_security_auditor.py.

The pure-function tests run anywhere (no browser). The integration test is
skipped unless Playwright *and* a Chromium build are available, so an
incomplete stack does not silently pass a browser-dependent check.
"""
import importlib.util
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "browser_security_auditor.py"
SPEC = importlib.util.spec_from_file_location("browser_security_auditor", SCRIPT_PATH)
bsa = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bsa
SPEC.loader.exec_module(bsa)


class RedactUrlTests(unittest.TestCase):
    def test_http_strips_query_and_fragment(self):
        self.assertEqual(bsa.redact_url("http://h.test/a/b?secret=1#frag"), "http://h.test/a/b")

    def test_https_default_port_omitted_custom_kept(self):
        self.assertEqual(bsa.redact_url("https://h.test:443/x"), "https://h.test/x")
        self.assertEqual(bsa.redact_url("https://h.test:8443/x?q=1"), "https://h.test:8443/x")

    def test_root_path_defaulted(self):
        self.assertEqual(bsa.redact_url("http://h.test"), "http://h.test/")

    def test_websocket_urls_are_redacted_not_discarded(self):
        # Regression: ws/wss previously collapsed to [invalid-url], losing the
        # intercepted socket's identity in the report.
        self.assertEqual(bsa.redact_url("ws://h.test:8771/socket?token=x"), "ws://h.test:8771/socket")
        self.assertEqual(bsa.redact_url("wss://h.test/live#f"), "wss://h.test/live")
        self.assertEqual(bsa.redact_url("wss://h.test:443/live"), "wss://h.test/live")
        self.assertEqual(bsa.redact_url("ws://h.test:80/s"), "ws://h.test/s")

    def test_credentialed_and_foreign_schemes_rejected(self):
        self.assertEqual(bsa.redact_url("http://user:pass@h.test/x"), "[invalid-url]")
        self.assertEqual(bsa.redact_url("ws://user:pass@h.test/x"), "[invalid-url]")
        self.assertEqual(bsa.redact_url("file:///etc/passwd"), "[invalid-url]")
        self.assertEqual(bsa.redact_url("javascript:alert(1)"), "[invalid-url]")


class CanonicalOriginTests(unittest.TestCase):
    def test_default_ports(self):
        self.assertEqual(bsa.canonical_origin("http://h.test/x"), ("http", "h.test", 80))
        self.assertEqual(bsa.canonical_origin("https://h.test/x"), ("https", "h.test", 443))

    def test_rejects_credentials_and_non_http(self):
        self.assertIsNone(bsa.canonical_origin("http://u:p@h.test/"))
        self.assertIsNone(bsa.canonical_origin("ws://h.test/"))
        self.assertIsNone(bsa.canonical_origin("ftp://h.test/"))

    def test_ws_origin_helper(self):
        self.assertEqual(bsa._canonical_ws_origin("ws://h.test/s"), ("ws", "h.test", 80))
        self.assertEqual(bsa._canonical_ws_origin("wss://h.test/s"), ("wss", "h.test", 443))
        self.assertIsNone(bsa._canonical_ws_origin("http://h.test/"))
        self.assertIsNone(bsa._canonical_ws_origin("ws://u:p@h.test/"))


class RequestDecisionTests(unittest.TestCase):
    def setUp(self):
        self.scope = {("http", "h.test", 80)}

    def test_same_origin_read_allowed(self):
        self.assertEqual(bsa.request_decision("GET", "http://h.test/a", self.scope), (True, "read"))
        self.assertEqual(bsa.request_decision("HEAD", "http://h.test/a", self.scope), (True, "read"))

    def test_off_origin_blocked(self):
        self.assertEqual(bsa.request_decision("GET", "http://evil.test/a", self.scope), (False, "origin"))

    def test_post_blocked_without_matching_form(self):
        self.assertEqual(bsa.request_decision("POST", "http://h.test/a", self.scope), (False, "method"))

    def test_post_allowed_once_for_pending_form(self):
        key = bsa.form_request_key("POST", "http://h.test/submit", self.scope)
        self.assertIsNotNone(key)
        # First matching POST consumes the one-shot grant.
        self.assertEqual(bsa.request_decision("POST", "http://h.test/submit", self.scope, key), (True, "form"))
        self.assertTrue(key["used"])
        # A second POST during the same window is no longer authorized.
        self.assertEqual(bsa.request_decision("POST", "http://h.test/submit", self.scope, key), (False, "method"))

    def test_pending_form_path_must_match(self):
        key = bsa.form_request_key("POST", "http://h.test/submit", self.scope)
        self.assertEqual(bsa.request_decision("POST", "http://h.test/other", self.scope, key), (False, "method"))


class FormRequestKeyTests(unittest.TestCase):
    def setUp(self):
        self.scope = {("http", "h.test", 80)}

    def test_rejects_non_get_post_and_off_scope(self):
        self.assertIsNone(bsa.form_request_key("PUT", "http://h.test/x", self.scope))
        self.assertIsNone(bsa.form_request_key("POST", "http://evil.test/x", self.scope))

    def test_accepts_get_and_post_in_scope(self):
        self.assertEqual(bsa.form_request_key("get", "http://h.test/x", self.scope)["method"], "GET")
        self.assertEqual(bsa.form_request_key("POST", "http://h.test/x", self.scope)["method"], "POST")


class StorageStateTests(unittest.TestCase):
    def setUp(self):
        self.scope = {("https", "app.test", 443)}

    def test_in_scope_cookie_and_localstorage_kept_values_preserved(self):
        raw = {
            "cookies": [{"name": "s", "value": "v", "domain": "app.test"}],
            "origins": [{"origin": "https://app.test", "localStorage": [{"name": "k", "value": "secret"}]}],
        }
        out = bsa.sanitize_storage_state(raw, self.scope)
        self.assertEqual(out["cookies"][0]["name"], "s")
        self.assertEqual(out["cookies"][0]["value"], "v")  # value kept in-memory for the session
        self.assertEqual(out["origins"][0]["localStorage"][0]["value"], "secret")

    def test_parent_domain_cookie_suffix_match_kept(self):
        # Documented behavior: a parent-domain cookie is kept when a scoped host
        # suffix-matches it (request routing still enforces exact origin).
        raw = {"cookies": [{"name": "s", "value": "v", "domain": ".test"}], "origins": []}
        out = bsa.sanitize_storage_state(raw, self.scope)
        self.assertEqual(len(out["cookies"]), 1)

    def test_out_of_scope_entries_dropped(self):
        raw = {
            "cookies": [{"name": "s", "value": "v", "domain": "evil.test"}],
            "origins": [{"origin": "https://evil.test", "localStorage": [{"name": "k", "value": "v"}]}],
        }
        out = bsa.sanitize_storage_state(raw, self.scope)
        self.assertEqual(out["cookies"], [])
        self.assertEqual(out["origins"], [])

    def test_non_dict_rejected(self):
        with self.assertRaises(ValueError):
            bsa.sanitize_storage_state([], self.scope)


class ActiveProbeTests(unittest.TestCase):
    def test_skips_sensitive_param_names(self):
        probes = bsa.active_probe_urls("http://h.test/x?token=1&q=2", 123456789)
        self.assertTrue(any(src == "fragment" for src, _ in probes))
        # No probe should carry a payload in the sensitive 'token' slot.
        for _src, url in probes:
            self.assertNotIn("__catusAuditExecuted", url.split("token=", 1)[-1].split("&", 1)[0] if "token=" in url else "")

    def test_default_names_when_no_params(self):
        probes = bsa.active_probe_urls("http://h.test/x", 123456789)
        self.assertTrue(probes)
        self.assertTrue(any(src == "query" for src, _ in probes))
        self.assertTrue(any(src == "fragment" for src, _ in probes))

    def test_bounded_by_max_probes(self):
        probes = bsa.active_probe_urls("http://h.test/x?a=1&b=2&c=3", 123456789, max_probes=3)
        self.assertLessEqual(len(probes), 3)

    def test_zero_budget_returns_empty(self):
        self.assertEqual(bsa.active_probe_urls("http://h.test/x", 1, max_probes=0), [])


class FieldAndLinkTests(unittest.TestCase):
    def test_eligible_form_field(self):
        self.assertTrue(bsa.eligible_form_field({"tag": "input", "type": "text", "name": "comment"}))
        self.assertTrue(bsa.eligible_form_field({"tag": "textarea", "type": "", "name": "body"}))
        self.assertFalse(bsa.eligible_form_field({"tag": "input", "type": "password", "name": "pw"}))
        self.assertFalse(bsa.eligible_form_field({"tag": "input", "type": "text", "name": "csrf_token"}))
        self.assertFalse(bsa.eligible_form_field({"tag": "input", "type": "text", "name": "x", "disabled": True}))

    def test_should_skip_state_changing_links(self):
        self.assertTrue(bsa.should_skip_link("http://h.test/account/logout"))
        self.assertTrue(bsa.should_skip_link("http://h.test/cart/checkout"))
        self.assertFalse(bsa.should_skip_link("http://h.test/products/view"))


class ExecutionPayloadTests(unittest.TestCase):
    def test_marker_is_int_coerced(self):
        self.assertIn("window.__catusAuditExecuted=42", bsa.build_execution_payload("42", "svg"))
        self.assertIn("onerror", bsa.build_execution_payload(7, "img"))

    def test_init_script_uses_instance_defineproperty(self):
        # Regression: the postMessage hook must defineProperty on the window
        # instance; a Window.prototype reassignment silently no-ops in Chromium.
        self.assertIn("Object.defineProperty(window, 'postMessage'", bsa.INIT_SCRIPT)
        self.assertNotIn("Window.prototype.postMessage =", bsa.INIT_SCRIPT)


# --------------------------------------------------------------------------
# Chromium-gated live integration test
# --------------------------------------------------------------------------
def _chromium_available():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


CHROMIUM = _chromium_available()


class _FixtureA(BaseHTTPRequestHandler):
    port_b = 0

    def log_message(self, *a):
        pass

    def _send(self, body, cookie=False):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", "session=abc; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(
                "<!doctype html><title>Home</title><body>"
                "<a href='/reflect?q=hi'>r</a>"
                "<img src='http://127.0.0.1:%d/p.png'>"
                "<script>try{localStorage.setItem('auth_token','x');}catch(e){}"
                "try{window.postMessage('p','*');}catch(e){}"
                "try{new WebSocket('ws://127.0.0.1:%d/s');}catch(e){}</script>"
                "</body>" % (self.port_b, self.server.server_address[1]),
                cookie=True,
            )
        elif path == "/reflect":
            self._send(
                "<!doctype html><title>R</title><body><div id=s></div><script>"
                "var v=new URLSearchParams(location.search).get('q')||'';"
                "document.getElementById('s').innerHTML=v;</script></body>"
            )
        else:
            self.send_response(404)
            self.end_headers()


class _FixtureB(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"x")


@unittest.skipUnless(CHROMIUM, "Playwright Chromium is not installed")
class BrowserIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv_b = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureB)
        cls.port_b = cls.srv_b.server_address[1]
        _FixtureA.port_b = cls.port_b
        cls.srv_a = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureA)
        cls.port_a = cls.srv_a.server_address[1]
        for s in (cls.srv_a, cls.srv_b):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv_a.shutdown()
        cls.srv_b.shutdown()

    def _run(self, extra):
        import types
        args = types.SimpleNamespace(
            active="--active" in extra or "--submit-forms" in extra,
            submit_forms="--submit-forms" in extra,
            depth=1, max_pages=10, max_requests=500, timeout_ms=15000,
            max_form_submissions=5, headed=False, storage_state=None,
        )
        target = bsa.validate_target_url("http://127.0.0.1:%d/" % self.port_a)
        allowed = {bsa.canonical_origin(target)}
        return bsa.run_browser_audit(args, target, allowed)

    def test_passive_findings_and_controls(self):
        r = self._run([])
        types_seen = {f["type"] for f in r["findings"]}
        self.assertIn("missing_security_header", types_seen)
        self.assertIn("cookie_missing_httponly", types_seen)
        self.assertIn("sensitive_storage_key", types_seen)
        # Fixed: wildcard postMessage is now detected.
        self.assertIn("postmessage_wildcard_target", types_seen)
        # Fixed: WebSocket URL is redacted, not discarded.
        self.assertEqual(len(r["websockets"]), 1)
        self.assertTrue(r["websockets"][0]["url"].startswith("ws://127.0.0.1"))
        self.assertFalse(r["websockets"][0]["upstream_connected"])
        # Off-origin request to fixture B was blocked and counted.
        self.assertGreaterEqual(r["summary"]["requests_blocked_by_origin"], 1)

    def test_active_query_dom_xss_detected(self):
        r = self._run(["--active"])
        dom = [f for f in r["findings"] if f["type"] == "dom_xss"]
        self.assertTrue(any(f["source"] == "query" for f in dom))


if __name__ == "__main__":
    unittest.main()
