import importlib.util
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "dom_xss_auditor.py"
SPEC = importlib.util.spec_from_file_location("dom_xss_auditor", SCRIPT_PATH)
dom_xss_auditor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dom_xss_auditor
SPEC.loader.exec_module(dom_xss_auditor)


class _TestHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def do_GET(self):
        type(self).requests_seen.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://outside.invalid/script.js")
            self.end_headers()
            return
        if self.path == "/app.js":
            body = b"const x = location.hash; document.querySelector('#x').innerHTML = x;"
            content_type = "application/javascript"
        else:
            body = (b"<script>document.write(location.hash)</script>"
                    b"<script src='/app.js'></script>"
                    b"<script src='https://outside.invalid/third.js'></script>"
                    b"<button onclick=\"document.write(location.search)\"></button>")
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class DomXssAuditorTests(unittest.TestCase):
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

        return patch.object(dom_xss_auditor.urllib.request, "build_opener", side_effect=build_opener)

    def test_tracks_source_through_aliases_into_html_sink(self):
        code = "const first = new URL(location.href).searchParams.get('q'); let next; next = first; node.innerHTML = next;"
        findings = dom_xss_auditor.audit_javascript(code, "bundle.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sink"], "innerHTML assignment")
        self.assertIn("location.href", findings[0]["sources"])
        self.assertEqual(findings[0]["confidence"], "low")

    def test_tracks_template_expression_into_document_write(self):
        findings = dom_xss_auditor.audit_javascript("document.write(`${location.hash}`);")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sink"], "document.write")
        self.assertIn("location.hash", findings[0]["sources"])

    def test_covers_compound_html_assignment_and_react_sink(self):
        code = "const input = location.search; node.innerHTML += input; const props = {dangerouslySetInnerHTML: {__html: input}};"
        findings = dom_xss_auditor.audit_javascript(code)
        self.assertEqual({finding["sink"] for finding in findings}, {
            "innerHTML assignment", "React dangerouslySetInnerHTML"
        })

    def test_ignores_source_and_sink_text_in_comments_and_strings(self):
        code = "// location.hash; node.innerHTML = value;\nconst note = 'document.write(location.search)';"
        self.assertEqual(dom_xss_auditor.audit_javascript(code), [])

    def test_finds_event_handler_and_skips_external_scripts_by_default(self):
        _TestHandler.requests_seen.clear()
        with self._without_environment_proxy():
            sources = dom_xss_auditor.collect_sources(self.base_url, [], include_external=False)
        findings = [finding for name, code in sources for finding in dom_xss_auditor.audit_javascript(code, name)]
        self.assertEqual(len(sources), 3)
        self.assertEqual(len(findings), 3)
        self.assertNotIn("/third.js", _TestHandler.requests_seen)

    def test_cross_origin_redirect_is_blocked(self):
        with self._without_environment_proxy():
            with self.assertRaises(Exception):
                dom_xss_auditor.fetch_text(self.base_url + "/redirect")
        self.assertNotIn("/script.js", _TestHandler.requests_seen)

    def test_url_query_values_are_redacted(self):
        self.assertEqual(
            dom_xss_auditor.redact_url("https://example.test/a?token=secret&mode=debug#x"),
            "https://example.test/a?token=%5Bredacted%5D&mode=%5Bredacted%5D",
        )


if __name__ == "__main__":
    unittest.main()
