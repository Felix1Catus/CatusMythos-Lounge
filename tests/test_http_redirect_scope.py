import importlib.util
import ssl
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
NETWORK_SKILLS = (
    "recon-dominator",
    "webapp-exploit-hunter",
    "api-breaker",
    "cloud-pivot-finder",
    "attack-path-architect",
)


def load_common(skill):
    path = REPO_ROOT / "skills" / skill / "scripts" / "_common.py"
    name = "redirect_scope_{}".format(skill.replace("-", "_"))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMMON_MODULES = {skill: load_common(skill) for skill in NETWORK_SKILLS}


class _DestinationHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def do_GET(self):
        type(self).requests_seen.append((self.path, self.headers.get("Cookie")))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"destination")

    def log_message(self, format, *args):
        pass


class _SourceHandler(BaseHTTPRequestHandler):
    same_origin_cookies = []
    destination_url = ""

    def do_GET(self):
        if self.path == "/redirect-cross-origin":
            self.send_response(302)
            self.send_header("Location", type(self).destination_url + "/received")
            self.end_headers()
            return
        if self.path == "/redirect-same-origin":
            self.send_response(302)
            self.send_header("Location", "/received")
            self.end_headers()
            return
        if self.path == "/received":
            type(self).same_origin_cookies.append(self.headers.get("Cookie"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"source")

    def log_message(self, format, *args):
        pass


class HttpRedirectScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.destination = ThreadingHTTPServer(("127.0.0.1", 0), _DestinationHandler)
        cls.destination_thread = threading.Thread(target=cls.destination.serve_forever, daemon=True)
        cls.destination_thread.start()
        _SourceHandler.destination_url = "http://127.0.0.1:{}".format(cls.destination.server_address[1])
        cls.source = ThreadingHTTPServer(("127.0.0.1", 0), _SourceHandler)
        cls.source_thread = threading.Thread(target=cls.source.serve_forever, daemon=True)
        cls.source_thread.start()
        cls.source_url = "http://127.0.0.1:{}".format(cls.source.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.source.shutdown()
        cls.destination.shutdown()
        cls.source.server_close()
        cls.destination.server_close()
        cls.source_thread.join(timeout=2)
        cls.destination_thread.join(timeout=2)

    def setUp(self):
        _DestinationHandler.requests_seen.clear()
        _SourceHandler.same_origin_cookies.clear()

    def _without_environment_proxy(self):
        original = urllib.request.build_opener

        def build_opener(*handlers):
            return original(urllib.request.ProxyHandler({}), *handlers)

        return patch.object(urllib.request, "build_opener", side_effect=build_opener)

    def test_all_network_skill_helpers_block_cross_origin_redirects(self):
        for skill, common in COMMON_MODULES.items():
            with self.subTest(skill=skill), self._without_environment_proxy():
                request = urllib.request.Request(
                    self.source_url + "/redirect-cross-origin",
                    headers={"Cookie": "session=do-not-forward"},
                )
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    common.scoped_urlopen(request, timeout=2, context=ssl.create_default_context())
                self.assertEqual(caught.exception.code, 302)
                caught.exception.close()
        self.assertEqual(_DestinationHandler.requests_seen, [])

    def test_same_origin_redirects_still_work_and_keep_target_cookie(self):
        for skill, common in COMMON_MODULES.items():
            with self.subTest(skill=skill), self._without_environment_proxy():
                request = urllib.request.Request(
                    self.source_url + "/redirect-same-origin",
                    headers={"Cookie": "session=target-only"},
                )
                with common.scoped_urlopen(request, timeout=2, context=ssl.create_default_context()) as response:
                    self.assertEqual(response.read(), b"source")
        self.assertEqual(_SourceHandler.same_origin_cookies, ["session=target-only"] * len(COMMON_MODULES))

    def test_rejects_credentialed_initial_urls_before_network_io(self):
        before = len(_SourceHandler.same_origin_cookies)
        common = COMMON_MODULES["webapp-exploit-hunter"]
        with self.assertRaises(ValueError):
            common.scoped_urlopen("http://user:password@127.0.0.1:{}/received".format(self.source.server_address[1]))
        self.assertEqual(len(_SourceHandler.same_origin_cookies), before)


if __name__ == "__main__":
    unittest.main()
