import importlib.util
import sys
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "crawler.py"
SPEC = importlib.util.spec_from_file_location("crawler_discovery_for_tests", SCRIPT_PATH)
crawler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = crawler
_original_common = sys.modules.pop("_common", None)
sys.path.insert(0, str(SCRIPT_PATH.parent))
try:
    SPEC.loader.exec_module(crawler)
finally:
    sys.path.remove(str(SCRIPT_PATH.parent))
    sys.modules.pop("_common", None)
    if _original_common is not None:
        sys.modules["_common"] = _original_common


class _DiscoveryHandler(BaseHTTPRequestHandler):
    base_url = ""
    requested_paths = []
    robots_body = None
    sitemap_body = b""

    def do_GET(self):
        type(self).requested_paths.append(self.path)
        if self.path == "/robots.txt":
            body = type(self).robots_body or (
                "User-agent: *\n"
                "Disallow: /private\n"
                "Allow: /public\n"
                "Disallow: /wild*card\n"
                "Sitemap: {}/sitemap-index.xml\n".format(type(self).base_url)
                + "Sitemap: http://127.0.0.1:1/other-port.xml\n"
            ).encode()
        elif self.path == "/sitemap-index.xml":
            body = (
                "<?xml version='1.0'?>"
                "<sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                "<sitemap><loc>{}/sitemap-pages.xml</loc></sitemap>"
                "<sitemap><loc>https://outside.invalid/evil.xml</loc></sitemap>"
                "<sitemap><loc>http://127.0.0.1:1/other-port.xml</loc></sitemap>"
                "</sitemapindex>".format(type(self).base_url)
            ).encode()
        elif self.path == "/sitemap-pages.xml":
            body = (
                "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                "<url><loc>{}/from-sitemap</loc></url>"
                "<url><loc>https://outside.invalid/evil</loc></url>"
                "<url><loc>http://127.0.0.1:1/internal</loc></url>"
                "</urlset>".format(type(self).base_url)
            ).encode()
        elif self.path == "/sitemap.xml":
            body = type(self).sitemap_body
        else:
            body = b"<html>fixture page</html>"
        self.send_response(200)
        self.send_header("Content-Type", "application/xml" if b"<urlset" in body or b"<sitemapindex" in body else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class CrawlerDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        _DiscoveryHandler.base_url = "http://127.0.0.1:{}".format(cls.server.server_address[1])
        cls.start_url = _DiscoveryHandler.base_url + "/start"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        _DiscoveryHandler.requested_paths.clear()
        _DiscoveryHandler.robots_body = None
        _DiscoveryHandler.sitemap_body = b""

    def _without_environment_proxy(self):
        original = urllib.request.build_opener

        def build_opener(*handlers):
            return original(urllib.request.ProxyHandler({}), *handlers)

        return patch.object(urllib.request, "build_opener", side_effect=build_opener)

    def test_robots_and_sitemap_routes_are_discovered_on_same_domain(self):
        with self._without_environment_proxy():
            discovered = crawler.discover_robots_sitemap_urls(self.start_url)
        paths = {urllib.parse.urlparse(url).path for url in discovered}
        self.assertIn("/private", paths)
        self.assertIn("/public", paths)
        self.assertIn("/from-sitemap", paths)
        self.assertNotIn("/wild*card", paths)
        self.assertFalse(any("outside.invalid" in url for url in discovered))
        self.assertFalse(any(":1/" in url for url in discovered))
        self.assertEqual(
            _DiscoveryHandler.requested_paths,
            ["/robots.txt", "/sitemap-index.xml", "/sitemap.xml", "/sitemap-pages.xml"],
        )

    def test_crawl_visits_discovered_sitemap_paths_within_page_budget(self):
        with self._without_environment_proxy():
            result = crawler.crawl(self.start_url, max_depth=1, max_pages=10)
        endpoint_paths = {entry["path"] for entry in result["endpoints"]}
        self.assertIn("/from-sitemap", endpoint_paths)
        self.assertIn("/from-sitemap", {urllib.parse.urlparse(url).path for url in result["discovered_urls"]})

    def test_entity_declarations_are_rejected_and_path_count_is_bounded(self):
        with self._without_environment_proxy():
            limited = crawler.discover_robots_sitemap_urls(self.start_url, max_paths=1)
        self.assertEqual(len(limited), 1)

        _DiscoveryHandler.requested_paths.clear()
        _DiscoveryHandler.robots_body = b"User-agent: *\n"
        _DiscoveryHandler.sitemap_body = (
            b"<!DOCTYPE urlset [<!ENTITY xxe SYSTEM 'http://127.0.0.1/secret'>]>"
            b"<urlset><url><loc>&xxe;</loc></url></urlset>"
        )
        with self._without_environment_proxy():
            discovered = crawler.discover_robots_sitemap_urls(self.start_url, max_paths=10)
        self.assertEqual(discovered, [])
        self.assertNotIn("/secret", _DiscoveryHandler.requested_paths)


if __name__ == "__main__":
    unittest.main()
