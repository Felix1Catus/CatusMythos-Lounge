"""Opt-in campaign browser run charges browser traffic to the campaign ledger."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from test_assessment_campaign import campaign


ROOT = Path(__file__).resolve().parents[1]


def _browser_available():
    if importlib.util.find_spec("playwright") is None:
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _browser_available(), reason="Playwright Chromium is unavailable")
def test_assess_browser_requests_are_campaign_metered_and_scoped(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><a href='/next'>next</a><input name='q'></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = "http://127.0.0.1:{}/".format(server.server_address[1])
    try:
        manifest = {"schema_version": 1, "engagement": "browser-campaign-fixture",
                    "scope": {"origins": [base], "request_budget": 30},
                    "targets": [{"id": "app", "url": base,
                                 "roles": [{"name": "anonymous"}]}],
                    "steps": [{"id": "browser", "tool": "web_browser", "target": "app",
                               "max_requests": 30, "max_pages": 1}]}
        manifest_path = tmp_path / "manifest.json"
        output_path = tmp_path / "assessment.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        status = campaign.main([
            "assess", "--manifest", str(manifest_path), "--state-db", str(tmp_path / "ledger.sqlite"),
            "--campaign-id", "browser-campaign-fixture", "--output", str(output_path), "--process-only",
        ])
        report = json.loads(output_path.read_text(encoding="utf-8"))
        assert status == 0
        assert report["status"] == "complete"
        assert report["steps"][0]["requests_sent"] > 0
        assert report["steps"][0]["requests_sent"] <= 30
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
