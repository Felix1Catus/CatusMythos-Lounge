"""Local-only intentionally vulnerable benchmark app for authorization/workflow tests."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class BenchmarkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        role = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if self.path.startswith("/api/orders/"):
            object_id = self.path.rsplit("/", 1)[-1]
            if object_id not in ("101", "202"):
                self.send_error(404)
                return
            # Intentional BOLA: records identify their owner but no role check is done.
            owner = "alice" if object_id == "101" else "bob"
            self._json(200, {"id": int(object_id), "owner": owner})
            return
        if self.path == "/api/reports":
            # Intentional BFLA: a member role reaches an administrator function.
            self._json(200, {"reports": ["quarterly"]})
            return
        if self.path in ("/checkout/start", "/checkout/review", "/checkout/confirm"):
            # Intentional workflow skip: later steps accept a fresh session.
            self._json(200, {"step": self.path.rsplit("/", 1)[-1], "role": role})
            return
        self.send_error(404)

    def _json(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def serve():
    """Bind loopback only; callers own shutdown and must never expose externally."""
    return ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
