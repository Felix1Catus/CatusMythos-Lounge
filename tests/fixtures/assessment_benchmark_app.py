"""Local-only intentionally vulnerable benchmark app for authorization/workflow tests."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class BenchmarkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        role = self.headers.get("Authorization", "").removeprefix("Bearer ")
        owned_orders = {"alice": (101, "alice"), "member": (202, "member"),
                        "admin": (303, "admin")}
        if self.path == "/api/orders":
            order_id, owner = owned_orders.get(role, (101, "alice"))
            self._json(200, {"orders": [{"id": order_id, "owner": owner}]})
            return
        if self.path.startswith("/api/orders/"):
            object_id = self.path.rsplit("/", 1)[-1]
            owners = {"101": "alice", "202": "member", "303": "admin"}
            if object_id not in owners:
                self.send_error(404)
                return
            # Intentional BOLA: records identify their owner but no role check is done.
            owner = owners[object_id]
            self._json(200, {"id": int(object_id), "owner": owner})
            return
        if self.path == "/api/reports":
            # Intentional BFLA: a member role reaches an administrator function.
            self._json(200, {"reports": ["quarterly"]})
            return
        if self.path == "/api/admin":
            if role != "admin":
                self._json(403, {"error": "forbidden"})
                return
            self._json(200, {"admin": True, "feature_flags": ["fixture"]})
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
