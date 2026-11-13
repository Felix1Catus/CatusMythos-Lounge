#!/usr/bin/env python3
"""
Shared helpers for api-breaker's scripts.

Vendored per-skill rather than a repo-wide shared module -- this file must
stay importable when someone copies just this one skill directory out of
the plugin (the README documents that install path). Every script in this
skill's scripts/ directory imports from this sibling file instead of
hand-rolling its own copy. A sibling `check_common_sync.py` at the repo
root diffs this file against the other pipeline skills' own `_common.py`
copies and fails loudly if they drift, since they're intentionally
duplicated-by-design across skills, not meant to diverge within one.
"""

import ssl
import urllib.error
import urllib.request


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def vuln(msg):
    print(f"[!!] VULNERABILITY: {msg}")


def http_request(url, method="GET", headers=None, data=None, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    default_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; orizon-hunter/1.0)",
        "Accept": "application/json, text/html, */*",
    }
    if headers:
        default_headers.update(headers)
    if data and isinstance(data, str):
        data = data.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=default_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read(32768).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, dict(e.headers) if hasattr(e, "headers") else {}, body
    except Exception:
        return 0, {}, ""
