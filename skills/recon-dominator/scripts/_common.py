#!/usr/bin/env python3
"""
Shared helpers for recon-dominator's scripts.

Vendored per-skill rather than a repo-wide shared module -- this file must
stay importable when someone copies just this one skill directory out of
the plugin (the README documents that install path). Every script in this
skill's scripts/ directory imports from this sibling file instead of
hand-rolling its own copy. A sibling `check_common_sync.py` at the repo
root diffs this file against the other pipeline skills' own `_common.py`
copies and fails loudly if they drift, since they're intentionally
duplicated-by-design across skills, not meant to diverge within one.
"""

import os
import ssl
import urllib.error
import urllib.parse
import urllib.request


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def _http_origin(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if (
            scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        if port == 0:
            return None
        return scheme, parsed.hostname.lower(), port
    except (TypeError, ValueError):
        return None


def same_origin_url(base_url, candidate):
    """Resolve a URL only when it remains on the base HTTP origin."""
    base_origin = _http_origin(base_url)
    if not base_origin:
        return None
    try:
        url = urllib.parse.urljoin(base_url, str(candidate or ""))
        if _http_origin(url) != base_origin:
            return None
        parsed = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit(parsed._replace(fragment=""))
    except (TypeError, ValueError):
        return None


def _reserve_campaign_request(url, method="GET"):
    """Reserve through the repository campaign gate when campaign mode is active."""
    if os.environ.get("CATUS_CAMPAIGN_GATE_DB"):
        from campaign_request_gate import reserve_from_environment
        reserve_from_environment(url, method)


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only when scheme, host, and effective port stay fixed."""

    def __init__(self, initial_url):
        self.expected_origin = _http_origin(initial_url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _reserve_campaign_request(newurl, req.get_method())
        if not self.expected_origin or _http_origin(newurl) != self.expected_origin:
            raise urllib.error.HTTPError(req.full_url, code, "cross-origin redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def scoped_urlopen(request, timeout=10, context=None):
    """Open a request while preventing urllib from forwarding headers off-origin."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    if not _http_origin(url):
        raise ValueError("only credential-free HTTP(S) request URLs are allowed")
    method = request.get_method() if isinstance(request, urllib.request.Request) else "GET"
    _reserve_campaign_request(url, method)
    opener = urllib.request.build_opener(
        SameOriginRedirectHandler(url),
        urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
    )
    return opener.open(request, timeout=timeout)


def error(msg):
    print(f"[-] {msg}")


def http_get(url, timeout=15):
    """Simple HTTP GET without external dependencies. Returns the decoded
    body as a string, or None on any failure (logged via warn())."""
    ctx = ssl.create_default_context()
    if os.environ.get("CATUS_INSECURE_TLS") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with scoped_urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        if os.environ.get("CATUS_CAMPAIGN_GATE_DB"):
            from campaign_request_gate import CampaignGateError
            if isinstance(e, CampaignGateError):
                raise
        warn(f"Request failed: {url} - {e}")
        return None
