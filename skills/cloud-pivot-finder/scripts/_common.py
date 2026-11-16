#!/usr/bin/env python3
"""
Shared helpers for cloud-pivot-finder's scripts.

Vendored per-skill rather than a repo-wide shared module -- this file must
stay importable when someone copies just this one skill directory out of
the plugin (the README documents that install path). Every script in this
skill's scripts/ directory imports from this sibling file instead of
hand-rolling its own copy. A sibling `check_common_sync.py` at the repo
root diffs this file against the other pipeline skills' own `_common.py`
copies and fails loudly if they drift, since they're intentionally
duplicated-by-design across skills, not meant to diverge within one.

Deliberately NOT included here: an `http_get()`/`http_request()` wrapper. This
skill's network-calling scripts (bucket_enum.py, cicd_finder.py,
metadata_paths.py, serverless_finder.py) each have a genuinely different
`http_get()` -- different tuple-return ORDER (bucket_enum.py returns
(status, body, headers); the others return (status, headers, body)),
different tuple length (metadata_paths.py has no headers at all, just
(status, body), plus its own extra_headers parameter), and different
max-body-size defaults. These aren't cosmetic copy-paste drift the way
log/success/warn/vuln are -- blindly unifying them risks a silent,
severe bug (a caller doing `headers.get(...)` would actually be handed
the body string). Left as each file's own local helper rather than forced
into one shared signature without a dedicated call-site audit. A shared
`scoped_urlopen()` below enforces only transport scope; it does not choose a
response tuple shape or body-size limit.
"""


import ssl
import urllib.error
import urllib.parse
import urllib.request


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


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only when scheme, host, and effective port stay fixed."""

    def __init__(self, initial_url):
        self.expected_origin = _http_origin(initial_url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.expected_origin or _http_origin(newurl) != self.expected_origin:
            raise urllib.error.HTTPError(req.full_url, code, "cross-origin redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def scoped_urlopen(request, timeout=10, context=None):
    """Open a request while preventing urllib from forwarding headers off-origin."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    if not _http_origin(url):
        raise ValueError("only credential-free HTTP(S) request URLs are allowed")
    opener = urllib.request.build_opener(
        SameOriginRedirectHandler(url),
        urllib.request.HTTPSHandler(context=context or ssl.create_default_context()),
    )
    return opener.open(request, timeout=timeout)


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def vuln(msg):
    print(f"[!!] {msg}")
