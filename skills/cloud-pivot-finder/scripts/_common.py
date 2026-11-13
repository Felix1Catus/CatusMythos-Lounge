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

Deliberately NOT included here: an `http_get()`/`http_request()`. This
skill's four network-calling scripts (bucket_enum.py, cicd_finder.py,
metadata_paths.py, serverless_finder.py) each have a genuinely different
`http_get()` -- different tuple-return ORDER (bucket_enum.py returns
(status, body, headers); the others return (status, headers, body)),
different tuple length (metadata_paths.py has no headers at all, just
(status, body), plus its own extra_headers parameter), and different
max-body-size defaults. These aren't cosmetic copy-paste drift the way
log/success/warn/vuln are -- blindly unifying them risks a silent,
severe bug (a caller doing `headers.get(...)` would actually be handed
the body string). Left as each file's own local helper rather than forced
into one shared signature without a dedicated call-site audit.
"""


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def vuln(msg):
    print(f"[!!] {msg}")
