#!/usr/bin/env python3
"""
Shared helpers for attack-path-architect's scripts.

Vendored per-skill rather than a repo-wide shared module -- this file must
stay importable when someone copies just this one skill directory out of
the plugin (the README documents that install path). Every script in this
skill's scripts/ directory imports from this sibling file instead of
hand-rolling its own copy. A sibling `check_common_sync.py` at the repo
root diffs this file against the other pipeline skills' own `_common.py`
copies and fails loudly if they drift, since they're intentionally
duplicated-by-design across skills, not meant to diverge within one.
"""


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")
