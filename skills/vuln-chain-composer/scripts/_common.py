#!/usr/bin/env python3
"""
Shared helpers for vuln-chain-composer's scripts.

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


def cvss_round_up(value):
    """CVSS v3.1 spec Roundup(x): round UP to 1 decimal unless already exact.

    Ordinary round-half-up / math.ceil(x*10)/10 is not equivalent and can
    under-score a result that floating point stored just below a 0.1
    boundary. This integer-math form, from the CVSS v3.1 specification,
    sidesteps that.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def score_to_severity(score):
    """Convert CVSS score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"
