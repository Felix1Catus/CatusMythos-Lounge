"""Value-redaction, origin-scope, and SPA-fallback checks for file exposure testing."""

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "webapp-exploit-hunter" / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    spec = importlib.util.spec_from_file_location("exposure_tester_tests", SCRIPTS / "exposure_tester.py")
    exposure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exposure)
finally:
    sys.path.remove(str(SCRIPTS))


def test_env_sensitive_assignments_confirm_without_emitting_values():
    result = exposure.classify_exposure(
        "/.env", 200, {"Content-Type": "text/plain"},
        "DB_PASSWORD=do-not-print-me\nAPI_TOKEN=fixture-token\n")
    assert result["validated"] is True
    assert result["sensitive_key_names"] == ["DB_PASSWORD", "API_TOKEN"]
    assert "do-not-print-me" not in str(result)
    assert "fixture-token" not in str(result)


def test_html_spa_fallback_is_not_an_exposed_env_file():
    html = "<html><body>app shell</body></html>"
    assert exposure.classify_exposure(
        "/.env", 200, {"Content-Type": "text/html"}, html, html) is None


def test_git_head_reference_is_reported_but_not_raw_values():
    result = exposure.classify_exposure(
        "/.git/HEAD", 200, {"Content-Type": "text/plain"},
        "ref: refs/heads/main\n")
    assert result["type"] == "exposed_git_metadata"
    assert "refs/heads/main" not in str(result)


def test_scan_stays_on_exact_origin_and_emits_only_metadata():
    calls = []

    def request(url, timeout=8):
        calls.append(url)
        if url.endswith("/"):
            return 200, {"Content-Type": "text/html"}, "shell"
        return 200, {"Content-Type": "text/plain"}, "DB_PASSWORD=secret-value\n"

    result = exposure.scan_origin("https://example.test", paths=["/.env"], request_func=request)
    assert calls == ["https://example.test:443/", "https://example.test:443/.env"]
    assert result["meta"]["response_values_recorded"] is False
    assert "secret-value" not in str(result)


def test_rejects_credentials_and_cross_origin_target():
    import pytest

    with pytest.raises(ValueError, match="credential-free"):
        exposure.scan_origin("https://user:pass@example.test")
