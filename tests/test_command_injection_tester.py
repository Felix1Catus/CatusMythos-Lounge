"""Offline regression matrix for harmless command-injection validation."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/webapp-exploit-hunter/scripts/command_injection_tester.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("command_injection_tester_test", SCRIPT)
command = importlib.util.module_from_spec(spec)
spec.loader.exec_module(command)
sys.path.pop(0)


def test_probe_expected_output_is_not_contiguous_in_payload():
    payload, expected = command.make_probe("deadbeefcafe", ";")
    assert expected not in payload
    assert "printf" in payload


def test_probe_rejects_invalid_marker():
    with pytest.raises(ValueError):
        command.make_probe("not-safe;id")


def test_reflected_command_is_not_execution_proof():
    payload, expected = command.make_probe("deadbeefcafe", ";")
    assert not command.response_confirms(payload, expected, payload)
    assert command.response_confirms(payload, expected, "PING output\n" + expected)


def test_builder_preserves_post_siblings_and_submit_controls():
    crawl = {"endpoints": [], "forms": [{
        "url": "https://lab.test/vulnerabilities/exec/", "method": "POST",
        "inputs": [
            {"name": "ip", "type": "text", "value": ""},
            {"name": "Submit", "type": "submit", "value": "Run"},
        ],
    }]}
    targets = command.build_targets(crawl)
    assert targets == [{
        "url": "https://lab.test/vulnerabilities/exec/", "param": "ip",
        "method": "POST", "form_data": {"Submit": "Run"},
    }]


def test_live_probe_requires_unique_printf_output(monkeypatch):
    calls = []

    def fake(url, method="GET", data=None, headers=None, timeout=10):
        calls.append((url, method, data))
        payload = dict(__import__("urllib.parse").parse.parse_qsl(data or "")).get("ip", "")
        expected = ""
        if payload:
            import re
            match = re.search(r"printf '([^']+)' ([a-f0-9]{12})", payload)
            if match:
                expected = match.group(1).replace("%s", match.group(2))
        return 200, {}, "command output: " + expected

    monkeypatch.setattr(command, "http_request", fake)
    findings = command.test_target({
        "url": "https://lab.test/exec", "param": "ip", "method": "POST",
        "form_data": {"Submit": "Run"},
    }, delay=0, token_factory=lambda: "deadbeefcafe")
    assert len(findings) == 1
    assert findings[0]["validated"] is True
    assert len(calls) == 1
    assert "Submit=Run" in calls[0][2]
