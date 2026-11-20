"""Acceptance gate fails closed for misses, false confirms, and unresolved cases."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_gate", ROOT / "scripts" / "check_release_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def test_gate_passes_only_all_confirmed_positives_and_clean_negative_controls():
    report = {"cases": [
        {"id": "sqli", "expected": "vulnerable", "status": "confirmed"},
        {"id": "xss", "expected": "vulnerable", "status": "confirmed"},
        {"id": "safe-fallback", "expected": "not_vulnerable", "status": "tested_negative"},
    ]}
    assert gate.evaluate_release_gate(report)["ready"] is True


def test_candidate_and_false_confirm_fail_gate():
    report = {"cases": [
        {"id": "sqli", "expected": "vulnerable", "status": "candidate"},
        {"id": "safe-fallback", "expected": "not_vulnerable", "status": "confirmed"},
    ]}
    result = gate.evaluate_release_gate(report)
    assert result["ready"] is False
    assert len(result["failures"]) == 2


def test_unknown_labels_are_not_accepted_in_release_suite():
    report = {"cases": [{"id": "unknown", "expected": "unknown", "status": "tested_negative"}]}
    assert gate.evaluate_release_gate(report)["ready"] is False
