"""Lab summary keeps unresolved candidates out of accuracy denominators."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "lab_benchmark_summary", ROOT / "scripts" / "summarize_lab_benchmark.py")
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def test_summary_requires_both_reflection_and_browser_execution_for_xss(tmp_path):
    artifacts = {
        "dvwa-sqli-campaign-findings.json": {
            "meta": {"parameters_tested": 2},
            "findings": [{"type": "error_based_sqli"}],
        },
        "dvwa-xss-campaign-findings.json": {
            "meta": {"parameters_tested": 1},
            "findings": [{"type": "reflected_xss_candidate", "validated": False}],
        },
        "dvwa-xss-browser.json": {
            "findings": [{"type": "dom_xss", "confidence": "confirmed"}],
        },
        "crapi-exposure.json": {
            "meta": {"paths_tested": 9},
            "findings": [{"type": "exposed_secret_configuration", "validated": True}],
        },
        "juice-shop-exposure.json": {"meta": {"paths_tested": 9}, "findings": []},
    }
    for name, data in artifacts.items():
        (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")

    result = summary.summarize_lab_artifacts(tmp_path)
    metrics = result["labeled_metrics"]
    assert metrics["true_positive"] == 3
    assert metrics["true_negative"] == 1
    assert metrics["false_positive"] == 0
    assert metrics["false_negative"] == 0
    assert metrics["unresolved_labeled"] == 0
    xss = next(case for case in result["cases"] if case["id"] == "dvwa-low-reflected-xss")
    assert xss["status"] == "confirmed"
