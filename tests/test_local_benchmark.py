"""The repeatable offline benchmark must retain its labeled detector results."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_local_benchmark_test", ROOT / "scripts" / "run_local_benchmark.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_local_benchmark_reports_detected_authz_workflow_and_clean_negative_control():
    report = benchmark.run_benchmark()

    assert report["benchmark"]["external_targets_contacted"] is False
    assert report["benchmark"]["detector_signals"] == {
        "bola_confirmed": True,
        "bfla_confirmed": True,
        "admin_negative_control_alerted": False,
        "sensitive_file_exposure_confirmed": True,
        "workflow_impact_confirmed": True,
        "workflow_cleanup_reset": True,
    }
    assert report["labeled_metrics"]["true_positive"] == 4
    assert report["labeled_metrics"]["false_negative"] == 0
    assert report["labeled_metrics"]["false_positive"] == 0
    assert report["labeled_metrics"]["true_negative"] == 1
