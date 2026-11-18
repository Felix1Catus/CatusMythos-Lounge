#!/usr/bin/env python3
"""Run the labeled loopback authz/workflow benchmark and emit coverage metrics."""

import argparse
import contextlib
import importlib.util
import io
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load(name, path, script_dir):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load benchmark component: {}".format(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(script_dir))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
    return module


def run_benchmark():
    fixture_path = ROOT / "tests" / "fixtures" / "assessment_benchmark_app.py"
    fixture = _load("catus_local_benchmark_fixture", fixture_path, fixture_path.parent)
    authz_dir = ROOT / "skills" / "api-breaker" / "scripts"
    authz = _load("catus_local_benchmark_authz", authz_dir / "authz_tester.py", authz_dir)
    web_dir = ROOT / "skills" / "webapp-exploit-hunter" / "scripts"
    exposure = _load("catus_local_benchmark_exposure", web_dir / "exposure_tester.py", web_dir)
    scenario_path = web_dir / "business_scenario.py"
    business_scenario = _load("catus_local_benchmark_scenario", scenario_path, web_dir)
    campaign_path = ROOT / "scripts" / "assessment_campaign.py"
    campaign = _load("catus_local_benchmark_campaign", campaign_path, ROOT / "scripts")

    server = fixture.serve()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = "http://127.0.0.1:{}".format(server.server_port)
    try:
        roles = authz.build_role_matrix([
            ("alice", "alice"), ("member", "member"), ("admin", "admin")])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            bola = authz.test_bola_matrix(
                base, [{"path": "/api/orders", "url": base + "/api/orders"}], roles, delay=0)
            bfla = authz.test_bfla_matrix(base, roles, delay=0)

        scenario = {
            "version": 1,
            "name": "repeat-coupon-impact",
            "fixture_note": "Disposable loopback benchmark cart",
            "setup": [{"method": "POST", "path": "/reset"}],
            "cleanup": [{"method": "POST", "path": "/reset"}],
            "baseline": {
                "actions": [{"method": "POST", "path": "/checkout",
                             "body": {"coupon": "BENCHMARK"}},
                            {"method": "GET", "path": "/cart"}],
                "assertions": [{"pointer": "/coupon_count", "equals": 1}],
            },
            "cases": [{
                "name": "repeat-coupon",
                "actions": [{"method": "POST", "path": "/checkout",
                             "body": {"coupon": "BENCHMARK"}},
                            {"method": "POST", "path": "/checkout",
                             "body": {"coupon": "BENCHMARK"}},
                            {"method": "GET", "path": "/cart"}],
                "impact_assertions": [{"pointer": "/coupon_count", "equals": 2,
                                       "safe_value": 1}],
            }],
        }

        def request(url, method, data, headers):
            request_obj = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
            try:
                with urllib.request.urlopen(request_obj, timeout=5) as response:
                    return response.status, dict(response.headers.items()), response.read(65537).decode("utf-8")
            except urllib.error.HTTPError as error:
                return error.code, dict(error.headers.items()), error.read(65537).decode("utf-8")

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            scenario_result = business_scenario.execute_scenario(
                scenario, base, request, delay=0)
            exposure_result = exposure.scan_origin(base)

        confirmed_bola = any(item.get("type") == "bola" and item.get("validated") is True
                             for item in bola)
        confirmed_bfla = any(item.get("type") == "bfla" and item.get("validated") is True
                             for item in bfla)
        admin_lower_alert = any(item.get("path") == "/api/admin" and
                                item.get("role") in ("alice", "member") and
                                item.get("validated") is True for item in bfla)
        confirmed_workflow = scenario_result.get("validated") is True
        confirmed_exposure = any(item.get("type") == "exposed_secret_configuration"
                                 and item.get("validated") is True
                                 for item in exposure_result["findings"])

        results = [
            {"case_id": "fixture-bola-cross-role",
             "status": "confirmed" if confirmed_bola else "tested_negative",
             "evidence_review": {"schema_version": 1, "assessment_state": "confirmed",
                                 "proof_checks": {"complete": True}}
             if confirmed_bola else None},
            {"case_id": "fixture-bfla-role-crossing",
             "status": "confirmed" if confirmed_bfla else "tested_negative",
             "evidence_review": {"schema_version": 1, "assessment_state": "confirmed",
                                 "proof_checks": {"complete": True}}
             if confirmed_bfla else None},
            {"case_id": "fixture-bfla-admin-denial-control",
             "status": "tested_negative" if not admin_lower_alert else "confirmed",
             "evidence_review": {"schema_version": 1, "assessment_state": "confirmed",
                                 "proof_checks": {"complete": True}}
             if admin_lower_alert else None},
            {"case_id": "fixture-env-secret-disclosure",
             "status": "confirmed" if confirmed_exposure else "tested_negative",
             "evidence_review": {"schema_version": 1, "assessment_state": "confirmed",
                                 "proof_checks": {"complete": True}}
             if confirmed_exposure else None},
            {"case_id": "fixture-workflow-repeat-coupon-impact",
             "status": "confirmed" if confirmed_workflow else "tested_negative",
             "evidence_review": {"schema_version": 1, "assessment_state": "confirmed",
                                 "proof_checks": {"complete": True}}
             if confirmed_workflow else None},
        ]
        manifest_path = ROOT / "doctrine" / "templates" / "ASSESSMENT_LOCAL_BENCHMARK.json"
        manifest = campaign.load_coverage_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
        report = campaign.evaluate_coverage(manifest, results)
        report["benchmark"] = {
            "name": "catus-local-authz-workflow-v2",
            "target": "loopback-only ephemeral fixture",
            "external_targets_contacted": False,
            "detector_signals": {"bola_confirmed": confirmed_bola,
                                 "bfla_confirmed": confirmed_bfla,
                                 "admin_negative_control_alerted": admin_lower_alert,
                                 "sensitive_file_exposure_confirmed": confirmed_exposure,
                                 "workflow_impact_confirmed": confirmed_workflow,
                                 "workflow_cleanup_reset": server.state["coupon_count"] == 0},
            "note": "Small regression benchmark; not an internet-wide detection estimate.",
        }
        return report
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args(argv)
    report = run_benchmark()
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
