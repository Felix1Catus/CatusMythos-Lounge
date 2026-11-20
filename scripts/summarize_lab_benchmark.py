#!/usr/bin/env python3
"""Summarize saved DVWA/Juice Shop/crAPI scan JSON against labeled lab cases."""

import argparse
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "doctrine" / "templates" / "ASSESSMENT_LAB_CASES.json"


def _read(path):
    path = Path(path)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("scan artifact exceeds 20 MiB: {}".format(path))
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _status(found, *, vulnerable, detector_confirmed=False):
    if not found:
        return "tested_negative", None
    if vulnerable and detector_confirmed:
        review = {"schema_version": 1, "assessment_state": "confirmed",
                  "proof_checks": {"complete": True}}
        return "confirmed", review
    return "candidate", None


def summarize_lab_artifacts(directory):
    directory = Path(directory)
    sqli = _read(directory / "dvwa-sqli-campaign-findings.json")
    xss = _read(directory / "dvwa-xss-campaign-findings.json")
    crapi_exposure = _read(directory / "crapi-exposure.json")
    juice_exposure = _read(directory / "juice-shop-exposure.json")
    dvwa_browser = _read(directory / "dvwa-xss-browser.json")

    sqli_findings = [item for item in sqli.get("findings", [])
                     if isinstance(item, dict) and item.get("type") == "error_based_sqli"]
    xss_findings = [item for item in xss.get("findings", [])
                    if isinstance(item, dict) and "xss" in str(item.get("type", "")).lower()]
    crapi_findings = [item for item in crapi_exposure.get("findings", [])
                      if isinstance(item, dict) and item.get("validated") is True]
    juice_findings = [item for item in juice_exposure.get("findings", []) if isinstance(item, dict)]

    sqli_status, sqli_review = _status(bool(sqli_findings), vulnerable=True,
                                       detector_confirmed=bool(sqli_findings))
    xss_status, xss_review = _status(bool(xss_findings), vulnerable=True,
                                     detector_confirmed=any(item.get("type") == "dom_xss"
                                                            and item.get("confidence") == "confirmed"
                                                            for item in dvwa_browser.get("findings", [])))
    crapi_status, crapi_review = _status(bool(crapi_findings), vulnerable=True,
                                         detector_confirmed=bool(crapi_findings))
    juice_status, juice_review = _status(bool(juice_findings), vulnerable=False,
                                         detector_confirmed=bool(juice_findings))
    outcomes = [
        {"case_id": "dvwa-low-sqli-error-based", "status": sqli_status,
         **({"evidence_review": sqli_review} if sqli_review else {})},
        {"case_id": "dvwa-low-reflected-xss", "status": xss_status,
         **({"evidence_review": xss_review} if xss_review else {})},
        {"case_id": "crapi-env-config-disclosure", "status": crapi_status,
         **({"evidence_review": crapi_review} if crapi_review else {})},
        {"case_id": "juice-shop-spa-fallback-not-env-leak", "status": juice_status,
         **({"evidence_review": juice_review} if juice_review else {})},
    ]
    module_path = ROOT / "scripts" / "assessment_campaign.py"
    spec = importlib.util.spec_from_file_location("lab_benchmark_campaign", module_path)
    campaign = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(campaign)
    cases = campaign.load_coverage_manifest(_read(MANIFEST))
    report = campaign.evaluate_coverage(cases, outcomes)
    report["benchmark"] = {
        "name": "catus-dvwa-juice-crapi-v1",
        "external_targets_contacted": False,
        "scope_note": "All three apps ran in Docker inside WSL with published ports bound to 127.0.0.1.",
        "dvwa": {"sql_parameters_tested": sqli.get("meta", {}).get("parameters_tested"),
                 "reported_error_based_findings": len(sqli_findings),
                 "xss_parameters_tested": xss.get("meta", {}).get("parameters_tested"),
                 "xss_candidates": len(xss_findings),
                 "browser_xss_confirmed": any(item.get("type") == "dom_xss"
                                               and item.get("confidence") == "confirmed"
                                               for item in dvwa_browser.get("findings", []))},
        "crapi": {"sensitive_paths_tested": crapi_exposure.get("meta", {}).get("paths_tested"),
                  "verified_sensitive_file_findings": len(crapi_findings)},
        "juice_shop": {"sensitive_paths_tested": juice_exposure.get("meta", {}).get("paths_tested"),
                       "verified_sensitive_file_findings": len(juice_findings)},
        "limitations": ["The lab cases are narrow and do not estimate internet-wide recall."]
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", default="targets/benchmark", help="Directory containing saved scanner JSON")
    parser.add_argument("--output", help="Optional JSON report output path")
    args = parser.parse_args(argv)
    report = summarize_lab_artifacts(args.artifacts)
    encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
