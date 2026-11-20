#!/usr/bin/env python3
"""Fail a release gate on any missed, false-confirmed, or unresolved gold case."""

import argparse
import json
from pathlib import Path


def evaluate_release_gate(report):
    cases = report.get("cases") if isinstance(report, dict) else None
    if not isinstance(cases, list) or not cases:
        return {"ready": False, "checked": 0, "failures": ["report has no cases"]}
    failures = []
    checked = 0
    for case in cases:
        if not isinstance(case, dict):
            failures.append("malformed case entry")
            continue
        case_id, expected, status = case.get("id"), case.get("expected"), case.get("status")
        if not isinstance(case_id, str) or expected not in ("vulnerable", "not_vulnerable"):
            failures.append("{}: case needs a supported labeled expectation".format(case_id or "unknown"))
            continue
        checked += 1
        required = "confirmed" if expected == "vulnerable" else "tested_negative"
        if status != required:
            failures.append("{}: expected {} but got {}".format(case_id, required, status or "untested"))
    return {"ready": checked == len(cases) and not failures,
            "checked": checked, "total": len(cases), "failures": failures,
            "gate_policy": "all vulnerable cases confirmed; all negative controls tested_negative; no unresolved cases"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="coverage JSON from assessment_campaign.py coverage")
    args = parser.parse_args(argv)
    try:
        path = Path(args.report)
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("coverage report exceeds 20 MiB")
        report = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error("cannot read coverage report: {}".format(exc))
    result = evaluate_release_gate(report)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
