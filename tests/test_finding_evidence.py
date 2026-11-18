"""Regression tests for cross-pipeline evidence review and report integration."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop("_common", None)
        if old_common is not None:
            sys.modules["_common"] = old_common
    return module


evidence = load("finding_evidence_contract", ROOT / "scripts" / "finding_evidence.py")
reporter = load("finding_evidence_reporter", ROOT / "skills" / "webapp-exploit-hunter" /
                "scripts" / "vuln_report.py")
importer = load("finding_evidence_importer", ROOT / "skills" / "vuln-chain-composer" /
                "scripts" / "import_findings.py")


def complete_proof():
    return {
        "baseline_observed": True,
        "negative_control_rejected": True,
        "effect_observed": True,
        "reproduced": True,
        "impact_evidence": ["controlled marker appeared in expected output"],
        "private_note": "must not appear in review output",
    }


def context_profile(host, criticality, sensitivity, scope):
    return {"schema_version": 1, "assets": [{
        "host": host, "service_name": "Payment service", "purpose": "Processes tenant payments",
        "business_criticality": criticality, "data_sensitivity": sensitivity,
        "affected_scope": scope, "evidence": "Owner supplied service inventory",
        "impact_evidence": "Finding affects the documented payment workflow",
        "source": "engagement risk register",
    }]}


class EvidenceContractTests(unittest.TestCase):
    def test_complete_proof_requires_all_independent_checks(self):
        review = evidence.evaluate_proof(complete_proof())
        self.assertTrue(review["complete"])
        self.assertEqual(review["impact_evidence_count"], 1)
        for field in ("baseline_observed", "negative_control_rejected", "effect_observed", "reproduced"):
            proof = complete_proof()
            proof[field] = False
            with self.subTest(field=field):
                self.assertFalse(evidence.evaluate_proof(proof)["complete"])

    def test_missing_or_malformed_impact_evidence_prevents_complete_proof(self):
        for impact in ([], "sensitive raw text", ["x" * 501], [42]):
            with self.subTest(impact=impact):
                self.assertFalse(evidence.evaluate_proof(
                    {**complete_proof(), "impact_evidence": impact})["complete"])

    def test_lifecycle_review_does_not_promote_unvalidated_or_legacy_findings(self):
        self.assertEqual(evidence.review_finding({"type": "sqli"})["assessment_state"], "unverified")
        candidate = evidence.review_finding({"type": "xss_candidate", "validated": False,
                                             "proof": complete_proof()})
        self.assertEqual(candidate["assessment_state"], "candidate")
        legacy = evidence.review_finding({"type": "sqli", "validated": True})
        self.assertEqual(legacy["assessment_state"], "validated_needs_proof_review")
        self.assertFalse(legacy["promotion_performed"])

    def test_complete_proof_confirms_only_an_existing_validated_claim(self):
        finding = {"type": "sqli", "validated": True, "proof": complete_proof()}
        self.assertEqual(evidence.review_finding(finding)["assessment_state"], "confirmed")
        finding["validated"] = False
        self.assertEqual(evidence.review_finding(finding)["assessment_state"], "candidate")

    def test_review_never_echoes_proof_payload_or_private_note(self):
        output = str(evidence.review_finding({"type": "sqli", "validated": True,
                                              "proof": complete_proof()}))
        self.assertNotIn("controlled marker", output)
        self.assertNotIn("must not appear", output)

    def test_normalized_import_attaches_review_without_changing_chainability_claim(self):
        candidate = importer.normalize_finding({"type": "reflected_xss_candidate", "validated": False}, "fixture")
        self.assertEqual(candidate["evidence_review"]["assessment_state"], "candidate")
        self.assertEqual(candidate["chainable_as"], [])
        confirmed = importer.normalize_finding({"type": "sqli", "validated": True}, "fixture")
        self.assertEqual(confirmed["evidence_review"]["assessment_state"], "validated_needs_proof_review")
        self.assertTrue(confirmed["chainable_as"])

    def test_json_report_includes_review_but_preserves_original_finding_fields(self):
        finding = {"type": "sqli", "url": "https://app.example.test/a", "validated": True,
                   "proof": complete_proof(), "_severity_rating": "HIGH", "_vuln_class": "sqli"}
        result = reporter.generate_json_report([finding], "fixture", {"target": "fixture"})
        rendered = result["findings"][0]
        self.assertEqual(rendered["evidence_review"]["assessment_state"], "confirmed")
        self.assertTrue(rendered["validated"])
        self.assertNotIn("private_note", str(rendered["evidence_review"]))

    def test_report_business_context_is_evidence_gated_and_kept_separate_from_cvss(self):
        context = context_profile("app.example.test", "critical", "restricted", "multi_tenant")
        confirmed = {"type": "sqli", "url": "https://app.example.test/search", "validated": True,
                     "severity": "MEDIUM", "proof": complete_proof()}
        assessment = reporter.assess_finding_business_context(confirmed, context)
        self.assertEqual(assessment["contextual_severity"], "CRITICAL")
        self.assertEqual(assessment["technical_severity"], "MEDIUM")

        unproven = {"type": "sqli", "url": "https://app.example.test/search", "validated": True,
                    "severity": "MEDIUM"}
        assessment = reporter.assess_finding_business_context(unproven, context)
        self.assertIsNone(assessment["contextual_severity"])
        self.assertEqual(assessment["potential_contextual_severity"], "CRITICAL")

    def test_report_business_context_does_not_bleed_to_neighbor_subdomain(self):
        context = context_profile("app.example.test", "critical", "restricted", "multi_tenant")
        finding = {"type": "sqli", "url": "https://api.app.example.test/search", "validated": True,
                   "severity": "MEDIUM", "proof": complete_proof()}
        assessment = reporter.assess_finding_business_context(finding, context)
        self.assertEqual(assessment["status"], "no_matching_context")
        self.assertIsNone(assessment["contextual_severity"])

    def test_report_cli_emits_context_tier_without_replacing_technical_severity(self):
        report_script = ROOT / "skills" / "webapp-exploit-hunter" / "scripts" / "vuln_report.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            findings_path, context_path, output_base = (root / "findings.json", root / "context.json",
                                                        root / "report")
            findings_path.write_text(json.dumps({"meta": {"target": "app.example.test"}, "findings": [
                {"type": "sqli", "url": "https://app.example.test/search", "validated": True,
                 "severity": "MEDIUM", "proof": complete_proof()},
                {"type": "xss", "url": "https://app.example.test/profile", "validated": True,
                 "severity": "LOW"},
            ]}), encoding="utf-8")
            context_path.write_text(json.dumps(context_profile(
                "app.example.test", "critical", "restricted", "multi_tenant")), encoding="utf-8")
            run = subprocess.run([sys.executable, str(report_script), "--findings", str(findings_path),
                                  "--format", "json", "--output", str(output_base),
                                  "--business-context", str(context_path)],
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            output = json.loads(Path(str(output_base) + ".json").read_text(encoding="utf-8"))
        confirmed, unproven = output["findings"]
        self.assertEqual(confirmed["severity"], "MEDIUM")
        self.assertEqual(confirmed["business_context_assessment"]["contextual_severity"], "CRITICAL")
        self.assertEqual(unproven["severity"], "LOW")
        self.assertEqual(unproven["business_context_assessment"]["potential_contextual_severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
