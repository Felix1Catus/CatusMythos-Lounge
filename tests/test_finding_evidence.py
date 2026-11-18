"""Regression tests for cross-pipeline evidence review and report integration."""
import importlib.util
import sys
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


if __name__ == "__main__":
    unittest.main()
