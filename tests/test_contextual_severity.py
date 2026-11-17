"""Regression matrix for evidence-linked contextual business severity."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "skills" / "vuln-chain-composer" / "scripts"


def load_script(name, filename):
    path = SCRIPT_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    original_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
        sys.modules.pop("_common", None)
        if original_common is not None:
            sys.modules["_common"] = original_common
    return module


context = load_script("vcc_context_severity", "context_severity.py")
impact = load_script("vcc_context_impact", "calculate_impact.py")
report = load_script("vcc_context_report", "generate_report.py")
importer = load_script("vcc_context_importer", "import_findings.py")
correlator = load_script("vcc_context_correlator", "correlate.py")


def profile(host, *, service, purpose, criticality, sensitivity, scope, evidence,
            impact_evidence="Confirmed finding evidence ties the issue to this service.",
            source="owner inventory"):
    return {
        "host": host,
        "service_name": service,
        "purpose": purpose,
        "business_criticality": criticality,
        "data_sensitivity": sensitivity,
        "affected_scope": scope,
        "evidence": evidence,
        "impact_evidence": impact_evidence,
        "source": source,
    }


class TestContextDocument(unittest.TestCase):
    def test_schema_and_host_normalization(self):
        records = context.load_context_document({
            "schema_version": 1,
            "assets": [profile("HTTPS://Blog.Example.Test/", service="Public blog",
                               purpose="Publishes public articles", criticality="low",
                               sensitivity="public", scope="individual", evidence="No accounts or private data.")],
        })
        self.assertEqual(records[0]["host"], "blog.example.test")

    def test_rejects_unknown_schema_enum_and_missing_evidence(self):
        asset = profile("blog.example.test", service="Blog", purpose="Public articles",
                        criticality="low", sensitivity="public", scope="individual", evidence="Owner inventory")
        with self.assertRaisesRegex(ValueError, "schema_version"):
            context.load_context_document({"schema_version": 2, "assets": [asset]})
        invalid = dict(asset, data_sensitivity="secret")
        with self.assertRaisesRegex(ValueError, "data_sensitivity"):
            context.load_context_document({"schema_version": 1, "assets": [invalid]})
        invalid = dict(asset, evidence="")
        with self.assertRaisesRegex(ValueError, "requires evidence"):
            context.load_context_document({"schema_version": 1, "assets": [invalid]})
        invalid = dict(asset, impact_evidence="")
        with self.assertRaisesRegex(ValueError, "requires impact_evidence"):
            context.load_context_document({"schema_version": 1, "assets": [invalid]})

    def test_rejects_duplicate_hosts(self):
        asset = profile("blog.example.test", service="Blog", purpose="Public articles",
                        criticality="low", sensitivity="public", scope="individual", evidence="Owner inventory")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            context.load_context_document({"schema_version": 1, "assets": [asset, asset]})

    def test_rejects_malformed_or_credentialed_hosts(self):
        asset = profile("blog.example.test", service="Blog", purpose="Public articles",
                        criticality="low", sensitivity="public", scope="individual", evidence="Owner inventory")
        for host in ("bad host", "https://user:pass@blog.example.test", "blog.example.test:bad"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "valid host"):
                context.load_context_document({"schema_version": 1, "assets": [dict(asset, host=host)]})


class TestContextualAssessment(unittest.TestCase):
    def setUp(self):
        self.chain = {
            "name": "Same confirmed issue", "confidence": "confirmed", "overall_severity": "MEDIUM",
            "primary_finding": {"id": "f1", "type": "idor", "domain": "blog.example.test"},
            "supporting_findings": [],
        }
        self.blog = context.load_context_document({"schema_version": 1, "assets": [profile(
            "blog.example.test", service="Public blog", purpose="Publishes public articles",
            criticality="low", sensitivity="public", scope="individual",
            evidence="Owner inventory says no login, personal data, or customer workflow.",
        )]})
        self.payments = context.load_context_document({"schema_version": 1, "assets": [profile(
            "blog.example.test", service="Tenant payments API", purpose="Processes tenant card payments and refunds",
            criticality="critical", sensitivity="restricted", scope="multi_tenant",
            evidence="Payment data inventory and tenant architecture review.", source="risk-register/payments",
        )]})

    def test_same_technical_finding_gets_contextual_difference(self):
        blog_result = impact.calculate_chain_cvss(self.chain, self.blog)
        payment_result = impact.calculate_chain_cvss(self.chain, self.payments)
        self.assertEqual(blog_result["severity"], payment_result["severity"])
        self.assertEqual(blog_result["business_context"]["contextual_severity"], "LOW")
        self.assertEqual(payment_result["business_context"]["contextual_severity"], "CRITICAL")
        self.assertIn("risk-register/payments", payment_result["business_context"]["matched_assets"][0]["source"])

    def test_context_never_changes_technical_cvss_or_chain_severity(self):
        without = impact.calculate_chain_cvss(self.chain)
        with_profile = impact.calculate_chain_cvss(self.chain, self.payments)
        self.assertEqual(without["cvss_score"], with_profile["cvss_score"])
        self.assertEqual(without["severity"], with_profile["severity"])
        self.assertEqual(with_profile["business_context"]["technical_severity"], with_profile["severity"])

    def test_unconfirmed_chain_gets_only_potential_context(self):
        chain = dict(self.chain, confidence="unconfirmed")
        assessment = context.assess_chain_context(chain, business_context=self.payments, technical_severity="MEDIUM")
        self.assertEqual(assessment["contextual_severity"], None)
        self.assertEqual(assessment["potential_contextual_severity"], "CRITICAL")
        self.assertEqual(assessment["status"], "matched_unconfirmed")

    def test_exact_host_matching_prevents_neighbor_context_bleed(self):
        chain = dict(self.chain)
        chain["primary_finding"] = {"id": "f1", "domain": "api.blog.example.test"}
        assessment = context.assess_chain_context(chain, business_context=self.blog)
        self.assertEqual(assessment["status"], "no_matching_context")
        self.assertIsNone(assessment["contextual_severity"])

    def test_attached_context_from_finding_artifact_is_used(self):
        chain = dict(self.chain)
        chain["primary_finding"] = {
            "id": "f1", "domain": "blog.example.test",
            "business_context": profile("blog.example.test", service="Public blog", purpose="Public articles",
                                         criticality="low", sensitivity="public", scope="individual",
                                         evidence="Asset inventory confirms public-only content."),
        }
        assessment = context.assess_chain_context(chain)
        self.assertEqual(assessment["contextual_severity"], "LOW")

    def test_missing_context_is_explicit_and_does_not_infer_from_type(self):
        assessment = context.assess_chain_context(self.chain, technical_severity="MEDIUM")
        self.assertEqual(assessment["status"], "no_matching_context")
        self.assertIsNone(assessment["contextual_severity"])
        self.assertEqual(assessment["technical_severity"], "MEDIUM")

    def test_report_separates_context_from_cvss_and_labels_assumptions(self):
        assessed = dict(self.chain)
        assessed["chain_severity"] = "MEDIUM"
        assessed["cvss_score"] = 5.4
        assessed["cvss_vector"] = "CVSS:3.1/example"
        assessed["impact_analysis"] = impact.calculate_chain_cvss(self.chain, self.payments)
        rendered = report.generate_hackerone_report(assessed)
        self.assertIn("Business Context (separate from CVSS)", rendered)
        self.assertIn("**Severity:** MEDIUM", rendered)
        self.assertIn("**Contextual severity:** CRITICAL", rendered)
        self.assertIn("not been independently verified", rendered)
        self.assertIn("tenant card payments", rendered)
        self.assertIn("Demonstrated impact:", rendered)

    def test_finding_artifact_context_flows_through_correlation_to_assessment(self):
        redirect = importer.normalize_finding({
            "type": "open_redirect", "url": "https://app.example.test/go", "parameter": "next",
            "severity": "LOW", "evidence": "redirects to https://internal.corp/",
            "business_context": profile(
                "app.example.test", service="Tenant payments API", purpose="Processes tenant payments",
                criticality="critical", sensitivity="restricted", scope="multi_tenant",
                evidence="Payment data classification inventory.",
                impact_evidence="Confirmed redirect chain reached the payment response for multiple tenants.",
            ),
        }, "fixture")
        ssrf = importer.normalize_finding({
            "type": "ssrf", "url": "https://app.example.test/fetch", "parameter": "url",
            "severity": "HIGH", "evidence": "allowlist permits internal.corp only",
        }, "fixture")
        chain = next(item for item in correlator.find_chains([redirect, ssrf])
                     if item.get("shared_capability") == "redirect_into_allowlist")
        result = impact.calculate_chain_cvss(chain)
        self.assertEqual(chain["confidence"], "confirmed")
        self.assertEqual(result["business_context"]["contextual_severity"], "CRITICAL")
        self.assertEqual(result["business_context"]["matched_assets"][0]["host"], "app.example.test")

    def test_unconfirmed_report_does_not_present_business_tier_as_assigned(self):
        chain = dict(self.chain, confidence="unconfirmed")
        assessed = dict(chain, chain_severity="MEDIUM", cvss_score=5.4, cvss_vector="CVSS:3.1/example")
        assessed["impact_analysis"] = impact.calculate_chain_cvss(chain, self.payments)
        rendered = report.generate_hackerone_report(assessed)
        self.assertIn("**Potential contextual severity (unconfirmed chain):** CRITICAL", rendered)
        self.assertIn("Business Context (separate from CVSS)", rendered)

    def test_calculate_impact_cli_accepts_context_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chain_path = root / "chains.json"
            context_path = root / "context.json"
            output_path = root / "impact.json"
            chain_path.write_text(json.dumps({"chains": [self.chain]}), encoding="utf-8")
            context_path.write_text(json.dumps({"schema_version": 1, "assets": self.payments}), encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "calculate_impact.py"), "--input", str(chain_path),
                 "--business-context", str(context_path), "--output", str(output_path)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(output_path.read_text(encoding="utf-8"))["chains"][0]
            self.assertEqual(result["chain_severity"], result["impact_analysis"]["severity"])
            self.assertEqual(result["impact_analysis"]["business_context"]["contextual_severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
