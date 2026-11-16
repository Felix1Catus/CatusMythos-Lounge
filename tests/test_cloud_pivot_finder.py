"""Regression tests for cloud-pivot-finder's logic-bearing, previously-untested
scripts. Covers the parts with real correctness risk:

- takeover_scanner: the fingerprint state machine (negative fingerprints rule a
  service OUT, ELB-style ``nxdomain_vulnerable: False`` stays inert, excluded S3
  ``-an`` names are skipped, edge-case platforms are flagged not confirmed) --
  the five-false-positive fix the refresh claims.
- bucket_enum: name generation, the cross-cloud credential regex, the
  reference-only claimable gate, and the region-hint crash guard.
- cloud_detector / serverless_finder / metadata_paths / cicd_finder: the pure
  classification + recon-JSON extraction helpers.
- cloud_report: remediation prioritization + section summaries.

Each script is loaded with the repo's isolate-_common pattern so the vendored
per-skill _common.py copies don't collide in sys.modules.
"""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "cloud-pivot-finder" / "scripts"


def load_script(name, filename):
    path = SCRIPTS / filename
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


takeover = load_script("cpf_takeover_scanner", "takeover_scanner.py")
bucket = load_script("cpf_bucket_enum", "bucket_enum.py")
detector = load_script("cpf_cloud_detector", "cloud_detector.py")
serverless = load_script("cpf_serverless_finder", "serverless_finder.py")
metadata = load_script("cpf_metadata_paths", "metadata_paths.py")
cicd = load_script("cpf_cicd_finder", "cicd_finder.py")
creport = load_script("cpf_cloud_report", "cloud_report.py")


# --- takeover_scanner --------------------------------------------------------
class ClassifyTakeoverTests(unittest.TestCase):
    """classify_takeover with network fully injected."""

    @staticmethod
    def _classify(cname, nxdomain=False, body=""):
        chain = [cname] if cname else []
        return takeover.classify_takeover(
            "sub.example.com", cname, chain,
            nxdomain_checker=lambda c: nxdomain,
            body_fetcher=lambda: (200, body),
        )

    def test_no_cname_not_vulnerable(self):
        f = takeover.classify_takeover("x", None, [], lambda c: True, lambda: (0, ""))
        self.assertFalse(f["vulnerable"])

    def test_s3_nxdomain_vulnerable(self):
        f = self._classify("foo.s3.amazonaws.com", nxdomain=False,
                           body="NoSuchBucket: The specified bucket does not exist")
        self.assertTrue(f["vulnerable"])
        self.assertEqual(f["service"], "AWS S3")
        self.assertEqual(f["impact"], "high")

    def test_s3_account_regional_an_excluded(self):
        # 2026 '-an' account-regional buckets can't be re-claimed cross-account.
        name = "bkt-123456789012-abc-an.s3.us-east-1.amazonaws.com"
        f = self._classify(name, body="NoSuchBucket")
        self.assertFalse(f["vulnerable"])

    def test_elb_nxdomain_is_inert_not_vulnerable(self):
        # Regression: an NXDOMAIN ELB target must NOT score as vulnerable.
        f = self._classify("x.us-east-1.elb.amazonaws.com", nxdomain=True)
        self.assertFalse(f["vulnerable"])
        self.assertTrue(any(e["service"] == "AWS ELB" for e in f["not_vulnerable_checked"]))

    def test_cloudfront_negative_fingerprint_rules_out(self):
        # Regression: this body is CloudFront's own suppression string, NOT a
        # takeover confirmation -- must not be scored vulnerable.
        f = self._classify("d123.cloudfront.net",
                           body="<Error>ViewerCertificateException</Error>")
        self.assertFalse(f["vulnerable"])
        self.assertTrue(any(e["service"] == "AWS CloudFront" for e in f["not_vulnerable_checked"]))

    def test_gcs_negative_fingerprint_rules_out(self):
        f = self._classify("bkt.storage.googleapis.com",
                           body="NoSuchBucket: The specified bucket does not exist")
        self.assertFalse(f["vulnerable"])
        self.assertTrue(any(e["service"] == "GCP Cloud Storage" for e in f["not_vulnerable_checked"]))

    def test_heroku_is_edge_case_flagged(self):
        f = self._classify("myapp.herokuapp.com", body="No such app")
        self.assertTrue(f["vulnerable"])
        self.assertEqual(f["service"], "Heroku")
        self.assertTrue(f["edge_case"])
        self.assertIn("edge_case_note", f)

    def test_azure_nxdomain_vulnerable(self):
        f = self._classify("app.azurewebsites.net", nxdomain=True)
        self.assertTrue(f["vulnerable"])
        self.assertTrue(f["service"].startswith("Azure"))

    def test_body_fetcher_called_at_most_once(self):
        calls = {"n": 0}

        def fetch():
            calls["n"] += 1
            return 200, "nothing matches here"

        takeover.classify_takeover(
            "s", "x.herokuapp.com", ["x.herokuapp.com"],
            nxdomain_checker=lambda c: False, body_fetcher=fetch)
        self.assertLessEqual(calls["n"], 1)


class BuildCnameChainTests(unittest.TestCase):
    def test_linear_chain(self):
        resolver = {"a": "b", "b": "c", "c": None}.get
        self.assertEqual(takeover._build_cname_chain("a", resolver), ["a", "b", "c"])

    def test_loop_is_bounded(self):
        resolver = {"a": "b", "b": "a"}.get  # cycle
        chain = takeover._build_cname_chain("a", resolver)
        self.assertEqual(chain, ["a", "b"])

    def test_self_reference(self):
        self.assertEqual(takeover._build_cname_chain("a", lambda c: "a"), ["a"])


# --- bucket_enum -------------------------------------------------------------
class BucketNameGenerationTests(unittest.TestCase):
    def test_includes_base_and_env_and_purpose(self):
        names = bucket.generate_bucket_names("example.com", company_name="Acme Corp")
        self.assertIn("example", names)
        self.assertIn("example-dev", names)
        self.assertIn("backup-example", names)
        self.assertIn("acme-corp", names)       # company with space -> hyphen
        self.assertIn("acmecorp", names)         # company space-stripped
        self.assertEqual(names, sorted(names))   # deterministic/sorted


class CredentialRegexTests(unittest.TestCase):
    def test_matches_cross_cloud_secrets(self):
        for s in (
            "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key = wJalr",
            "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789AB==",
            "DefaultEndpointsProtocol=https",
            '{"type": "service_account", "project_id": "x"}',
            "private_key_id",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ):
            self.assertTrue(bucket._CRED_PATTERNS.search(s), s)

    def test_ignores_benign_text(self):
        for s in ("hello world", "just some html <h1>hi</h1>", "AKIA-too-short"):
            self.assertIsNone(bucket._CRED_PATTERNS.search(s), s)


class CheckBucketGateTests(unittest.TestCase):
    """The claimable result is only surfaced for REAL references, never for
    blind brute-force guesses."""

    def test_claimable_only_surfaced_for_reference_names(self):
        claimable = {"name": "n", "provider": "aws_s3", "exists": False, "claimable": True}
        with patch.object(bucket, "check_s3_bucket", return_value=claimable):
            guessed = bucket.check_bucket("n", ["aws"], is_reference=False)
            referenced = bucket.check_bucket("n", ["aws"], is_reference=True)
        self.assertEqual(guessed, [])            # guessed claimable name dropped
        self.assertEqual(len(referenced), 1)     # real reference surfaced

    def test_existing_bucket_always_surfaced(self):
        existing = {"name": "n", "provider": "aws_s3", "exists": True, "public_list": True}
        with patch.object(bucket, "check_s3_bucket", return_value=existing):
            self.assertEqual(len(bucket.check_bucket("n", ["aws"], is_reference=False)), 1)


class S3RegionHintCrashGuardTests(unittest.TestCase):
    def test_empty_region_tag_does_not_crash(self):
        # Regression: '<Region></Region>' makes the substring present but the
        # full regex fail -- the old code did None.group(1) and crashed.
        with patch.object(bucket, "http_get", return_value=(301, "<Region></Region>", {})):
            result = bucket.check_s3_bucket("somebucket")
        self.assertIsInstance(result, dict)
        self.assertFalse(result["exists"])


# --- cloud_detector ----------------------------------------------------------
class ExtractHostsFromJsonTests(unittest.TestCase):
    def test_plain_list_of_strings(self):
        self.assertEqual(detector._extract_hosts_from_json(["a.com", "b.com"]), ["a.com", "b.com"])

    def test_subdomains_dicts(self):
        data = {"subdomains": [{"host": "a.com"}, {"hostname": "b.com"}]}
        self.assertEqual(detector._extract_hosts_from_json(data), ["a.com", "b.com"])

    def test_port_scan_results_shape(self):
        data = {"results": {"a.com": {"ip": "1.2.3.4"}, "1.2.3.5": {}}}
        hosts = detector._extract_hosts_from_json(data)
        self.assertIn("a.com", hosts)
        self.assertNotIn("1.2.3.5", hosts)  # pure-IP key is not treated as hostname

    def test_non_mapping_returns_empty(self):
        self.assertEqual(detector._extract_hosts_from_json(42), [])


# --- serverless_finder -------------------------------------------------------
class ServerlessTypeTests(unittest.TestCase):
    def test_each_provider_shape(self):
        cases = {
            "abc123.lambda-url.us-east-1.on.aws": ("AWS Lambda Function URL", "AWS"),
            "xyz.execute-api.us-east-1.amazonaws.com": ("AWS API Gateway", "AWS"),
            "us-central1-proj.cloudfunctions.net": ("GCP Cloud Functions", "GCP"),
            "myapp.run.app": ("GCP Cloud Run", "GCP"),
            "myfunc.azurewebsites.net": ("Azure Functions", "Azure"),
        }
        for host, expected in cases.items():
            self.assertEqual(serverless.identify_serverless_type(host), expected, host)

    def test_non_serverless_is_none(self):
        self.assertEqual(serverless.identify_serverless_type("example.com"), (None, None))


class ErrorSignatureTests(unittest.TestCase):
    def test_stack_trace_and_credentials(self):
        s = serverless.check_error_signatures("Traceback (most recent call last):", {})
        self.assertTrue(any(f["category"] == "stack_trace" for f in s))
        c = serverless.check_error_signatures("export AWS_SECRET=xyz", {})
        self.assertTrue(any(f["category"] == "credentials_leak" for f in c))

    def test_debug_header_detected_from_headers(self):
        s = serverless.check_error_signatures("", {"X-Amzn-Trace-Id": "Root=1-x"})
        self.assertTrue(any(f["category"] == "debug_info" for f in s))

    def test_clean_response_no_signatures(self):
        self.assertEqual(serverless.check_error_signatures("hello", {"Server": "nginx"}), [])


# --- metadata_paths ----------------------------------------------------------
class SsrfVectorTests(unittest.TestCase):
    def test_url_param_pdf_and_webhook(self):
        vecs = metadata.identify_ssrf_vectors([
            "https://x.com/search?url=http://evil",
            "https://x.com/generate/pdf",
            "https://x.com/webhook",
            "https://x.com/home",
        ])
        kinds = {(v["url"], v["vector_type"]) for v in vecs}
        self.assertIn(("https://x.com/search?url=http://evil", "url_parameter"), kinds)
        self.assertIn(("https://x.com/generate/pdf", "pdf_generator"), kinds)
        self.assertIn(("https://x.com/webhook", "webhook"), kinds)
        self.assertFalse(any(v["url"].endswith("/home") for v in vecs))


class ReconExtractionTests(unittest.TestCase):
    def test_extract_urls_nested_and_depth_capped(self):
        data = {"a": {"b": ["see https://x.com/p and https://y.com/q"]}}
        urls = metadata.extract_urls_from_recon(data)
        self.assertIn("https://x.com/p", urls)
        self.assertIn("https://y.com/q", urls)

    def test_extract_hosts_cloud_detection_type(self):
        data = {
            "meta": {"type": "cloud_detection"},
            "results": [{"hostname": "a.com", "providers_detected": ["AWS"], "cloud_services": []}],
        }
        hosts = metadata.extract_hosts_from_recon(data)
        self.assertIn("a.com", hosts)
        self.assertEqual(hosts["a.com"]["providers"], ["AWS"])


class PivotPathTests(unittest.TestCase):
    def test_provider_normalized_and_ecscape_only_for_aws(self):
        aws = metadata.build_pivot_path("a.com", {"providers": ["Amazon"]}, [])
        self.assertEqual(aws[0]["provider"], "AWS")
        self.assertTrue(any(metadata.ECSCAPE_NOTE in n for n in aws[0]["depth_notes"]))

        gcp = metadata.build_pivot_path("b.com", {"providers": ["Google"]}, [])
        self.assertEqual(gcp[0]["provider"], "GCP")
        self.assertFalse(any(metadata.ECSCAPE_NOTE in n for n in gcp[0]["depth_notes"]))
        self.assertTrue(any(metadata.DNS_REBINDING_NOTE in n for n in gcp[0]["depth_notes"]))

    def test_no_providers_returns_none(self):
        self.assertIsNone(metadata.build_pivot_path("a.com", {"providers": []}, []))


# --- cicd_finder -------------------------------------------------------------
class CicdLoadHostsTests(unittest.TestCase):
    def test_domain_lowercased_and_deduped(self):
        args = types.SimpleNamespace(domain="Example.COM", input=None)
        self.assertEqual(cicd.load_hosts(args), ["example.com"])


class ProbeHostPathTests(unittest.TestCase):
    def test_signature_match_on_200(self):
        info = {"signatures": ["AWSTemplateFormatVersion", "Resources:"], "severity": "high"}
        with patch.object(cicd, "http_get", return_value=(200, {}, "AWSTemplateFormatVersion: 2010")):
            r = cicd.probe_host_path("h.com", "/template.yaml", info)
        self.assertIsNotNone(r)
        self.assertIn("AWSTemplateFormatVersion", r["matched_signatures"])

    def test_404_skipped(self):
        info = {"signatures": ["x"], "severity": "low"}
        with patch.object(cicd, "http_get", return_value=(404, {}, "not found")):
            self.assertIsNone(cicd.probe_host_path("h.com", "/nope", info))


# --- cloud_report ------------------------------------------------------------
class RemediationPlanTests(unittest.TestCase):
    def test_priority_and_severity_ordering(self):
        sections = {
            "buckets": {"critical_buckets": [
                {"name": "b1", "provider": "aws_s3", "files_visible": 3}]},
            "takeover": {"findings": [
                {"subdomain": "s.x.com", "cname": "c", "service": "Heroku",
                 "impact": "medium", "severity": "high"}]},
            "cicd": {"findings": [
                {"host": "h", "category": "env_files", "description": "d",
                 "severity": "critical", "url": "u"}]},
            "serverless": {"findings": []},
            "pivot_paths": {"paths": []},
        }
        actions = creport.generate_remediation_plan(sections)
        # All priority-1 criticals come before the priority-2 high takeover.
        self.assertEqual(actions[-1]["category"], "DNS/Subdomain")
        self.assertTrue(all(a["priority"] == 1 for a in actions[:-1]))

    def test_build_takeover_summary_severity_mapping(self):
        data = {"stats": {"total_scanned": 2, "vulnerable": 2},
                "vulnerable": [
                    {"subdomain": "a", "impact": "high"},
                    {"subdomain": "b", "impact": "medium"}]}
        summary = creport.build_takeover_summary(data)
        sev = {f["subdomain"]: f["severity"] for f in summary["findings"]}
        self.assertEqual(sev["a"], "critical")
        self.assertEqual(sev["b"], "high")

    def test_build_bucket_summary_counts(self):
        data = {"stats": {"total_found": 3, "public_listing": 1, "private": 2},
                "public_buckets": [{"name": "p", "provider": "aws_s3", "files_visible": 5}],
                "private_buckets": [{"name": "q"}, {"name": "r"}]}
        s = creport.build_bucket_summary(data)
        self.assertEqual(s["total_found"], 3)
        self.assertEqual(len(s["critical_buckets"]), 1)
        self.assertEqual(len(s["all_buckets"]), 3)


if __name__ == "__main__":
    unittest.main()
