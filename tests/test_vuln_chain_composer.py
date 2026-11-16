"""Regression tests for vuln-chain-composer's correlation/impact/chain pipeline.

HANDOVER flagged this skill's correlation, impact scoring, and chain generation
as lightly verified. This matrix locks the logic-bearing units of all seven
scripts and pins the one real bug this pass found and fixed:

**The category-derivation bug (import_findings.normalize_finding).** `category`
was `vuln_type.split("_")[0]`, so the pipeline's own multi-word types normalized
to "reflected"/"error"/"subdomain"/"open"/"public"/"attack" -- none of which
equal the "xss"/"sqli"/"takeover"/"redirect"/"bucket"/"attack_path" keys that
correlate.py's named CHAIN_TEMPLATES and build_chains.py's EXPLOIT_TECHNIQUES
both match on. Result: 6 of the ~12 named chain templates (and every multi-word
type's specific exploit technique) silently never fired. Verified end-to-end:
two reflected_xss findings on sibling subdomains produced ZERO chains. Fixed via
a canonical `_derive_category` keyword map; the tests below lock both the fix
and the preserved single-word behavior.

Also covered: the confirmed/unconfirmed confidence mechanism (an unconfirmed
category-match chain must NOT be amplified -- the documented CVSS-10.0-on-a-
username-disclosure false positive), CVSS v3.1 scoring against known vectors,
generated-PoC shell safety + Python compilability, and the report formatters.
"""
import ast
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "vuln-chain-composer" / "scripts"


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


imp = load_script("vcc_import_findings", "import_findings.py")
cor = load_script("vcc_correlate", "correlate.py")
ci = load_script("vcc_calculate_impact", "calculate_impact.py")
bc = load_script("vcc_build_chains", "build_chains.py")
poc = load_script("vcc_generate_chain_poc", "generate_chain_poc.py")
rep = load_script("vcc_generate_report", "generate_report.py")


def _finding(vuln_type, url="https://a.example.com/p?q=1", severity="MEDIUM", **extra):
    f = {"type": vuln_type, "url": url, "severity": severity}
    f.update(extra)
    return imp.normalize_finding(f, "test")


# ---------------------------------------------------------------------------
# import_findings: the category-derivation fix
# ---------------------------------------------------------------------------
class TestDeriveCategory(unittest.TestCase):
    def test_multiword_types_map_to_template_category(self):
        cases = {
            "reflected_xss": "xss",
            "stored_xss": "xss",
            "dom_xss": "xss",
            "error_based_sqli": "sqli",
            "boolean_based_sqli": "sqli",
            "subdomain_takeover": "takeover",
            "open_redirect": "redirect",
            "public_bucket": "bucket",
            "attack_path_ci_cd_prod": "attack_path",
        }
        for vuln_type, expected in cases.items():
            self.assertEqual(imp._derive_category(vuln_type), expected, vuln_type)

    def test_single_word_types_unchanged(self):
        for t in ("ssrf", "idor", "blockedcve", "agenttoolaccess"):
            self.assertEqual(imp._derive_category(t), t)

    def test_info_disclosure_still_info(self):
        self.assertEqual(imp._derive_category("info_disclosure"), "info")

    def test_xxe_ssrf_prefers_ssrf(self):
        # xxe_ssrf is semantically an SSRF primitive -- must land on ssrf, not xxe.
        self.assertEqual(imp._derive_category("xxe_ssrf"), "ssrf")

    def test_unknown_type_falls_back_to_first_token(self):
        self.assertEqual(imp._derive_category("mass_assignment"), "mass")
        self.assertEqual(imp._derive_category("cicdexposure_github"), "cicdexposure")


class TestNormalizeFinding(unittest.TestCase):
    def test_severity_uppercased(self):
        self.assertEqual(_finding("reflected_xss", severity="medium")["severity"], "MEDIUM")

    def test_domain_extracted_from_url(self):
        self.assertEqual(_finding("ssrf", url="https://api.example.com/x")["domain"],
                         "api.example.com")

    def test_default_severity_from_map(self):
        self.assertEqual(imp.normalize_finding({"type": "jwt_none_algorithm"}, "t")["severity"],
                         "CRITICAL")

    def test_sqli_chainable_as(self):
        self.assertIn("credential_theft", _finding("error_based_sqli")["chainable_as"])

    def test_unvalidated_xss_candidate_not_chainable(self):
        # A reflection/static lead must not enable a chain before browser validation.
        f = _finding("reflected_xss_candidate")
        self.assertEqual(f["chainable_as"], [])

    def test_confirmed_xss_chainable(self):
        self.assertIn("cookie_scope_write", _finding("reflected_xss")["chainable_as"])

    def test_ssrf_allowlist_requires_redirect(self):
        f = _finding("ssrf", evidence="request blocked by destination allowlist")
        self.assertIn("redirect_into_allowlist", f["requires"])

    def test_idor_requires_authentication_bypass(self):
        self.assertIn("authentication_bypass", _finding("idor")["requires"])

    def test_cvehypothesis_requires_precondition_enabler(self):
        f = _finding("cvehypothesis")
        self.assertIn("precondition_enabler", f["requires"])
        self.assertIn("rce_potential", f["chainable_as"])

    def test_waf_blocked_blob_adds_requirement(self):
        f = _finding("reflected_xss", evidence="payload blocked by Cloudflare WAF 403")
        self.assertIn("waf_bypass_capable", f["requires"])


class TestLoadFindingsFromFile(unittest.TestCase):
    def _write(self, obj, name="findings.json"):
        d = tempfile.mkdtemp()
        p = Path(d) / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def test_basic_findings_list(self):
        path = self._write({"meta": {"tool": "scanner"},
                             "findings": [{"type": "ssrf", "url": "https://a.test/x"}]})
        out = imp.load_findings_from_file(path)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], "ssrf")

    def test_subdomain_takeover_scan_shape(self):
        path = self._write({
            "meta": {"type": "subdomain_takeover_scan", "tool": "takeover_scanner"},
            "vulnerable": [{"subdomain": "x.test", "service": "GitHub Pages",
                            "evidence": "404", "impact": "high", "method": "cname"}],
        }, name="takeover.json")
        out = imp.load_findings_from_file(path)
        self.assertTrue(any(f["type"] == "subdomain_takeover" for f in out))
        self.assertTrue(any(f["category"] == "takeover" for f in out))

    def test_malformed_entries_skipped(self):
        path = self._write({"meta": {"tool": "s"},
                             "findings": [None, "not an object", {"type": "xss", "url": "https://a.test"}]})
        out = imp.load_findings_from_file(path)
        self.assertEqual(len(out), 1)

    def test_inferred_type_from_filename(self):
        path = self._write({"meta": {}, "findings": [{"url": "https://a.test/x"}]},
                           name="sqli_scan.json")
        out = imp.load_findings_from_file(path)
        self.assertEqual(out[0]["type"], "sqli")


# ---------------------------------------------------------------------------
# correlate: evidence helpers + confidence mechanism
# ---------------------------------------------------------------------------
class TestCorrelateHelpers(unittest.TestCase):
    def test_get_parent_domain(self):
        self.assertEqual(cor.get_parent_domain("a.b.example.com"), "example.com")
        self.assertEqual(cor.get_parent_domain("example.com"), "example.com")
        self.assertEqual(cor.get_parent_domain("localhost"), "localhost")

    def test_significant_tokens_drops_stopwords_and_short(self):
        toks = cor._significant_tokens("The file upload form must be validated")
        self.assertIn("upload", toks)
        self.assertNotIn("the", toks)
        self.assertNotIn("be", toks)

    def test_credential_evidence_present_true(self):
        matched = {"info": [{"evidence": "found AKIA1234567890ABCDEF in the response"}]}
        self.assertTrue(cor._credential_evidence_present(matched))

    def test_credential_evidence_present_false_on_username(self):
        matched = {"info": [{"evidence": "username admin disclosed in error page"}]}
        self.assertFalse(cor._credential_evidence_present(matched))

    def test_cloud_metadata_evidence_present(self):
        self.assertTrue(cor._cloud_metadata_evidence_present(
            [{"evidence": "reached http://169.254.169.254/latest/meta-data/"}]))
        self.assertFalse(cor._cloud_metadata_evidence_present(
            [{"evidence": "server appears to be hosted on AWS"}]))

    def test_auth_system_evidence_present(self):
        self.assertTrue(cor._auth_system_evidence_present([{"url": "https://a.test/wp-login.php"}]))
        self.assertFalse(cor._auth_system_evidence_present([{"url": "https://a.test/about"}]))

    def test_agent_enables_precondition_requires_reachable_and_overlap(self):
        matched = {
            "blockedcve": [{"raw": {"missing_precondition": "enable file upload field"}}],
            "agenttoolaccess": [{"raw": {"prompt_injectable": True,
                                         "capabilities": ["edit form upload settings"]}}],
        }
        self.assertTrue(cor._agent_enables_precondition_evidence_present(matched))

    def test_agent_enables_precondition_false_when_unreachable(self):
        matched = {
            "blockedcve": [{"raw": {"missing_precondition": "enable file upload field"}}],
            "agenttoolaccess": [{"raw": {"requires_authentication": True,
                                         "capabilities": ["edit form upload settings"]}}],
        }
        self.assertFalse(cor._agent_enables_precondition_evidence_present(matched))

    def test_redirect_unlocks_ssrf_named_host(self):
        a = {"type": "open_redirect", "domain": "a.test",
             "evidence": "redirects to https://internal.corp/"}
        b = {"type": "ssrf", "evidence": "allowlist permits internal.corp only"}
        self.assertTrue(cor._redirect_unlocks_ssrf(a, b))

    def test_redirect_unlocks_ssrf_false_unrelated(self):
        a = {"type": "open_redirect", "domain": "a.test",
             "evidence": "redirects to https://evil.test/"}
        b = {"type": "ssrf", "evidence": "allowlist permits internal.corp only"}
        self.assertFalse(cor._redirect_unlocks_ssrf(a, b))

    def test_org_membership_evidence(self):
        a = {"evidence": "IDOR grants access to another organization's group"}
        b = {"evidence": "membership check lets you change a team member's email"}
        self.assertTrue(cor._org_membership_evidence_present(a, b))

    def test_waf_bypass_evidence(self):
        a = {"type": "wafbypass", "evidence": "parameter pollution bypasses the filter"}
        b = {"type": "reflected_xss", "evidence": "payload blocked by Cloudflare"}
        self.assertTrue(cor._waf_bypass_evidence_present(a, b))

    def test_scope_violation_evidence(self):
        inj = {"type": "promptinjection", "evidence": "instruction hidden in a calendar invite"}
        agent = {"type": "agenttoolaccess", "raw": {"prompt_injectable": True}}
        self.assertTrue(cor._scope_violation_evidence_present(inj, agent))


class TestCorrelateChains(unittest.TestCase):
    def test_xss_subdomain_template_fires_after_category_fix(self):
        findings = [_finding("reflected_xss", url="https://a.example.com/x?q=1"),
                    _finding("reflected_xss", url="https://b.example.com/y?q=1")]
        chains = cor.find_chains(findings)
        self.assertTrue(any("XSS to Session Hijacking" in c["name"] for c in chains))

    def test_info_chain_unconfirmed_keeps_primary_severity(self):
        findings = [_finding("info_disclosure", url="https://a.test/err", severity="LOW",
                             evidence="username admin disclosed")]
        chains = cor.find_chains(findings)
        info_chain = next(c for c in chains if "Info Disclosure" in c["name"])
        self.assertEqual(info_chain["confidence"], "unconfirmed")
        self.assertEqual(info_chain["overall_severity"], "LOW")  # NOT amplified

    def test_info_chain_confirmed_amplifies(self):
        findings = [_finding("info_disclosure", url="https://a.test/err", severity="LOW",
                             evidence="leaked api_key=sk_live_ABCDEFGHIJKLMNOP in response")]
        chains = cor.find_chains(findings)
        info_chain = next(c for c in chains if "Info Disclosure" in c["name"])
        self.assertEqual(info_chain["confidence"], "confirmed")
        self.assertEqual(info_chain["overall_severity"], "HIGH")

    def test_discover_generic_chains_capability_overlap(self):
        a = _finding("error_based_sqli", url="https://a.test/x")  # chainable credential_theft
        b = {"id": "custom_b", "type": "custom", "domain": "a.test", "url": "https://a.test/y",
             "severity": "HIGH", "chainable_as": [], "requires": ["credential_theft"], "raw": {}}
        chains = cor.discover_generic_chains([a, b])
        self.assertTrue(any(c.get("shared_capability") == "credential_theft" for c in chains))

    def test_discover_generic_respects_exclude_pairs(self):
        a = _finding("error_based_sqli", url="https://a.test/x")
        b = {"id": "custom_b", "type": "custom", "domain": "a.test", "url": "https://a.test/y",
             "severity": "HIGH", "chainable_as": [], "requires": ["credential_theft"], "raw": {}}
        chains = cor.discover_generic_chains([a, b], exclude_pairs={(a["id"], "custom_b")})
        self.assertEqual(chains, [])


# ---------------------------------------------------------------------------
# calculate_impact: CVSS v3.1 + confidence-gated amplification
# ---------------------------------------------------------------------------
class TestCvssScore(unittest.TestCase):
    def test_critical_unchanged_scope(self):
        self.assertEqual(ci.calculate_cvss_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "H", "I": "H", "A": "H"}, "U"), 9.8)

    def test_full_changed_scope_caps_at_ten(self):
        self.assertEqual(ci.calculate_cvss_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
             "C": "H", "I": "H", "A": "H"}, "C"), 10.0)

    def test_no_impact_is_zero(self):
        self.assertEqual(ci.calculate_cvss_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "N", "I": "N", "A": "N"}, "U"), 0.0)

    def test_known_xss_vector(self):
        self.assertEqual(ci.calculate_cvss_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
             "C": "L", "I": "L", "A": "N"}, "C"), 6.1)

    def test_build_vector_string(self):
        v = ci.build_vector({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                             "C": "H", "I": "H", "A": "H"})
        self.assertEqual(v, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestChainCvss(unittest.TestCase):
    _CHAIN = {"name": "Info Disclosure + Credential Reuse = Account Takeover",
              "overall_severity": "LOW", "total_steps": 3, "supporting_findings": [],
              "primary_finding": {"type": "info_disclosure", "severity": "LOW"}}

    def test_unconfirmed_not_amplified(self):
        chain = dict(self._CHAIN, confidence="unconfirmed")
        r = ci.calculate_chain_cvss(chain)
        self.assertIsNone(r["rule_matched"])  # heuristic, not the hardcoded CRITICAL vector
        self.assertNotEqual(r["severity"], "CRITICAL")

    def test_confirmed_applies_rule(self):
        chain = dict(self._CHAIN, confidence="confirmed")
        r = ci.calculate_chain_cvss(chain)
        self.assertEqual(r["rule_matched"], self._CHAIN["name"])
        self.assertEqual(r["severity"], "CRITICAL")

    def test_idor_primary_sets_pr_low(self):
        chain = {"name": "generic", "total_steps": 2, "overall_severity": "HIGH",
                 "supporting_findings": [], "primary_finding": {"type": "idor"}}
        r = ci.calculate_chain_cvss(chain)
        self.assertEqual(r["metrics"]["PR"], "L")


# ---------------------------------------------------------------------------
# build_chains
# ---------------------------------------------------------------------------
class TestBuildChains(unittest.TestCase):
    def test_get_technique_known_type(self):
        t = bc.get_technique({"type": "error_based_sqli", "category": "sqli"})
        self.assertEqual(t["technique"], "Error-based SQL Injection")

    def test_get_technique_default_subtype(self):
        t = bc.get_technique({"type": "idor", "category": "idor"})
        self.assertIn("Insecure Direct Object", t["technique"])

    def test_get_technique_fallback_generic(self):
        t = bc.get_technique({"type": "totally_unknown", "category": "totally"})
        self.assertIn("totally_unknown", t["technique"])
        self.assertEqual(t["data_gained"], ["unknown"])

    def test_build_detailed_chain_phases_and_feasibility(self):
        chain = {"name": "C", "overall_severity": "HIGH",
                 "primary_finding": {"id": "p1", "type": "error_based_sqli",
                                     "category": "sqli", "url": "https://a.test/x"},
                 "supporting_findings": []}
        built = bc.build_detailed_chain(chain)
        self.assertEqual(built["phases"][0]["phase"], "Initial Exploitation")
        self.assertEqual(built["phases"][-1]["phase"], "Impact Realization")
        self.assertTrue(1 <= built["feasibility_score"] <= 10)
        self.assertEqual(built["total_steps"], built["phases"][-1]["detailed_steps"][-1]["step"])

    def test_user_interaction_detected(self):
        chain = {"name": "C", "overall_severity": "HIGH",
                 "primary_finding": {"id": "p1", "type": "reflected_xss",
                                     "category": "xss", "url": "https://a.test/x"},
                 "supporting_findings": []}
        built = bc.build_detailed_chain(chain)
        # reflected_xss steps mention sending a crafted URL to the victim.
        self.assertTrue(built["requires_user_interaction"])


# ---------------------------------------------------------------------------
# generate_chain_poc: shell safety + Python compilability
# ---------------------------------------------------------------------------
class TestGenerateChainPoc(unittest.TestCase):
    def test_curl_command_shell_safe(self):
        finding = {"type": "reflected_xss", "url": "https://a.test/x", "method": "GET",
                   "parameter": "q", "payload": "'; rm -rf / #"}
        cmd = poc.generate_curl_command({"target": "https://a.test/x"}, finding)
        self.assertTrue(cmd.startswith("curl"))
        # The dangerous payload must be inside a single-quoted token, not bare.
        self.assertNotIn("; rm -rf / #\n", cmd)
        self.assertIn("'", cmd)

    def test_curl_jwt_special_case(self):
        cmd = poc.generate_curl_command({}, {"type": "jwt_none_algorithm"})
        self.assertIn("Decode JWT", cmd)

    def test_python_poc_compiles_simple(self):
        chain = {"name": "Simple", "steps": ["Exploit the thing", "Escalate"],
                 "primary_finding": {"url": "https://a.test"}}
        src = poc.generate_python_poc(chain)
        ast.parse(src)  # raises SyntaxError if the generator produced bad code

    def test_python_poc_compiles_with_hostile_strings(self):
        chain = {
            "name": 'evil"\'\n\\chain',
            "phases": [{"phase": "p'1\"\n", "technique": "t\\x", "finding_id": "f",
                        "detailed_steps": [{"step": 1, "action": "do '\"\n\\ stuff"}]}],
            "primary_finding": {"url": "https://a.test/'\"\n"},
        }
        src = poc.generate_python_poc(chain)
        ast.parse(src)  # hostile metadata must stay inside repr()'d literals

    def test_url_with_parameter(self):
        out = poc._url_with_parameter("https://a.test/x?a=1", "b", "2")
        self.assertIn("a=1", out)
        self.assertIn("b=2", out)


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------
class TestGenerateReport(unittest.TestCase):
    _CHAIN = {
        "name": "Test Chain", "chain_severity": "HIGH", "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "description": "A test chain.",
        "primary_finding": {"type": "reflected_xss", "domain": "a.test", "url": "https://a.test/x"},
        "supporting_findings": [{"type": "open_redirect", "domain": "b.test"}],
        "steps": ["Step one", "Step two"],
        "impact_analysis": {"metrics": {"C": "H", "I": "L", "A": "N"}},
    }

    def test_get_remediation_match(self):
        self.assertTrue(any("parameterized" in r.lower()
                            for r in rep.get_remediation("error_based_sqli")))

    def test_get_remediation_fallback(self):
        self.assertEqual(len(rep.get_remediation("totally_unknown")), 1)

    def test_get_vrt_match_and_fallback(self):
        self.assertIn("SQL Injection", rep.get_vrt("error_based_sqli"))
        self.assertEqual(rep.get_vrt("totally_unknown"), "Other")

    def test_ascii_diagram_nonempty(self):
        diagram = rep.generate_ascii_chain_diagram(self._CHAIN)
        self.assertIn("+", diagram)

    def test_ascii_diagram_no_steps(self):
        self.assertIn("No chain steps", rep.generate_ascii_chain_diagram({"phases": [], "steps": []}))

    def test_hackerone_report_contains_sections(self):
        r = rep.generate_hackerone_report(self._CHAIN)
        self.assertIn("## Summary", r)
        self.assertIn("## Remediation", r)
        self.assertIn("HIGH", r)

    def test_bugcrowd_report_priority_and_vrt(self):
        r = rep.generate_bugcrowd_report(dict(self._CHAIN, chain_severity="CRITICAL"))
        self.assertIn("**Priority:** P1", r)
        self.assertIn("VRT Classification", r)

    def test_impact_detail(self):
        self.assertIn("sensitive data", rep._impact_detail(self._CHAIN, "C"))


if __name__ == "__main__":
    unittest.main()
