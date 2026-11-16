"""Regression tests for attack-path-architect's logic-bearing scripts, which
previously had only repo-wide lint/shared-helper coverage.

Covers: the MITRE technique lookup/mapping engine, the attack-tree scoring and
chain-composition logic, asset classification + risk scoring (including the
tech-merge NameError fix), the trust-graph builder, and the engagement-plan
authorization gate.

Each script is loaded with the repo's isolate-_common pattern. mitre_mapper is
loaded under its real name so generate_attack_tree's ``from mitre_mapper import
MITREMapper`` reuses the same module object.
"""
import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "attack-path-architect" / "scripts"


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


# Real name so generate_attack_tree's `from mitre_mapper import ...` reuses it.
mitre = load_script("mitre_mapper", "mitre_mapper.py")
attree = load_script("apa_generate_attack_tree", "generate_attack_tree.py")
classify = load_script("apa_classify_assets", "classify_assets.py")
trust = load_script("apa_map_trust", "map_trust.py")
planner = load_script("apa_engagement_planner", "engagement_planner.py")


# --- mitre_mapper ------------------------------------------------------------
class MitreLookupTests(unittest.TestCase):
    def setUp(self):
        self.m = mitre.MITREMapper()

    def test_flat_technique(self):
        r = self.m.lookup_technique("T1190")
        self.assertEqual(r["name"], "Exploit Public-Facing Application")
        self.assertEqual(r["tactic"], "Initial Access")

    def test_subtechnique_inherits_parent_tactic(self):
        r = self.m.lookup_technique("T1059.001")
        self.assertEqual(r["name"], "PowerShell")
        self.assertEqual(r["tactic"], "Execution")
        self.assertEqual(r["parent"], "T1059")

    def test_unknown_and_undefined_sub(self):
        self.assertIsNone(self.m.lookup_technique("T9999"))
        self.assertIsNone(self.m.lookup_technique("T1190.999"))  # parent exists, sub undefined

    def test_map_techniques_split_and_grouping(self):
        out = self.m.map_techniques(["T1059.001", "T1486", "T9999", "T1078"])
        self.assertEqual(out["total_mapped"], 3)
        self.assertEqual(out["unmapped"], ["T9999"])
        # T1078's multi-tactic string is split across buckets.
        self.assertIn("Stealth", out["by_tactic"])
        self.assertIn("Initial Access", out["by_tactic"])
        self.assertIn("Execution", out["by_tactic"])

    def test_detection_query(self):
        self.assertIn("4688", self.m.generate_detection_query("T1059.001", "splunk"))
        self.assertIsNone(self.m.generate_detection_query("T1190", "splunk"))

    def test_navigator_layer(self):
        layer = self.m.generate_navigator_layer(["T1059.001", "T1003.001"])
        self.assertEqual(len(layer["techniques"]), 2)
        self.assertEqual(layer["domain"], "enterprise-attack")


# --- generate_attack_tree ----------------------------------------------------
class TtpLookupTests(unittest.TestCase):
    def test_enterprise_atlas_and_unknown(self):
        self.assertEqual(attree._ttp_lookup("T1190")["name"], "Exploit Public-Facing Application")
        self.assertEqual(attree._ttp_lookup("AML.T0053")["name"], "AI Agent Tool Invocation")
        self.assertEqual(attree._ttp_lookup("ZZZ")["name"], "Unknown")


class GeneratePathsTests(unittest.TestCase):
    @staticmethod
    def _asset(**kw):
        base = {"host": "t.x.com", "asset_type": "WEB_APP", "technologies": [],
                "risk_score": 1, "waf_cdn": "none_detected", "open_ports": []}
        base.update(kw)
        return base

    def test_condition_match_and_risk_boost(self):
        asset = self._asset(technologies=["PHP", "MySQL"], risk_score=8)
        paths = attree.generate_paths([asset])
        sqli = next(p for p in paths if p["attack_name"] == "SQL Injection to RCE")
        # base 6 +2 (risk>=7) +1 (condition met) = 9; no WAF penalty.
        self.assertEqual(sqli["feasibility"], 9)
        self.assertTrue(sqli["condition_matched"])
        self.assertIn("PHP", sqli["matched_technologies"])
        self.assertIn("MySQL", sqli["matched_technologies"])

    def test_waf_reduces_feasibility_and_stealth(self):
        no_waf = attree.generate_paths([self._asset(technologies=["PHP", "MySQL"])])
        with_waf = attree.generate_paths([self._asset(technologies=["PHP", "MySQL"], waf_cdn="cloudflare")])
        sqli_no = next(p for p in no_waf if p["attack_name"] == "SQL Injection to RCE")
        sqli_waf = next(p for p in with_waf if p["attack_name"] == "SQL Injection to RCE")
        self.assertLess(sqli_waf["feasibility"], sqli_no["feasibility"])
        self.assertLess(sqli_waf["stealth"], sqli_no["stealth"])

    def test_web_patterns_added_for_http_serving_nonweb_asset(self):
        asset = self._asset(asset_type="DATABASE", open_ports=[{"port": 443}])
        names = {p["attack_name"] for p in attree.generate_paths([asset])}
        # DATABASE pattern plus the WEB_APP fallback patterns.
        self.assertIn("Direct Database Access via Exposed Port", names)
        self.assertIn("XSS to Session Hijacking", names)

    def test_steps_carry_mitre_tactic(self):
        paths = attree.generate_paths([self._asset(asset_type="STORAGE")])
        step = paths[0]["steps"][0]
        self.assertIn("ttp_name", step)
        self.assertNotEqual(step["tactic"], "")

    def test_sorted_by_combined_score(self):
        paths = attree.generate_paths([self._asset(technologies=["PHP", "MySQL"], risk_score=9)])
        scores = [p["combined_score"] for p in paths]
        self.assertEqual(scores, sorted(scores, reverse=True))


class ChainOpportunitiesTests(unittest.TestCase):
    def test_xss_plus_shared_cookie(self):
        paths = [{"target": "t", "asset_type": "WEB_APP",
                  "attack_name": "XSS to Session Hijacking", "combined_score": 6.0}]
        rels = [{"type": "SHARED_COOKIE_SCOPE", "source": "t"}]
        chains = attree.generate_chain_opportunities(paths, rels)
        self.assertTrue(any("XSS" in c["name"] for c in chains))

    def test_ssrf_plus_storage(self):
        paths = [
            {"target": "t", "asset_type": "WEB_APP",
             "attack_name": "SSRF to Cloud Credential Theft", "combined_score": 5.0},
            {"target": "s", "asset_type": "STORAGE",
             "attack_name": "Public Cloud Storage Data Leak", "combined_score": 4.0},
        ]
        chains = attree.generate_chain_opportunities(paths, [])
        self.assertTrue(any(c["risk"] == "CRITICAL" and "SSRF" in c["name"] for c in chains))

    def test_dangling_cname_chain(self):
        rels = [{"type": "DANGLING_CNAME", "source": "s.x.com", "target": "gone.example.com"}]
        chains = attree.generate_chain_opportunities([], rels)
        self.assertTrue(any("Takeover" in c["name"] for c in chains))

    def test_no_signals_no_chains(self):
        self.assertEqual(attree.generate_chain_opportunities([], []), [])


# --- classify_assets ---------------------------------------------------------
class ClassifyHelpersTests(unittest.TestCase):
    def test_classify_by_subdomain(self):
        self.assertEqual(classify.classify_by_subdomain("api.x.com", "x.com"), "API")
        self.assertEqual(classify.classify_by_subdomain("admin.x.com", "x.com"), "ADMIN_PANEL")
        self.assertEqual(classify.classify_by_subdomain("www.x.com", "x.com"), "WEB_APP")

    def test_classify_by_ports(self):
        types, services = classify.classify_by_ports([{"port": 3306}, {"port": 443}])
        self.assertIn("DATABASE", types)
        self.assertIn("WEB_APP", types)
        self.assertTrue(any(s["service"] == "MySQL" for s in services))

    def test_risk_score_bounds_and_signals(self):
        asset = {"technologies": ["phpMyAdmin"], "exposure": "EXTERNAL",
                 "open_ports": [{"port": 3306}], "asset_type": "DATABASE",
                 "waf_cdn": "none_detected", "missing_security_headers": ["a", "b", "c", "d", "e"]}
        score, reasons = classify.calculate_risk_score(asset)
        self.assertTrue(1 <= score <= 10)
        self.assertEqual(score, 10)  # many signals -> clamped to max
        self.assertTrue(any("Dangerous port" in r for r in reasons))

    def test_determine_exposure(self):
        self.assertEqual(classify.determine_exposure({"host": "a.x.com"}, "cloudflare"), "SEMI-EXTERNAL")
        self.assertEqual(classify.determine_exposure({"host": "dev.x.com"}, "none_detected"), "INTERNAL-EXPOSED")
        self.assertEqual(classify.determine_exposure({"host": "www.x.com"}, "none_detected"), "EXTERNAL")


class ClassifyAssetsIntegrationTests(unittest.TestCase):
    def test_tech_only_host_does_not_crash(self):
        # Regression: a tech_fingerprint host absent from the port-scan map and
        # carrying a "details" key used to hit a NameError on `details`.
        recon = {"data": {
            "port_scan": {"results": [
                {"host": "a.x.com", "ip": "1.1.1.1",
                 "open_ports": [{"port": 443}], "waf_cdn": "none_detected"}]},
            "tech_fingerprint": {"results": [
                {"host": "b.x.com", "technologies": ["WordPress"],
                 "details": {"missing_security_headers": ["CSP", "HSTS", "XFO"]}}]},
            "passive_recon": {"meta": {"domain": "x.com"}},
        }}
        assets = classify.classify_assets(recon)
        hosts = {a["host"] for a in assets}
        self.assertIn("a.x.com", hosts)
        self.assertIn("b.x.com", hosts)
        b = next(a for a in assets if a["host"] == "b.x.com")
        self.assertIn("WordPress", b["technologies"])
        self.assertEqual(b["missing_security_headers"], ["CSP", "HSTS", "XFO"])

    def test_sorted_by_risk_desc(self):
        recon = {"data": {
            "port_scan": {"results": [
                {"host": "low.x.com", "ip": "1.1.1.1", "open_ports": [], "waf_cdn": "cloudflare"},
                {"host": "high.x.com", "ip": "1.1.1.2",
                 "open_ports": [{"port": 3306}], "waf_cdn": "none_detected"}]},
            "passive_recon": {"meta": {"domain": "x.com"}},
        }}
        assets = classify.classify_assets(recon)
        self.assertGreaterEqual(assets[0]["risk_score"], assets[-1]["risk_score"])


# --- map_trust ---------------------------------------------------------------
class BuildTrustGraphTests(unittest.TestCase):
    def test_source_target_edge(self):
        g = trust.build_trust_graph([
            {"type": "DANGLING_CNAME", "source": "a", "target": "b", "risk": "CRITICAL"}])
        self.assertEqual(g["nodes"], ["a", "b"])
        self.assertEqual(len(g["edges"]), 1)
        self.assertEqual(g["edges"][0]["type"], "DANGLING_CNAME")

    def test_hosts_fully_connected(self):
        g = trust.build_trust_graph([
            {"type": "SHARED_IP", "hosts": ["a", "b", "c"], "risk": "MEDIUM"}])
        # 3 hosts fully connected -> 3 undirected edges.
        self.assertEqual(len(g["edges"]), 3)
        self.assertTrue(all(e.get("bidirectional") for e in g["edges"]))
        self.assertEqual(g["nodes"], ["a", "b", "c"])


# --- engagement_planner ------------------------------------------------------
class EngagementPlannerTests(unittest.TestCase):
    def test_authorization_defaults_false(self):
        plan = planner.generate_plan({})
        self.assertIs(plan["authorization"]["authorized"], False)

    def test_explicit_authorized_honored(self):
        plan = planner.generate_plan({"authorized": True, "name": "Op Test"})
        self.assertIs(plan["authorization"]["authorized"], True)
        self.assertEqual(plan["engagement_name"], "Op Test")

    def test_eight_phases_and_prohibited(self):
        plan = planner.generate_plan({})
        self.assertEqual(len(plan["kill_chain_plan"]), 8)
        self.assertIn("DoS/DDoS", plan["rules_of_engagement"]["prohibited_techniques"])

    def test_markdown_renders_authorization(self):
        md = planner.to_markdown(planner.generate_plan({}))
        self.assertIn("## Authorization", md)


if __name__ == "__main__":
    unittest.main()
