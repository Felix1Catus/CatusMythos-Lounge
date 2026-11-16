"""Regression tests for recon-dominator's highest-logic, previously-untested
scripts: cve_lookup.py (NVD/OSV version-range matching) and active_recon.py
(the Sitting-Ducks SOA delegation verdict), plus passive_recon merge logic.

Each script is loaded with the repo's isolate-_common pattern so the vendored
per-skill _common.py copies don't collide in sys.modules.
"""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "recon-dominator" / "scripts"


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


cve = load_script("recon_cve_lookup", "cve_lookup.py")
active = load_script("recon_active_recon", "active_recon.py")
passive = load_script("recon_passive_recon", "passive_recon.py")
techfp = load_script("recon_tech_fingerprint", "tech_fingerprint.py")
jsrecon = load_script("recon_js_recon", "js_recon.py")
portscan = load_script("recon_port_scanner", "port_scanner.py")
wayback = load_script("recon_wayback_analyzer", "wayback_analyzer.py")
dorker = load_script("recon_google_dorker", "google_dorker.py")
report = load_script("recon_generate_report", "generate_report.py")


class PassiveReconOptionalToolTests(unittest.TestCase):
    def test_missing_amass_reports_unverified_compatibility_without_old_install_command(self):
        with patch.object(passive.subprocess, "run", side_effect=FileNotFoundError), patch.object(
            passive, "warn"
        ) as warning:
            self.assertEqual(passive.run_amass_passive("example.com"), [])
        warning.assert_called_once()
        self.assertIn("not bootstrap-managed", warning.call_args.args[0])
        self.assertNotIn("go install", warning.call_args.args[0])


class ParseVersionTests(unittest.TestCase):
    def test_basic_and_empty(self):
        self.assertEqual(cve._parse_version("4.2.1"), (4, 2, 1))
        self.assertEqual(cve._parse_version("4.2"), (4, 2))
        self.assertEqual(cve._parse_version(""), (0,))
        self.assertEqual(cve._parse_version(None), (0,))

    def test_ordering(self):
        self.assertLess(cve._parse_version("4.2"), cve._parse_version("4.2.1"))
        self.assertGreater(cve._parse_version("4.11.0"), cve._parse_version("4.2.0"))


class VersionInRangeTests(unittest.TestCase):
    def test_exact_version_equality(self):
        self.assertTrue(cve._version_in_range("2.3.4", exact_version="2.3.4"))
        self.assertFalse(cve._version_in_range("2.3.5", exact_version="2.3.4"))

    def test_no_fields_is_unknown(self):
        self.assertIsNone(cve._version_in_range("1.0.0"))

    def test_end_including_vs_excluding(self):
        # endIncluding 4.2.1 -> 4.2.1 affected; endExcluding 4.2.1 -> not.
        self.assertTrue(cve._version_in_range("4.2.1", end_incl="4.2.1"))
        self.assertFalse(cve._version_in_range("4.2.1", end_excl="4.2.1"))
        self.assertTrue(cve._version_in_range("4.2.0", end_excl="4.2.1"))

    def test_start_bounds(self):
        self.assertFalse(cve._version_in_range("1.0.0", start_incl="2.0.0"))
        self.assertTrue(cve._version_in_range("2.0.0", start_incl="2.0.0"))
        self.assertFalse(cve._version_in_range("2.0.0", start_excl="2.0.0"))


class BackportTests(unittest.TestCase):
    def test_distro_suffixes_flagged(self):
        for v in ("9.2p1-2+deb12u1", "9.2p1-2~bpo12+1", "8.9p1-3ubuntu0.6",
                  "1.2.3-1.el9", "1.2.3-1.fc40"):
            self.assertTrue(cve._looks_backported(v), v)

    def test_clean_upstream_not_flagged(self):
        for v in ("9.2", "9.2p1", "4.2.1", "1.0.0-rc1", ""):
            self.assertFalse(cve._looks_backported(v), v)


class ParseRangeFromTextTests(unittest.TestCase):
    def test_through_is_inclusive(self):
        r = cve._parse_range_from_text("This issue affects X: from n/a through 4.2.1.")
        self.assertEqual(r["end_incl"], "4.2.1")
        self.assertIsNone(r["end_excl"])

    def test_before_and_prior_are_exclusive(self):
        for phrase in ("versions before 4.2.1 are affected", "fixed; prior to 4.2.1 affected"):
            r = cve._parse_range_from_text(phrase)
            self.assertEqual(r["end_excl"], "4.2.1", phrase)
            self.assertIsNone(r["end_incl"], phrase)

    def test_lt_operator_inclusive_vs_exclusive(self):
        self.assertEqual(cve._parse_range_from_text("affected <= 4.2.1")["end_incl"], "4.2.1")
        self.assertEqual(cve._parse_range_from_text("affected < 4.2.1")["end_excl"], "4.2.1")

    def test_no_match(self):
        self.assertIsNone(cve._parse_range_from_text("no version information here"))

    def test_exclusive_boundary_regression(self):
        # Regression: 'before X' must NOT flag an installed X as affected.
        r = cve._parse_range_from_text("affects all versions before 4.2.1")
        self.assertIs(
            cve._version_in_range("4.2.1", None, None, r["end_incl"], r["end_excl"]), False
        )
        self.assertIs(
            cve._version_in_range("4.2.0", None, None, r["end_incl"], r["end_excl"]), True
        )


class MatchesComponentTests(unittest.TestCase):
    @staticmethod
    def _cve(criteria, **cpe_fields):
        match = {"criteria": criteria, "vulnerable": True}
        match.update(cpe_fields)
        return {"configurations": [{"nodes": [{"cpeMatch": [match]}]}]}

    def test_exact_product_with_range(self):
        item = self._cve("cpe:2.3:a:elementor:elementor_pro:*:*:*:*:*:wordpress:*:*",
                         versionEndExcluding="3.11.7")
        matched, rng = cve._matches_component(item, "elementor_pro")
        self.assertTrue(matched)
        self.assertEqual(rng["end_excl"], "3.11.7")

    def test_substring_product_rejected(self):
        # 'elementor' must not match a different product that merely contains it.
        item = self._cve("cpe:2.3:a:wpdeveloper:essential_addons_for_elementor:*:*:*:*:*:*:*:*",
                         versionEndExcluding="5.0.0")
        matched, rng = cve._matches_component(item, "elementor")
        self.assertFalse(matched)
        self.assertIsNone(rng)

    def test_no_configs_is_unknown(self):
        matched, rng = cve._matches_component({"configurations": []}, "anything")
        self.assertIsNone(matched)
        self.assertIsNone(rng)

    def test_exact_version_cpe(self):
        item = self._cve("cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*")
        matched, rng = cve._matches_component(item, "vsftpd")
        self.assertTrue(matched)
        self.assertEqual(rng["exact_version"], "2.3.4")


class ExtractCvssTests(unittest.TestCase):
    def test_prefers_v31_over_v30_over_v2(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        }
        self.assertEqual(cve._extract_cvss(metrics), (9.8, "CRITICAL"))

    def test_empty(self):
        self.assertEqual(cve._extract_cvss({}), (None, None))


class LookupComponentFilteringTests(unittest.TestCase):
    """End-to-end filtering/classification with NVD paging mocked out."""

    @staticmethod
    def _item(cve_id, desc, configs=None, published="2024-01-01T00:00:00"):
        cve_obj = {
            "id": cve_id, "published": published,
            "descriptions": [{"lang": "en", "value": desc}],
            "metrics": {}, "references": [],
        }
        if configs is not None:
            cve_obj["configurations"] = configs
        return {"cve": cve_obj}

    def _run(self, items, name, version):
        with patch.object(cve, "_fetch_all_cve_pages", return_value=items):
            return cve.lookup_component(name, version)

    def test_real_in_range_hit(self):
        configs = [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:elementor:elementor_pro:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "3.11.7", "vulnerable": True}]}]}]
        items = [self._item("CVE-2024-0001", "Elementor Pro plugin before 3.11.7 allows RCE", configs)]
        hyps = self._run(items, "elementor-pro", "3.10.0")
        self.assertEqual(len(hyps), 1)
        self.assertTrue(hyps[0]["version_appears_affected"])
        self.assertEqual(hyps[0]["range_source"], "nvd-cpe-match")

    def test_addon_for_product_rejected(self):
        # "X for Elementor Pro" addon must not be attributed to elementor-pro.
        items = [self._item("CVE-2026-28192",
                            "Unauthenticated Arbitrary File Upload in Piotnet Addons For Elementor Pro")]
        self.assertEqual(self._run(items, "elementor-pro", "3.10.0"), [])

    def test_cpe_mismatch_skipped(self):
        configs = [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:other:other_product:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "9.0", "vulnerable": True}]}]}]
        items = [self._item("CVE-2024-0002", "Elementor Pro mentioned but CPE names other_product", configs)]
        self.assertEqual(self._run(items, "elementor-pro", "3.10.0"), [])


class InterpretSoaOutputTests(unittest.TestCase):
    AUTHORITATIVE = (
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
        ";; ANSWER SECTION:\n"
        "example.com.\t3600\tIN\tSOA\tns1.example.com. admin.example.com. 1 7200 3600 1209600 3600\n"
    )
    REFUSED = ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1\n"
    NOERROR_EMPTY = (
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
        ";; AUTHORITY SECTION:\n.\t3600\tIN\tNS\ta.root-servers.net.\n"
    )

    def test_authoritative(self):
        self.assertEqual(active._interpret_soa_output(self.AUTHORITATIVE), "authoritative")

    def test_lame_refused(self):
        self.assertEqual(active._interpret_soa_output(self.REFUSED), "lame")
        self.assertEqual(active._interpret_soa_output("status: SERVFAIL"), "lame")
        self.assertEqual(active._interpret_soa_output("status: NXDOMAIN"), "lame")

    def test_lame_noerror_no_answer(self):
        self.assertEqual(active._interpret_soa_output(self.NOERROR_EMPTY), "lame")

    def test_unreachable_when_unparseable(self):
        self.assertEqual(active._interpret_soa_output(""), "unreachable")
        self.assertEqual(active._interpret_soa_output("garbage with no status line"), "unreachable")


class MergeResultsTests(unittest.TestCase):
    def test_dedup_and_source_attribution(self):
        merged = passive.merge_results({
            "crt.sh": ["a.ex.com", "b.ex.com"],
            "wayback": ["A.EX.COM", "c.ex.com."],  # case + trailing dot normalize
        })
        self.assertEqual(sorted(merged["a.ex.com"]), ["crt.sh", "wayback"])
        self.assertIn("c.ex.com", merged)
        self.assertEqual(len(merged), 3)


class ExtractVersionedComponentsTests(unittest.TestCase):
    """tech_fingerprint.py's ?ver= asset-version miner -- the WordPress-shaped
    feed into cve_lookup. The whole value is an *exact* version per component,
    so the parsing has to be right."""

    def test_plugin_and_theme_versions(self):
        body = (
            '<link href="/wp-content/plugins/elementor-pro/assets/css/'
            'sticky.min.css?ver=4.0.4" />'
            '<script src="/wp-content/themes/hello-elementor/js/x.js?ver=2.1.0">'
        )
        comps = techfp.extract_versioned_components(body)
        self.assertIn({"kind": "wordpress-plugin", "name": "elementor-pro", "version": "4.0.4"}, comps)
        self.assertIn({"kind": "wordpress-theme", "name": "hello-elementor", "version": "2.1.0"}, comps)

    def test_plugin_dedup_same_version(self):
        body = (
            '/wp-content/plugins/woocommerce/a.css?ver=8.3.1 '
            '/wp-content/plugins/woocommerce/b.js?ver=8.3.1'
        )
        comps = techfp.extract_versioned_components(body)
        wc = [c for c in comps if c["name"] == "woocommerce"]
        self.assertEqual(len(wc), 1)
        self.assertEqual(wc[0]["version"], "8.3.1")

    def test_core_requires_two_agreeing_matches(self):
        # Two wp-includes assets agreeing on one version -> trust it as core.
        body = (
            '/wp-includes/js/jquery/jquery.min.js?ver=6.4.2 '
            '/wp-includes/js/wp-embed.min.js?ver=6.4.2'
        )
        comps = techfp.extract_versioned_components(body)
        self.assertIn({"kind": "wordpress-core", "name": "wordpress", "version": "6.4.2"}, comps)

    def test_core_single_match_not_trusted(self):
        body = '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'
        comps = techfp.extract_versioned_components(body)
        self.assertEqual([c for c in comps if c["kind"] == "wordpress-core"], [])

    def test_core_disagreeing_versions_not_trusted(self):
        # A bundled library carrying its own version must not be mistaken for core.
        body = (
            '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1 '
            '/wp-includes/js/dist/block.min.js?ver=6.4.2'
        )
        comps = techfp.extract_versioned_components(body)
        self.assertEqual([c for c in comps if c["kind"] == "wordpress-core"], [])

    def test_none_body_is_safe(self):
        self.assertEqual(techfp.extract_versioned_components(None), [])
        self.assertEqual(techfp.extract_versioned_components(""), [])


class MaybeUrlTests(unittest.TestCase):
    def test_rejects_non_pathy_and_noise(self):
        self.assertFalse(jsrecon.maybe_url("plainword"))
        self.assertFalse(jsrecon.maybe_url("a b c"))
        self.assertFalse(jsrecon.maybe_url("fn(x)"))

    def test_accepts_absolute_path_and_hosts(self):
        self.assertTrue(jsrecon.maybe_url("/api/v2/users"))
        self.assertTrue(jsrecon.maybe_url("https://api.example.com/x"))
        self.assertTrue(jsrecon.maybe_url("data.json"))

    def test_rejects_non_http_scheme(self):
        self.assertFalse(jsrecon.maybe_url("mailto:a@b.com"))


class ExtractApiCallsTests(unittest.TestCase):
    def test_fetch_axios_jquery_xhr_and_template(self):
        js = (
            "fetch('/api/me');"
            "axios.post('/api/login', body);"
            "$.ajax({ type:'GET', url: '/legacy/data' });"
            "xhr.open('DELETE', `/api/items/${id}`);"
        )
        calls = jsrecon.extract_api_calls(js)
        pairs = {(c["method"], c["url"]) for c in calls}
        self.assertIn(("GET", "/api/me"), pairs)
        self.assertIn(("POST", "/api/login"), pairs)
        self.assertIn(("?", "/legacy/data"), pairs)       # $.ajax object literal
        self.assertIn(("DELETE", "/api/items/{param}"), pairs)  # template normalized

    def test_pure_placeholder_dropped(self):
        self.assertEqual(jsrecon.extract_api_calls("fetch(`${base}`)"), [])

    def test_normalize_template(self):
        self.assertEqual(jsrecon.normalize_template("/u/${id}/p/${k}"), "/u/{param}/p/{param}")


class EndpointExtractionTests(unittest.TestCase):
    def test_extract_endpoints_filters_noise(self):
        js = 'var a="/admin/panel"; var b="not a url"; var c="/api/v1/health";'
        eps = jsrecon.extract_endpoints(js)
        self.assertIn("/admin/panel", eps)
        self.assertIn("/api/v1/health", eps)
        self.assertNotIn("not a url", eps)


class FindSourcemapUrlTests(unittest.TestCase):
    def test_comment_directive_wins(self):
        self.assertEqual(
            jsrecon.find_sourcemap_url("//# sourceMappingURL=app.js.map", "https://x/js/app.js"),
            "https://x/js/app.js.map",
        )

    def test_fallback_plain(self):
        self.assertEqual(
            jsrecon.find_sourcemap_url("code;", "https://x/app.js"),
            "https://x/app.js.map",
        )

    def test_fallback_strips_query(self):
        # Regression: cache-busted URL must not yield `app.js?v=1.map`.
        self.assertEqual(
            jsrecon.find_sourcemap_url("code;", "https://x/app.js?v=1#frag"),
            "https://x/app.js.map",
        )


class JsManifestTests(unittest.TestCase):
    def test_next_build_id(self):
        self.assertEqual(
            jsrecon.get_next_build_id('/_next/static/AbC123/_buildManifest.js'), "AbC123")
        self.assertEqual(
            jsrecon.get_next_build_id('"buildId":"xyz789"'), "xyz789")
        self.assertIsNone(jsrecon.get_next_build_id("<html></html>"))

    def test_referenced_chunks(self):
        js = '"/static/chunks/42.js" and "app.1a2b3c4d.js"'
        chunks = jsrecon.find_referenced_chunks(js)
        self.assertIn("/static/chunks/42.js", chunks)
        self.assertIn("app.1a2b3c4d.js", chunks)

    def test_extract_script_urls_resolves_relative(self):
        html = '<script src="/a.js"></script><script src="https://cdn/b.js"></script>'
        urls = jsrecon.extract_script_urls(html, "https://site.test/page")
        self.assertIn("https://site.test/a.js", urls)
        self.assertIn("https://cdn/b.js", urls)


class ParseServiceVersionTests(unittest.TestCase):
    def test_ssh_banner_and_os_hint(self):
        comps = portscan.parse_service_version(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertIn({"kind": "os-service", "name": "openssh", "version": "8.9p1"}, comps)
        self.assertTrue(any(c["kind"] == "os-hint" and c["name"] == "Ubuntu" for c in comps))

    def test_ftp_vsftpd(self):
        comps = portscan.parse_service_version(21, "220 (vsFTPd 3.0.3)")
        self.assertEqual(comps, [{"kind": "os-service", "name": "vsftpd", "version": "3.0.3"}])

    def test_smtp_exim(self):
        comps = portscan.parse_service_version(25, "220 mail ESMTP Exim 4.94.2 Mon")
        self.assertEqual(comps, [{"kind": "os-service", "name": "exim", "version": "4.94.2"}])

    def test_http_server_and_x_powered_by(self):
        comps = portscan.parse_service_version(
            None, "", http_info={"server": "Apache/2.4.41 (Ubuntu)", "x_powered_by": "PHP/7.4.3"})
        self.assertIn({"kind": "os-service", "name": "apache", "version": "2.4.41"}, comps)
        self.assertIn({"kind": "os-service", "name": "php", "version": "7.4.3"}, comps)
        self.assertTrue(any(c["kind"] == "os-hint" and c["name"] == "Ubuntu" for c in comps))

    def test_unrecognized_yields_nothing(self):
        self.assertEqual(portscan.parse_service_version(22, "random noise"), [])
        self.assertEqual(portscan.parse_service_version(None, "", http_info={"server": "nginx"}), [])


class DetectWafTests(unittest.TestCase):
    def test_cloudflare_and_none(self):
        self.assertEqual(portscan.detect_waf({"server": "cloudflare"}), "cloudflare")
        self.assertEqual(portscan.detect_waf({"server": "nginx"}), "none_detected")
        self.assertEqual(portscan.detect_waf(None), "unknown")


class WaybackCategorizeTests(unittest.TestCase):
    def _entries(self, *urls):
        return [{"original": u, "timestamp": "20230101000000", "statuscode": "200"} for u in urls]

    def test_categorizes_and_counts_params(self):
        cats = wayback.categorize_urls(
            self._entries(
                "https://x.com/api/v1/users?id=5",
                "https://x.com/app.js",
                "https://x.com/.env",
                "https://x.com/wp-admin/",
            ), "x.com")
        self.assertIn("https://x.com/api/v1/users?id=5", cats["api_endpoints"])
        self.assertIn("https://x.com/app.js", cats["javascript_files"])
        self.assertIn("https://x.com/.env", cats["config_files"])
        self.assertIn("https://x.com/wp-admin/", cats["admin_panels"])
        names = {p["name"] for p in cats["top_parameters"]}
        self.assertIn("id", names)

    def test_removed_content_detection(self):
        entries = [
            {"original": "https://x.com/old", "timestamp": "20200101000000", "statuscode": "200"},
            {"original": "https://x.com/old", "timestamp": "20240101000000", "statuscode": "404"},
        ]
        removed = wayback.identify_removed_content(entries)
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["url"], "https://x.com/old")
        self.assertEqual(removed[0]["current_status"], "404")


class GoogleDorkerTests(unittest.TestCase):
    def test_generate_dorks_substitutes_domain(self):
        dorks = dorker.generate_dorks("acme.com", categories=["sensitive_files"])
        self.assertIn("sensitive_files", dorks)
        self.assertTrue(all("acme.com" in d["query"] for d in dorks["sensitive_files"]))
        self.assertTrue(all(d["url"].startswith("https://www.google.com/search?q=") for d in dorks["sensitive_files"]))

    def test_unknown_category_skipped(self):
        self.assertEqual(dorker.generate_dorks("acme.com", categories=["nope"]), {})


class GenerateReportTests(unittest.TestCase):
    def test_inline_code_fences_backticks(self):
        # A dork query containing backticks must not break out of its code span.
        out = report.generate_markdown_report(
            {"dorking": {"dorks": {"x": [{"query": "a `` b ``` c"}]}}}, "t.com")
        # Longest backtick run in the query is 3, so the fence must be 4.
        self.assertIn("````a `` b ``` c````", out)

    def test_report_smoke_and_metrics(self):
        data = {
            "passive_recon": {"meta": {"total_unique": 3}, "subdomains": [{"host": "a.t.com", "sources": ["crt.sh"]}]},
            "port_scan": {"meta": {"live_hosts": 2, "total_open_ports": 5},
                          "results": [{"host": "a.t.com", "ip": "1.2.3.4",
                                       "open_ports": [{"port": 80}], "waf_cdn": "none"}]},
        }
        out = report.generate_markdown_report(data, "t.com")
        self.assertIn("# Reconnaissance Report: t.com", out)
        self.assertIn("| Total Subdomains Discovered | 3 |", out)
        self.assertIn("| Live Hosts | 2 |", out)


if __name__ == "__main__":
    unittest.main()
