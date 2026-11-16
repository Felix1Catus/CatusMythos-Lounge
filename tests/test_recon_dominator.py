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


if __name__ == "__main__":
    unittest.main()
