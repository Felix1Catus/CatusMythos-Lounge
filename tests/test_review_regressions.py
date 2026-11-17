"""Offline regressions for crawler scope, JWT controls, and report integrity."""
import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(skill, filename):
    path = ROOT / 'skills' / skill / 'scripts' / (filename + '.py')
    spec = importlib.util.spec_from_file_location('review_' + filename, path)
    module = importlib.util.module_from_spec(spec)
    old_common = sys.modules.pop('_common', None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop('_common', None)
        if old_common is not None:
            sys.modules['_common'] = old_common
    return module


crawler = load('webapp-exploit-hunter', 'crawler')
auth = load('webapp-exploit-hunter', 'auth_tester')
importer = load('vuln-chain-composer', 'import_findings')
reporter = load('vuln-chain-composer', 'generate_report')
builder = load('vuln-chain-composer', 'build_chains')


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()


class ReviewRegressions(unittest.TestCase):
    def test_crawler_does_not_forward_credentials_to_discovered_origins(self):
        calls = []
        def get(url, headers=None, **kwargs):
            calls.append((url, headers))
            if url.endswith('/app.js'):
                return 200, {}, 'fetch("https://outside.invalid/collect"); fetch("/api/owned")'
            if url == 'https://scope.example/':
                return 200, {}, ('<script src="/app.js"></script>'
                    '<script src="https://child.scope.example/evil.js"></script>'
                    '<a href="http://scope.example/plain">downgrade</a>'
                    '<a href="https://scope.example:8443/admin">port</a>'
                    '<a href="https://child.scope.example/">child</a>')
            return 200, {}, 'fixture'
        with patch.object(crawler, 'http_get', side_effect=get), patch.object(
            crawler, 'discover_robots_sitemap_urls', return_value=['https://outside.invalid/seed']
        ):
            crawler.crawl('https://scope.example/', max_pages=10,
                          extra_headers={'Authorization': 'Bearer fixture', 'Cookie': 'fixture'})
        self.assertEqual({url for url, _ in calls}, {
            'https://scope.example/', 'https://scope.example/app.js',
            'https://scope.example/api/owned'})

    def test_sitemap_does_not_inherit_subdomain_scope(self):
        calls = []
        def get(url, **kwargs):
            calls.append(url)
            if url.endswith('robots.txt'):
                return 200, {}, 'Sitemap: https://child.scope.example/sitemap.xml'
            return 200, {}, '<urlset><url><loc>https://child.scope.example/private</loc></url></urlset>'
        with patch.object(crawler, 'http_get', side_effect=get):
            self.assertEqual(crawler.discover_robots_sitemap_urls('https://scope.example/'), [])
        self.assertTrue(all(url.startswith('https://scope.example/') for url in calls))

    def jwt_findings(self, mode):
        token = encoded({'alg': 'RS256', 'typ': 'JWT'}) + '.' + encoded({'sub': 'fixture'}) + '.signature'
        calls = []
        def request(url, headers=None, **kwargs):
            headers = headers or {}
            calls.append(headers)
            bearer = headers.get('Authorization', '')
            if mode == 'public':
                return 200, {}, 'public landing page'
            if bearer == 'Bearer ' + token:
                return 200, {}, '{"sub":"fixture","private":true}'
            if not bearer or bearer.endswith('.Aignature'):
                return 401, {}, 'unauthorized'
            if mode == 'secure':
                return 401, {}, 'unauthorized'
            return 200, {}, '{"sub":"fixture","private":true}'
        with patch.object(auth, 'http_request', side_effect=request):
            findings = auth.analyze_jwt('https://scope.example/', {
                'Authorization': 'Bearer ' + token, 'Cookie': 'session=fixture'})
        self.assertTrue(all('Cookie' not in h for h in calls[1:]))
        return findings

    def test_public_page_is_not_a_confirmed_jwt_bypass(self):
        findings = self.jwt_findings('public')
        self.assertTrue(findings)
        self.assertTrue(all(f['validated'] is False and f['severity'] == 'INFO' for f in findings))

    def test_protected_jwt_bypass_retains_positive_detection(self):
        findings = self.jwt_findings('bypass')
        self.assertEqual({f['type'] for f in findings}, {'jwt_none_algorithm', 'jwt_empty_signature'})
        self.assertTrue(all(f['validated'] for f in findings))

    def test_secure_endpoint_has_no_jwt_bypass(self):
        self.assertEqual(self.jwt_findings('secure'), [])

    def test_import_preserves_distinct_paths_methods_and_deduplicates_repeats(self):
        findings = [dict(type='ssrf', url='https://scope.example/' + path,
                         param='url', method=method)
                    for path, method in [('profile', 'GET'), ('export', 'GET'), ('export', 'POST')]]
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / 'in.json'
            out = Path(directory) / 'out.json'
            src.write_text(json.dumps({'findings': findings + [findings[0]]}), encoding='utf-8')
            with patch.object(sys, 'argv', ['import', '--input', str(src), '--output', str(out)]):
                importer.main()
            self.assertEqual(len(json.loads(out.read_text())['findings']), 3)

    def test_candidates_do_not_enable_chain_capabilities(self):
        for kind in ['jwt_none_algorithm_candidate', 'bola_candidate', 'ssrf_candidate']:
            finding = importer.normalize_finding(dict(type=kind, validated=False), 'fixture')
            self.assertEqual(finding['chainable_as'], [])

    def test_distinct_mass_assignment_fields_retain_distinct_ids(self):
        findings = [importer.normalize_finding(dict(
            type='mass_assignment_candidate', url='https://scope.example/profile',
            field=field, method='PATCH', validated=False), 'fixture')
            for field in ['role', 'balance']]
        self.assertNotEqual(findings[0]['id'], findings[1]['id'])

    def test_report_preserves_unconfirmed_status_in_all_formats_and_built_chains(self):
        chain = dict(name='Fixture chain', confidence='unconfirmed',
                     confidence_note='Connection has not been verified.',
                     primary_finding=dict(type='ssrf', category='ssrf', url='https://scope.example/',
                                          parameter='url'), supporting_findings=[], steps=['Verify access'])
        for value in [chain, builder.build_detailed_chain(chain)]:
            for generate in [reporter.generate_hackerone_report,
                             reporter.generate_bugcrowd_report, reporter.generate_generic_report]:
                report = generate(value)
                self.assertIn('**Chain status:** Unconfirmed', report)
                self.assertIn(chain['confidence_note'], report)
                self.assertIn('Proposed Verification Steps', report)
                self.assertNotIn('to achieve HIGH-severity impact', report)
                self.assertNotIn('This is a realistic attack scenario', report)

    def test_report_defaults_to_unconfirmed_when_evidence_status_is_missing(self):
        self.assertIn('**Chain status:** Unconfirmed', reporter.generate_hackerone_report({}))
        self.assertIn('**Chain status:** Confirmed', reporter.generate_hackerone_report({'confidence': 'confirmed'}))


if __name__ == '__main__':
    unittest.main()
