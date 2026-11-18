"""Offline matrix for shared target knowledge and its three opt-in integrations."""
import contextlib
import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.pop('_common', None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop('_common', None)
        if old is not None:
            sys.modules['_common'] = old
    return module


kb = load('knowledge_matrix', ROOT / 'scripts/target_knowledge.py')
recon = load('knowledge_recon', ROOT / 'skills/recon-dominator/scripts/tech_fingerprint.py')
sqli = load('knowledge_sqli', ROOT / 'skills/webapp-exploit-hunter/scripts/sqli_tester.py')
importer = load('knowledge_importer', ROOT / 'skills/vuln-chain-composer/scripts/import_findings.py')


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'knowledge.sqlite'
        self.now = 1000.0
        self.store = kb.KnowledgeStore(self.path, 'engagement-a', clock=lambda: self.now)
        self.url = 'https://app.example.test/item?q=private-query'

    def observe(self, **kwargs):
        self.store.observe(self.url, 'technology', 'stack', {'name': 'nginx'}, 'fixture', **kwargs)

    def test_origin_canonicalization(self):
        cases = {'HTTPS://EXAMPLE.TEST/a?secret=x': 'https://example.test:443',
                 'https://example.test:443/': 'https://example.test:443',
                 'http://example.test/': 'http://example.test:80',
                 'http://[::1]:8000/': 'http://[::1]:8000',
                 'https://bücher.test/': 'https://xn--bcher-kva.test:443'}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(kb.canonical_origin(value), expected)

    def test_invalid_origins_are_rejected(self):
        for value in ['ftp://host/', 'file:///etc/passwd', 'https://user:secret@host/',
                      'https://host:0/', 'https://host:99999/', '/relative']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                kb.canonical_origin(value)

    def test_engagement_is_required(self):
        for name in ['', ' ', None]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                kb.KnowledgeStore(self.path, name)

    def test_namespace_origin_scheme_port_and_subdomain_isolation(self):
        self.observe()
        self.assertEqual(len(self.store.query('https://app.example.test:443/')), 1)
        for other in ['http://app.example.test/', 'https://app.example.test:8443/',
                      'https://child.app.example.test/']:
            self.assertEqual(self.store.query(other), [])
        self.assertEqual(kb.KnowledgeStore(self.path, 'engagement-b').query(self.url), [])

    def test_expiry_boundary_and_audit_query(self):
        self.observe(ttl=10)
        self.now += 9
        self.assertEqual(len(self.store.query(self.url)), 1)
        self.now += 1
        self.assertEqual(self.store.query(self.url), [])
        row = self.store.query(self.url, include_expired=True)[0]
        self.assertEqual(row['source'], 'fixture')
        self.assertEqual(row['observed_at'], 1000)
        self.assertEqual(row['confidence'], 'observed')

    def test_latest_observation_replaces_same_key_only(self):
        self.observe()
        self.now += 1
        self.store.observe(self.url, 'technology', 'stack', {'name': 'apache'}, 'new-source')
        rows = self.store.query(self.url)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['value'], {'name': 'apache'})
        self.assertEqual(rows[0]['source'], 'new-source')
        history = self.store.history(self.url, 'technology', 'stack')
        self.assertEqual([row['value'] for row in history], [{'name': 'nginx'}, {'name': 'apache'}])
        self.assertEqual([row['event'] for row in history], ['observe', 'observe'])

    def test_v1_database_migrates_current_facts_into_auditable_history(self):
        legacy = Path(self.temp.name) / 'legacy-v1.sqlite'
        with contextlib.closing(sqlite3.connect(str(legacy))) as db:
            with db:
                db.execute('''CREATE TABLE observations (
                engagement TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL,
                kind TEXT NOT NULL, fact_key TEXT NOT NULL, context TEXT NOT NULL,
                value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL,
                observed_at REAL NOT NULL, expires_at REAL NOT NULL,
                PRIMARY KEY (engagement, origin, resource, kind, fact_key, context))''')
                db.execute('''INSERT INTO observations VALUES
                ('engagement-a', 'https://app.example.test:443', '/item', 'technology',
                 'stack', '', '{"name":"nginx"}', 'legacy', 'observed', 900, 2000)''')
                db.execute('PRAGMA user_version = 1')
        migrated = kb.KnowledgeStore(legacy, 'engagement-a', clock=lambda: 1000)
        history = migrated.history(self.url, 'technology', 'stack')
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['event'], 'migration_snapshot')
        self.assertEqual(history[0]['source'], 'legacy')
        migrated.observe(self.url, 'technology', 'stack', {'name': 'apache'}, 'fresh')
        self.assertEqual([row['value'] for row in migrated.history(self.url, 'technology', 'stack')],
                         [{'name': 'nginx'}, {'name': 'apache'}])

    def test_forget_records_removed_observations_without_leaking_to_current_view(self):
        self.observe()
        self.assertEqual(self.store.forget(self.url, 'technology', 'stack'), 1)
        self.assertEqual(self.store.query(self.url, 'technology'), [])
        self.assertEqual(self.store.history(self.url, 'technology', 'stack')[-1]['event'], 'forget')

    def test_history_is_bounded_per_engagement_without_pruning_current_facts(self):
        original_limit = kb.MAX_HISTORY_ROWS_PER_ENGAGEMENT
        kb.MAX_HISTORY_ROWS_PER_ENGAGEMENT = 2
        try:
            for index in range(3):
                self.store.observe(self.url, 'waf', 'event-{}'.format(index),
                                   {'name': 'waf-{}'.format(index)}, 'fixture')
            self.assertEqual(len(self.store.history(self.url, 'waf')), 2)
            self.assertEqual(len(self.store.query(self.url, 'waf')), 3)
        finally:
            kb.MAX_HISTORY_ROWS_PER_ENGAGEMENT = original_limit

    def test_history_cli_inspects_superseded_rows_without_network(self):
        self.observe()
        self.now += 1
        self.store.observe(self.url, 'technology', 'stack', {'name': 'apache'}, 'fresh')
        result = subprocess.run([
            sys.executable, str(ROOT / 'scripts' / 'target_knowledge.py'), '--db', str(self.path),
            '--engagement', 'engagement-a', '--target', self.url, '--kind', 'technology', '--history'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['source'] for row in json.loads(result.stdout)], ['fixture', 'fresh'])

    def test_invalid_ttl_kind_confidence_and_oversize_are_rejected(self):
        for ttl in [0, -1, float('nan'), float('inf')]:
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.observe(ttl=ttl)
        with self.assertRaises(ValueError):
            self.observe(confidence='certain')
        with self.assertRaises(ValueError):
            self.store.observe(self.url, 'unknown', 'x', {}, 'fixture')
        with self.assertRaises(ValueError):
            self.store.observe(self.url, 'waf', 'x', 'a' * 65537, 'fixture')

    def test_future_schema_is_rejected(self):
        with contextlib.closing(sqlite3.connect(str(self.path))) as db:
            db.execute('PRAGMA user_version = 99')
        with self.assertRaises(ValueError):
            kb.KnowledgeStore(self.path, 'engagement-a')

    def test_invalid_database_is_not_silently_reset(self):
        other = Path(self.temp.name) / 'broken.sqlite'
        other.write_text('not a database')
        with self.assertRaises(sqlite3.DatabaseError):
            kb.KnowledgeStore(other, 'test')
        self.assertEqual(other.read_text(), 'not a database')

    def test_concurrent_connections_do_not_lose_updates(self):
        def write(number):
            store = kb.KnowledgeStore(self.path, 'engagement-a', clock=lambda: 1000)
            store.observe(self.url, 'waf', str(number), {'number': number}, 'concurrent')
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(24)))
        self.assertEqual(len(self.store.query(self.url)), 24)

    def test_context_captures_role_values_baseline_and_parameter(self):
        base = [self.url, 'GET', {'Cookie': 'role-a'}, 'q', 'original', [200, 'baseline']]
        expected = kb.request_context(*base)
        same = list(base)
        same[2] = {'cookie': 'role-a'}
        self.assertEqual(expected, kb.request_context(*same))
        for index, value in [(0, self.url + 'changed'), (1, 'POST'), (2, {'Cookie': 'role-b'}),
                             (3, 'other'), (4, 'new-original'), (5, [200, 'new-baseline'])]:
            changed = list(base)
            changed[index] = value
            self.assertNotEqual(expected, kb.request_context(*changed))

    def test_expired_or_hypothetical_failures_are_not_reused(self):
        context = 'context'
        self.store.record_failed_payload(self.url, context, 'payload', 200)
        self.assertTrue(self.store.failed_payload(self.url, context, 'payload'))
        self.assertFalse(self.store.failed_payload(self.url, 'different-role', 'payload'))
        self.now += 900
        self.assertFalse(self.store.failed_payload(self.url, context, 'payload'))
        self.store.observe(self.url, 'payload_failure', kb.digest('payload'), {'outcome': 'no_new_error'},
                           'manual', confidence='hypothesis', context=context, resource='/item')
        self.assertFalse(self.store.failed_payload(self.url, context, 'payload'))

    def test_shared_database_does_not_store_raw_payload_credentials_or_query(self):
        context = kb.request_context(self.url, 'GET', {'Cookie': 'secret-cookie'}, 'q', 'secret-original', 'secret-body')
        self.store.record_failed_payload(self.url, context, 'secret-payload', 200)
        raw = self.path.read_bytes()
        for secret in [b'private-query', b'secret-cookie', b'secret-original', b'secret-body', b'secret-payload']:
            self.assertNotIn(secret, raw)

    def test_fingerprint_records_versions_and_waf_without_raw_headers(self):
        self.store.record_fingerprint({'technologies': ['WordPress'], 'details': {
            'url': self.url, 'waf': ['Cloudflare'], 'headers': {'Set-Cookie': 'secret-cookie'},
            'versioned_components': [{'name': 'plugin', 'version': '1.2.3'}]}})
        rows = self.store.query(self.url)
        self.assertEqual({r['kind'] for r in rows}, {'technology', 'waf'})
        self.assertEqual(rows[0]['value']['versioned_components'][0]['version'], '1.2.3')
        self.assertNotIn(b'secret-cookie', self.path.read_bytes())

    def test_empty_fingerprint_is_not_a_negative_fact(self):
        self.store.record_fingerprint({'host': 'app.example.test', 'details': {}})
        self.assertEqual(self.store.query(self.url), [])

    def test_response_signals_are_not_declared_confirmed_requirements(self):
        for status in [401, 403, 429, 0, 200]:
            self.store.record_response(self.url, status)
        rows = self.store.query(self.url)
        self.assertEqual({r['kind'] for r in rows}, {'auth', 'rate_limit'})
        self.assertTrue(all(r['confidence'] == 'observed' for r in rows))
        self.assertTrue(all(r['resource'] == '/item' for r in rows))

    def probe(self, status=200, body='clean', headers=None, baseline_status=200, store=True):
        responses = [(baseline_status, {}, 'baseline', 0), (status, {}, body, 0)]
        with patch.object(sqli, 'http_request', side_effect=responses) as request, \
             patch.object(sqli, 'ERROR_PAYLOADS', ["'"]):
            result = sqli.test_error_based(self.url, 'q', 'original', extra_headers=headers,
                                          max_mutations=0, knowledge=self.store if store else None)
        return result, request.call_count

    def test_repeat_probe_skips_network_but_retains_fresh_baseline(self):
        self.assertEqual(self.probe()[1], 2)
        self.assertEqual(self.probe()[1], 1)
        self.assertEqual(self.store.reused_probes, 1)

    def test_changed_auth_context_does_not_skip(self):
        self.probe(headers={'Cookie': 'a'})
        self.assertEqual(self.probe(headers={'Cookie': 'b'})[1], 2)

    def test_expired_probe_is_sent_again(self):
        self.probe()
        self.now += 900
        self.assertEqual(self.probe()[1], 2)

    def test_refresh_sends_again_and_invalidates_failure_on_positive_result(self):
        self.probe()
        self.store.refresh = True
        findings, count = self.probe(body='You have an error in your SQL syntax')
        self.assertEqual(count, 2)
        self.assertTrue(findings)
        self.store.refresh = False
        self.assertEqual(self.probe()[1], 2)

    def test_auth_rate_transport_errors_and_blocks_are_not_negative_probe_cache(self):
        for status, body in [(0, ''), (401, 'unauthorized'), (403, 'forbidden'),
                             (429, 'rate limit'), (500, 'server failure'), (200, 'request blocked')]:
            with self.subTest(status=status, body=body):
                self.assertEqual(self.probe(status=status, body=body)[1], 2)
        self.assertEqual(self.store.query(self.url, 'payload_failure'), [])

    def test_store_rejects_failed_status_as_a_clean_payload_outcome(self):
        for status in [0, 401, 403, 429, 500]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.store.record_failed_payload(self.url, 'context', 'payload', status)

    def test_malformed_manual_failure_value_does_not_justify_reuse(self):
        self.store.observe(self.url, 'payload_failure', kb.digest('payload'), 'not-an-outcome',
                           'manual', context='context', resource='/item')
        self.assertFalse(self.store.failed_payload(self.url, 'context', 'payload'))

    def test_failed_baseline_never_creates_negative_probe_cache(self):
        self.probe(baseline_status=0)
        self.assertEqual(self.store.query(self.url, 'payload_failure'), [])

    def test_disabled_mode_does_not_skip_or_create_files(self):
        self.assertEqual(self.probe(store=False)[1], 2)
        self.assertEqual(self.probe(store=False)[1], 2)
        self.assertEqual(self.store.query(self.url), [])

    def test_query_cli_process_reads_another_process_store(self):
        store = kb.KnowledgeStore(self.path, 'cli-engagement')
        store.observe(self.url, 'waf', 'fixture', {'products': ['fixture']}, 'fixture')
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/target_knowledge.py'),
            '--db', str(self.path), '--engagement', 'cli-engagement', '--target', self.url,
            '--kind', 'waf'], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]['value']['products'], ['fixture'])

    def test_recon_and_importer_cli_integrations_share_state(self):
        hosts = Path(self.temp.name) / 'hosts.txt'
        hosts.write_text('app.example.test')
        recon_out = Path(self.temp.name) / 'recon.json'
        flags = ['--knowledge-db', str(self.path), '--engagement', 'cli-engagement']
        with patch.object(sys, 'argv', ['tech_fingerprint', '--input', str(hosts), '--output', str(recon_out)] + flags), \
             patch.object(recon, 'fetch_page', return_value=({'server': 'nginx', 'cf-ray': 'fixture'}, '')), \
             contextlib.redirect_stdout(io.StringIO()):
            recon.main()
        inputs = Path(self.temp.name) / 'findings.json'
        outputs = Path(self.temp.name) / 'normalized.json'
        inputs.write_text(json.dumps({'findings': [{'type': 'ssrf', 'url': self.url, 'severity': 'HIGH'}]}))
        with patch.object(sys, 'argv', ['import_findings', '--input', str(inputs), '--output', str(outputs)] + flags), \
             contextlib.redirect_stdout(io.StringIO()):
            importer.main()
        finding = json.loads(outputs.read_text())['findings'][0]
        self.assertEqual(finding['severity'], 'HIGH')
        self.assertTrue(finding['target_knowledge'])
        self.assertIn('nginx', str(finding['target_knowledge']).lower())

    def test_sqli_cli_reports_reused_probes_and_recon_context(self):
        shared = kb.KnowledgeStore(self.path, 'cli-engagement')
        shared.record_fingerprint({'technologies': ['fixture-tech'], 'details': {'url': self.url}})
        output = Path(self.temp.name) / 'sqli.json'
        args = ['sqli', '--target', self.url, '--skip-time', '--delay', '0',
                '--max-mutations', '0', '--knowledge-db', str(self.path),
                '--engagement', 'cli-engagement', '--output', str(output)]
        def response(url, **kwargs):
            return 200, {}, 'baseline', 0
        with patch.object(sqli, 'http_request', side_effect=response), \
             patch.object(sqli, 'ERROR_PAYLOADS', ["'"]), \
             patch.object(sqli, 'test_boolean_based', return_value=[]), \
             patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            sqli.main()
            sqli.main()
        result = json.loads(output.read_text())
        self.assertEqual(result['meta']['knowledge_reused_error_payloads'], 1)
        self.assertIn('fixture-tech', str(result['target_knowledge']))

    def test_concurrent_process_writers_preserve_both_namespaces(self):
        code = (
            'import sys; sys.path.insert(0, sys.argv[1]); '
            'from target_knowledge import KnowledgeStore; '
            's=KnowledgeStore(sys.argv[2], sys.argv[3]); '
            's.observe("https://app.example.test/", "waf", sys.argv[4], {}, "process")'
        )
        def write(number):
            result = subprocess.run([sys.executable, '-c', code, str(ROOT / 'scripts'),
                str(self.path), 'process-' + str(number % 2), str(number)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(write, range(8)))
        for number in [0, 1]:
            store = kb.KnowledgeStore(self.path, 'process-' + str(number))
            self.assertEqual(len(store.query(self.url)), 4)

    def test_cli_requires_engagement_when_opted_in(self):
        result = subprocess.run([sys.executable, str(ROOT / 'skills/webapp-exploit-hunter/scripts/sqli_tester.py'),
            '--target', self.url, '--knowledge-db', str(self.path)], capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('engagement', result.stderr)


if __name__ == '__main__':
    unittest.main()
