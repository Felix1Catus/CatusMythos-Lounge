"""Offline supervisor regressions; Git integration uses disposable local repositories."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('agent_supervisor_test', ROOT / 'tools/agent-supervisor/supervisor.py')
sup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sup)


def task(name='task-one', files=None, agent='codex', dependencies=None):
    return {'id': name, 'agent': agent, 'prompt': 'Improve the fixture.',
            'files': files or ['app.txt'], 'depends_on': dependencies or []}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 100.0
        self.store = sup.Store(Path(self.temp.name) / 'runtime', clock=lambda: self.now)
        self.owner = 'runner-one'
        self.store.acquire_runner(self.owner, 120)

    def enqueue(self, spec=None):
        self.store.enqueue(spec or task(), approved=True)

    def test_operator_approval_is_required(self):
        with self.assertRaises(ValueError):
            self.store.enqueue(task())
        self.assertEqual(self.store.tasks(), [])

    def test_unsafe_identifiers_and_claims_are_rejected(self):
        for value in ['../escape', 'a/b', '', 'a b', '-flag']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                sup.safe_id(value)
        for value in ['../escape', '/absolute', 'C:/outside', '.git/config', 'a/../b',
                      'a\\b', 'src/*.py', 'a\nb']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                sup.safe_path(value)

    def test_directory_overlap(self):
        self.assertTrue(sup.overlaps('SRC/', 'src/app.py'))
        self.assertTrue(sup.overlaps('app.txt', 'APP.TXT'))
        self.assertTrue(sup.overlaps('src/', 'src/app.py'))
        self.assertTrue(sup.overlaps('src/app.py', 'src/'))
        self.assertFalse(sup.overlaps('src/', 'src-other/app.py'))

    def test_claims_are_atomic_across_connections(self):
        self.enqueue()
        def claim(_):
            return sup.Store(self.store.root, clock=lambda: self.now).claim(self.owner, 120)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(claim, range(12)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_overlapping_file_sets_conflict(self):
        self.enqueue(task('one', ['src/']))
        self.enqueue(task('two', ['src/app.py', 'other.py']))
        self.assertEqual(self.store.claim(self.owner, 120)['id'], 'one')
        self.assertIsNone(self.store.claim(self.owner, 120))

    def test_quarantined_claims_are_not_reassigned(self):
        self.enqueue(task('one'))
        self.enqueue(task('two'))
        claimed = self.store.claim(self.owner, 120)
        self.store.checkpoint(self.owner, claimed, {'error': 'fixture'}, 'attention')
        self.assertIsNone(self.store.claim(self.owner, 120))

    def test_stale_fencing_token_cannot_update_or_renew(self):
        self.enqueue()
        old = self.store.claim(self.owner, 120)
        self.store.recover(confirmed=True, retry=old['id'])
        self.store.acquire_runner('new-owner', 120)
        new = self.store.claim('new-owner', 120)
        self.assertGreater(new['fence'], old['fence'])
        with self.assertRaises(RuntimeError):
            self.store.checkpoint(self.owner, old, {'wrong': True}, 'done')
        with self.assertRaises(RuntimeError):
            self.store.pulse(self.owner, 120, old)

    def test_expired_owner_is_not_automatically_replaced(self):
        self.enqueue()
        claimed = self.store.claim(self.owner, 120)
        self.now += 121
        with self.assertRaises(RuntimeError):
            self.store.pulse(self.owner, 120, claimed)
        with self.assertRaises(RuntimeError):
            self.store.acquire_runner('replacement', 120)
        with self.assertRaises(ValueError):
            self.store.recover()

    def test_stop_prevents_heartbeats_and_new_claims(self):
        self.store.stop()
        with self.assertRaises(RuntimeError):
            self.store.pulse(self.owner, 120)
        with self.assertRaises(RuntimeError):
            self.store.claim(self.owner, 120)

    def test_dependency_must_exist_and_finish(self):
        with self.assertRaises(ValueError):
            self.enqueue(task('second', dependencies=['missing']))
        self.enqueue(task('first', ['first.txt']))
        self.enqueue(task('second', ['second.txt'], dependencies=['first']))
        claimed = self.store.claim(self.owner, 120)
        self.assertIsNone(self.store.claim(self.owner, 120))
        self.store.checkpoint(self.owner, claimed, {'phase': 'pushed'}, 'done')
        self.assertEqual(self.store.claim(self.owner, 120)['id'], 'second')

    def test_approval_hash_detects_changed_spec(self):
        self.enqueue()
        with self.store.db() as db:
            db.execute('UPDATE tasks SET spec=?', (json.dumps(task(files=['other.txt'])),))
        with self.assertRaises(RuntimeError):
            self.store.claim(self.owner, 120)

    def test_transcript_is_rebuilt_without_touching_historical_mailbox(self):
        self.enqueue()
        view = Path(self.temp.name) / 'view.md'
        self.store.transcript(view)
        self.assertIn('Event 1', view.read_text(encoding='utf-8'))
        with self.assertRaises(ValueError):
            self.store.transcript(Path(self.temp.name) / 'claude-to-codex.md')
        self.assertEqual(len(self.store.tasks()), 1)

    def test_cancellation_releases_claims_only_after_operator_confirmation(self):
        self.enqueue(task('one'))
        self.enqueue(task('two'))
        claimed = self.store.claim(self.owner, 120)
        self.store.checkpoint(self.owner, claimed, {'phase': 'reviewing'}, 'attention')
        with self.assertRaises(ValueError):
            self.store.cancel('one')
        self.store.cancel('one', confirmed=True)
        self.assertEqual(self.store.claim(self.owner, 120)['id'], 'two')

    def test_checkpoint_progress_tracks_measured_stage(self):
        self.enqueue()
        claimed = self.store.claim(self.owner, 120)
        self.store.checkpoint(self.owner, claimed, {'phase': 'reviewing'})
        self.assertEqual(self.store.tasks()[0]['checkpoint']['progress_percent'], 65)

    def test_second_runner_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.store.acquire_runner('other', 120)


class ProcessTests(unittest.TestCase):
    def test_arguments_and_stdin_are_not_shell_interpolated(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'process.log'
            value = 'literal $(not-a-command) `backtick` & percent%'
            result = sup.execute([sys.executable, '-c', 'import sys; print(sys.stdin.read())'],
                                 directory, value, output, 10, lambda: None)
            self.assertEqual(result.strip(), value)
            marker = json.loads(output.with_suffix('.log.process.json').read_text())
            self.assertEqual(marker['state'], 'parent-exited')
            self.assertTrue(marker['session_token'])

    def test_timeout_and_stop_quarantine_child(self):
        with tempfile.TemporaryDirectory() as directory:
            for stopping in [False, True]:
                output = Path(directory) / ('stop.log' if stopping else 'timeout.log')
                def heartbeat():
                    if stopping:
                        raise RuntimeError('stop requested')
                with self.subTest(stopping=stopping), self.assertRaises((TimeoutError, RuntimeError)):
                    sup.execute([sys.executable, '-c', 'import time; time.sleep(20)'],
                                directory, None, output, .25, heartbeat)
                marker = json.loads(output.with_suffix('.log.process.json').read_text())
                self.assertIsNotNone(marker['returncode'])

    def test_review_rejects_stale_sha_false_types_and_unresolved_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            final = Path(directory) / 'review.json'
            valid = dict(approved=True, candidate_sha='candidate', base_sha='base', findings=[])
            final.write_text(json.dumps(valid))
            self.assertTrue(sup.parse_review('codex', '', final, 'candidate', 'base')['approved'])
            for change in [dict(candidate_sha='old'), dict(base_sha='old'),
                           dict(approved='true'), dict(findings=['unresolved']), dict(extra='unexpected')]:
                final.write_text(json.dumps(dict(valid, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    sup.parse_review('codex', '', final, 'candidate', 'base')

    def test_permission_adapters_never_use_bypass_flags(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sup, 'resolve_cli', side_effect=lambda a: [a]):
            for agent in sup.AGENTS:
                for review in [False, True]:
                    args = sup.worker_command(agent, review, Path(directory) / 'final.json', {})
                    self.assertFalse(any('bypass' in value or 'skip-permissions' in value for value in args))
                    if agent == 'codex':
                        self.assertIn('read-only' if review else 'workspace-write', args)
                    elif review:
                        self.assertIn('Read,Glob,Grep', args)
                        self.assertNotIn('Read,Glob,Grep,Edit,Write', args)

    def test_disabled_configuration_and_invalid_limits(self):
        for config in [{}, {'version': 1, 'checks': ['shell command']},
                       {'version': 1, 'checks': [['python3']], 'max_repairs': 100}]:
            with self.assertRaises(ValueError):
                sup.validate_config(config)


class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        self.remote = self.base / 'remote.git'
        subprocess.run(['git', 'init', '--bare', str(self.remote)], check=True, capture_output=True)
        subprocess.run(['git', 'init', '-b', 'main', str(self.repo)], check=True, capture_output=True)
        sup.run_git(self.repo, 'config', 'user.name', 'Fixture')
        sup.run_git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        sup.run_git(self.repo, 'config', 'core.autocrlf', 'false')
        (self.repo / 'app.txt').write_text('baseline\n')
        sup.run_git(self.repo, 'add', 'app.txt')
        sup.run_git(self.repo, 'commit', '-m', 'fixture baseline')
        sup.run_git(self.repo, 'remote', 'add', 'origin', str(self.remote))
        sup.run_git(self.repo, 'push', '-u', 'origin', 'main')
        self.initial = sup.run_git(self.repo, 'rev-parse', 'HEAD')
        self.config = {'version': 1, 'enabled': True, 'push': True, 'max_repairs': 1,
                       'checks': [[sys.executable, '-c', 'pass']]}
        self.store = sup.Store(sup.runtime_dir(self.repo))
        self.reviews = []
        self.reject_first = False
        self.outside_file = False
        self.fail_check = False
        self.advance_main = False
        self.author_calls = 0

    def worker_command(self, agent, review, final, config):
        return [agent, 'review' if review else 'author', str(final)]

    def runner(self, argv, cwd, prompt, output, timeout, heartbeat):
        heartbeat()
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        if argv[0] not in sup.AGENTS:
            if self.fail_check:
                raise RuntimeError('fixture validation failure')
            output.write_text('checks passed')
            return 'checks passed'
        if argv[1] == 'author':
            self.author_calls += 1
            name = 'unclaimed.txt' if self.outside_file else 'app.txt'
            path = Path(cwd) / name
            path.write_text(path.read_text() + 'improved\n' if path.exists() else 'outside\n')
            output.write_text(json.dumps({'is_error': False}))
            return output.read_text()
        candidate = sup.run_git(cwd, 'rev-parse', 'HEAD')
        base = self.initial
        # All task candidates must expose their exact base in the review prompt.
        for line in prompt.splitlines():
            if line.startswith('{"base_sha"'):
                base = json.loads(line)['base_sha']
        result = dict(approved=not self.reject_first or bool(self.reviews), candidate_sha=candidate,
                      base_sha=base, findings=['fixture repair requested'] if self.reject_first and not self.reviews else [])
        self.reviews.append(result)
        if self.advance_main:
            extra = self.base / 'external'
            subprocess.run(['git', 'clone', '-b', 'main', str(self.remote), str(extra)], check=True, capture_output=True)
            (extra / 'other.txt').write_text('another contributor')
            sup.run_git(extra, 'add', 'other.txt')
            sup.run_git(extra, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'concurrent change')
            sup.run_git(extra, 'push', 'origin', 'main')
        Path(argv[2]).write_text(json.dumps(result))
        text = json.dumps({'structured_output': result, 'is_error': False})
        output.write_text(text)
        return text

    def run_task(self, push=True):
        self.store.enqueue(task(), approved=True)
        engine = sup.Supervisor(self.repo, self.config, self.store, runner=self.runner)
        with patch.object(sup, 'worker_command', side_effect=self.worker_command):
            return engine.run(execute_tasks=True, push=push, max_seconds=60)

    def test_full_author_review_validate_push_cycle_uses_local_remote(self):
        self.assertEqual(self.run_task(), 1)
        record = self.store.tasks()[0]
        self.assertEqual(record['state'], 'done')
        self.assertEqual(record['checkpoint']['reviewed_sha'], record['checkpoint']['remote_sha'])
        self.assertNotEqual(record['checkpoint']['remote_sha'], self.initial)
        self.assertEqual(sup.run_git(self.repo, 'rev-parse', 'HEAD'), self.initial)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'baseline\n')

    def test_opposite_model_review_and_bounded_repair(self):
        self.reject_first = True
        self.assertEqual(self.run_task(), 1)
        self.assertEqual(self.author_calls, 2)
        self.assertNotEqual(self.reviews[0]['candidate_sha'], self.reviews[1]['candidate_sha'])
        self.assertEqual(self.store.tasks()[0]['checkpoint']['reviewer'], 'claude')

    def test_unclaimed_changes_are_quarantined_before_commit_or_push(self):
        self.outside_file = True
        with self.assertRaises(RuntimeError):
            self.run_task()
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')
        self.assertEqual(sup.run_git(self.repo, 'ls-remote', 'origin', 'refs/heads/main').split()[0], self.initial)
        self.assertEqual(self.reviews, [])

    def test_failed_validation_never_reaches_review_or_push(self):
        self.fail_check = True
        with self.assertRaises(RuntimeError):
            self.run_task()
        self.assertEqual(self.author_calls, 2)
        self.assertEqual(self.reviews, [])
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')

    def test_changed_main_invalidates_reviewed_integration(self):
        self.advance_main = True
        with self.assertRaisesRegex(RuntimeError, 'main advanced'):
            self.run_task()
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')
        self.assertNotEqual(sup.run_git(self.repo, 'ls-remote', 'origin', 'refs/heads/main').split()[0],
                            self.reviews[0]['candidate_sha'])

    def test_push_requires_both_operator_gates(self):
        self.config['push'] = False
        with self.assertRaises(ValueError):
            self.run_task()
        self.assertEqual(self.author_calls, 0)

    def test_reviewed_candidate_without_push_is_retained_for_operator(self):
        with self.assertRaisesRegex(RuntimeError, 'push disabled'):
            self.run_task(push=False)
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')
        self.assertEqual(sup.run_git(self.repo, 'ls-remote', 'origin', 'refs/heads/main').split()[0], self.initial)

    def test_runtime_is_shared_between_worktrees(self):
        other = self.base / 'other-worktree'
        sup.run_git(self.repo, 'worktree', 'add', '--detach', str(other), self.initial)
        self.assertEqual(sup.runtime_dir(self.repo), sup.runtime_dir(other))


if __name__ == '__main__':
    unittest.main()
