"""Offline supervisor regressions; Git integration uses disposable local repositories."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
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

    def test_ambiguous_push_cannot_be_blindly_retried(self):
        self.enqueue()
        claimed = self.store.claim(self.owner, 120)
        self.store.checkpoint(self.owner, claimed, {'phase': 'needs-attention', 'push_attempted': True,
            'push_outcome': {'applied': None}}, 'attention')
        with self.assertRaisesRegex(ValueError, 'push may already be applied'):
            self.store.recover(confirmed=True, retry=claimed['id'])
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')

    def test_operator_can_reconcile_exact_approved_remote_and_unblock_dependencies(self):
        self.enqueue(task('first'))
        self.enqueue(task('dependent', ['other.txt'], dependencies=['first']))
        claimed = self.store.claim(self.owner, 120)
        candidate = 'a' * 40
        base = 'b' * 40
        checkpoint = {'candidate_sha': candidate, 'base_sha': base, 'reviewed_sha': candidate,
                      'review': {'approved': True, 'candidate_sha': candidate, 'base_sha': base, 'findings': []},
                      'checks': [{'passed': True}]}
        self.store.checkpoint(self.owner, claimed, checkpoint, 'attention')
        with self.assertRaises(ValueError):
            self.store.reconcile('first', 'wrong', confirmed=True)
        with self.assertRaises(ValueError):
            self.store.reconcile('first', candidate)
        self.store.reconcile('first', candidate, confirmed=True)
        self.assertEqual(self.store.tasks()[0]['state'], 'done')
        self.store.acquire_runner('new-runner', 120)
        self.assertEqual(self.store.claim('new-runner', 120)['id'], 'dependent')

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

    def test_stdout_and_stderr_stay_separate_for_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'json.log'
            result = sup.execute([sys.executable, '-c',
                'import sys; print("warning",file=sys.stderr); print("{}")'],
                directory, None, output, 10, lambda: None)
            self.assertEqual(json.loads(result), {})
            self.assertIn('warning', output.with_suffix('.log.stderr.log').read_text())

    def test_successful_parent_does_not_leave_background_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'orphan-wrote.txt'
            child = 'import time; from pathlib import Path; time.sleep(1); Path(' + repr(str(marker)) + ').write_text("orphan")'
            parent = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(child) + '])'
            sup.execute([sys.executable, '-c', parent], directory, None,
                        Path(directory) / 'parent.log', 10, lambda: None)
            time.sleep(1.5)
            self.assertFalse(marker.exists())

    def test_failure_diagnostics_are_bounded_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'failure.log'
            output.write_text('x' * 20000 + '\nassert expected useful-value\nAuthorization: Bearer private-token\nAPI_KEY=private-key\n')
            error = str(sup.ProcessFailed('failed', output))
            self.assertIn('assert expected useful-value', error)
            self.assertNotIn('private-token', error)
            self.assertNotIn('private-key', error)
            self.assertLess(len(error), 8500)

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
        (self.repo / 'app.txt').write_bytes(b'baseline\n')
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
        self.review_prompts = []
        self.author_prompts = []
        self.lose_ownership = False

    def worker_command(self, agent, review, final, config):
        return [agent, 'review' if review else 'author', str(final)]

    def runner(self, argv, cwd, prompt, output, timeout, heartbeat):
        heartbeat()
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        if argv[0] not in sup.AGENTS:
            if self.lose_ownership:
                raise sup.OwnershipLost('fixture lease lost')
            if self.fail_check:
                output.write_text('fixture check expected a useful repaired value')
                raise sup.ProcessFailed('fixture validation failure', output)
            output.write_text('checks passed')
            return 'checks passed'
        if argv[1] == 'author':
            self.author_prompts.append(prompt)
            self.author_calls += 1
            name = 'unclaimed.txt' if self.outside_file else 'app.txt'
            path = Path(cwd) / name
            path.write_bytes((path.read_text() + 'improved\n' if path.exists() else 'outside\n').encode())
            output.write_text(json.dumps({'is_error': False}))
            return output.read_text()
        self.review_prompts.append(prompt)
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

    def run_task(self, push=True, spec=None):
        self.store.enqueue(spec or task(), approved=True)
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

    def test_commit_hook_cannot_smuggle_unclaimed_file_into_candidate(self):
        hooks = self.base / 'hooks'
        hooks.mkdir()
        hook = hooks / 'pre-commit'
        hook.write_text('#!/bin/sh\necho hook-added > injected.txt\ngit add -- injected.txt\n', encoding='utf-8')
        hook.chmod(0o755)
        sup.run_git(self.repo, 'config', 'core.hooksPath', str(hooks))
        with self.assertRaisesRegex(RuntimeError, 'unclaimed file'):
            self.run_task()
        self.assertEqual(self.reviews, [])
        self.assertEqual(self.store.tasks()[0]['state'], 'attention')

    def test_worker_worktree_is_outside_git_metadata(self):
        self.run_task()
        worktree = Path(self.store.tasks()[0]['checkpoint']['worktree'])
        self.assertNotIn('.git', worktree.parts)
        self.assertNotIn(self.store.root, worktree.parents)

    def test_opposite_model_review_and_bounded_repair(self):
        self.reject_first = True
        self.assertEqual(self.run_task(), 1)
        self.assertEqual(self.author_calls, 2)
        self.assertNotEqual(self.reviews[0]['candidate_sha'], self.reviews[1]['candidate_sha'])
        self.assertEqual(self.store.tasks()[0]['checkpoint']['reviewer'], 'claude')

    def test_full_diff_is_reviewed_even_when_claim_uses_different_case(self):
        self.assertEqual(self.run_task(spec=task(files=['APP.TXT'])), 1)
        self.assertIn('+improved', self.review_prompts[0])

    def test_ownership_loss_during_validation_never_starts_a_repair(self):
        self.lose_ownership = True
        with self.assertRaises(sup.OwnershipLost):
            self.run_task()
        self.assertEqual(self.author_calls, 1)
        self.assertEqual(self.reviews, [])

    def test_lost_push_acknowledgement_reconciles_exact_remote_sha(self):
        original = sup.run_git
        def lose_ack(repo, *args, **kwargs):
            result = original(repo, *args, **kwargs)
            if args[0] == 'push':
                raise sup.ProcessFailed('push acknowledgement lost')
            return result
        with patch.object(sup, 'run_git', side_effect=lose_ack):
            self.assertEqual(self.run_task(), 1)
        record = self.store.tasks()[0]
        self.assertEqual(record['state'], 'done')
        self.assertTrue(record['checkpoint']['push_outcome']['applied'])

    def test_committed_whitespace_error_blocks_review(self):
        original_runner = self.runner
        def trailing_space(argv, cwd, prompt, output, timeout, heartbeat):
            result = original_runner(argv, cwd, prompt, output, timeout, heartbeat)
            if argv[0] in sup.AGENTS and argv[1] == 'author':
                (Path(cwd) / 'app.txt').write_bytes(b'baseline\ntrailing-space \n')
            return result
        self.runner = trailing_space
        with self.assertRaises(sup.ProcessFailed):
            self.run_task()
        self.assertEqual(self.reviews, [])

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
        self.assertIn('fixture check expected a useful repaired value', self.author_prompts[1])
        self.assertIn('BEGIN UNTRUSTED CHECK OUTPUT', self.author_prompts[1])
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
