"""Read-only session-stream and monitor regressions."""
import importlib.util
import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools/agent-supervisor' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


view = load('session_view_tests', 'live_view.py')
backend = load('session_backend_tests', 'supervisor.py')


class SessionViewTests(unittest.TestCase):
    def test_claude_result_accepts_old_json_and_stream_json(self):
        result = {'type': 'result', 'is_error': False, 'structured_output': {'approved': True}}
        self.assertEqual(backend.claude_result(json.dumps(result)), result)
        stream = json.dumps({'type': 'system', 'subtype': 'init'}) + '\n' + json.dumps(result) + '\n'
        self.assertEqual(backend.claude_result(stream), result)
        with self.assertRaises(ValueError):
            backend.claude_result('{"type":"assistant"}\n')

    def test_review_parser_accepts_streamed_structured_result(self):
        result = dict(approved=True, candidate_sha='candidate', base_sha='base', findings=[])
        text = json.dumps({'type': 'system', 'subtype': 'init'}) + '\n' + json.dumps(
            {'type': 'result', 'is_error': False, 'structured_output': result})
        self.assertTrue(backend.parse_review('claude', text, None, 'candidate', 'base')['approved'])

    def test_codex_events_expose_session_messages_and_tool_activity(self):
        identifier = str(uuid.uuid4())
        events = [{'type': 'thread.started', 'thread_id': identifier},
                  {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'Inspecting source'}},
                  {'type': 'item.started', 'item': {'type': 'command_execution', 'command': 'git status'}},
                  {'type': 'turn.completed'}]
        result = view.summarize(events)
        self.assertEqual(result['session_id'], identifier)
        self.assertEqual(result['agent'], 'codex')
        self.assertIn('Tool: git status', result['messages'])
        self.assertEqual(result['result'], 'completed')

    def test_claude_events_expose_native_session_id(self):
        identifier = str(uuid.uuid4())
        events = [{'type': 'system', 'subtype': 'init', 'session_id': identifier},
                  {'type': 'assistant', 'message': {'content': [
                      {'type': 'text', 'text': 'Reviewing this goal'}, {'type': 'tool_use', 'name': 'Read'}]}},
                  {'type': 'result', 'session_id': identifier, 'result': 'Done', 'is_error': False}]
        result = view.summarize(events)
        self.assertEqual(result['session_id'], identifier)
        self.assertEqual(result['agent'], 'claude')
        self.assertIn('Reviewing this goal', result['messages'])
        self.assertIn('Tool: Read', result['messages'])

    def test_partial_event_does_not_hide_previous_complete_events(self):
        text = '{"type":"thread.started","thread_id":"fixture"}\n{"type":"item.'
        self.assertEqual(len(view.events_from_text(text)), 1)

    def test_snapshot_groups_both_providers_under_same_goal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs' / 'same-goal' / '1'
            run.mkdir(parents=True)
            for agent in ['codex', 'claude']:
                log = run / (agent + '-demo.log')
                identifier = str(uuid.uuid4())
                log.write_text(json.dumps({'type': 'thread.started', 'thread_id': identifier}) if agent == 'codex'
                    else json.dumps({'type': 'system', 'subtype': 'init', 'session_id': identifier}))
                log.with_suffix('.session.json').write_text(json.dumps({'agent': agent, 'name': 'same-goal / ' + agent}))
                log.with_suffix('.log.process.json').write_text(json.dumps({'state': 'running', 'pid': 100, 'started_at': time.time(), 'heartbeat_at': time.time()}))
            rows = view.sessions(root, 'same-goal')
            self.assertEqual({row['agent'] for row in rows}, {'codex', 'claude'})
            self.assertTrue(all(row['goal'] == 'same-goal' and row['state'] == 'running' for row in rows))
            self.assertTrue(all(row['resume_command'] for row in rows))
            self.assertEqual(view.sessions(root, 'other-goal'), [])
            rendered = view.render(rows, 'same-goal')
            self.assertIn('CODEX', rendered)
            self.assertIn('CLAUDE', rendered)
            self.assertIn('same-goal', rendered)

    def test_control_snapshot_exposes_goal_progress_and_stop_switch_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = backend.Store(root)
            store.enqueue({'id': 'goal', 'agent': 'codex', 'prompt': 'fixture', 'files': ['app.txt']}, approved=True)
            store.acquire_runner('owner', 120)
            task = store.claim('owner', 120)
            store.checkpoint('owner', task, {'phase': 'reviewing'})
            goals, stopped = view.control_snapshot(root)
            self.assertEqual(goals['goal']['progress_percent'], 65)
            self.assertFalse(stopped)
            store.stop()
            self.assertTrue(view.control_snapshot(root)[1])

    def test_stale_marker_is_not_presented_as_a_verified_running_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs' / 'goal' / '1'
            run.mkdir(parents=True)
            log = run / 'codex-demo.log'
            log.write_text(json.dumps({'type': 'thread.started', 'thread_id': str(uuid.uuid4())}))
            log.with_suffix('.log.process.json').write_text(json.dumps({'state': 'running', 'pid': 100, 'started_at': 1}))
            self.assertEqual(view.sessions(root)[0]['state'], 'stale/unknown')

    def test_terminal_control_sequences_are_not_replayed(self):
        self.assertEqual(view.clean('\x1b[2Jhello\x00\x07'), 'hello')

    def test_bounded_stream_retains_first_session_event_and_latest_message(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stream.log'
            first = json.dumps({'type': 'thread.started', 'thread_id': 'fixture-id'})
            last = json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'latest'}})
            path.write_text(first + '\n' + ('{"type":"noise"}\n' * 20000) + last + '\n')
            text = view.bounded_stream(path)
            self.assertLess(len(text), 100000)
            result = view.summarize(view.events_from_text(text))
            self.assertEqual(result['session_id'], 'fixture-id')
            self.assertEqual(result['messages'][-1], 'latest')

    def test_empty_queue_view_does_not_invent_or_launch_work(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(view.sessions(Path(directory)), [])
            self.assertIn('No worker sessions yet', view.render([]))
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
