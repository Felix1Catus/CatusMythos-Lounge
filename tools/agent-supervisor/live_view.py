"""Read-only shared terminal view of real Codex/Claude CLI session streams."""
import concurrent.futures
import importlib.util
import json
import re
import shutil
import sqlite3
import sys
import time
import uuid
from pathlib import Path


def clean(value):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(value))
    return ''.join(char for char in text if char in '\n\t' or 32 <= ord(char) < 127 or ord(char) >= 160)


def events_from_text(text):
    """Accept both historical one-JSON results and current JSONL streams."""
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return [value]
    except (ValueError, TypeError):
        pass
    events = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
        except ValueError:
            continue  # incomplete lines are completed on the next refresh
    return events


def summarize(events, defaults=None):
    result = dict(defaults or {})
    messages = []
    for event in events:
        kind = event.get('type')
        if kind == 'thread.started':
            result.update(agent='codex', session_id=event.get('thread_id'))
        elif kind == 'system' and event.get('subtype') == 'init':
            result.update(agent='claude', session_id=event.get('session_id'))
        elif kind == 'result':
            result.setdefault('agent', 'claude')
            if event.get('session_id'):
                result['session_id'] = event['session_id']
            if event.get('is_error') or event.get('permission_denials') or str(event.get('subtype', '')).startswith('error'):
                result['result'] = 'needs-attention'
            else:
                result['result'] = 'completed'
                if event.get('result'):
                    messages.append(clean(event['result']))
                elif isinstance(event.get('structured_output'), dict):
                    review = event['structured_output']
                    messages.append('Review: ' + ('approved' if review.get('approved') is True else 'changes requested'))
        if kind in ('item.started', 'item.completed'):
            item = event.get('item', {})
            if item.get('type') == 'agent_message' and item.get('text'):
                messages.append(clean(item['text']))
            elif item.get('type') == 'command_execution' and item.get('command'):
                messages.append('Tool: ' + clean(item['command']))
        elif kind in ('assistant', 'user'):
            message = event.get('message', {})
            for block in message.get('content', []) if isinstance(message, dict) else []:
                if isinstance(block, dict) and block.get('type') == 'text':
                    messages.append(clean(block.get('text', '')))
                elif isinstance(block, dict) and block.get('type') == 'tool_use':
                    messages.append('Tool: ' + clean(block.get('name', 'unknown')))
        elif kind in ('turn.failed', 'error'):
            result['result'] = 'needs-attention'
            messages.append(clean(event.get('message') or event.get('error') or kind))
        elif kind == 'turn.completed':
            result['result'] = 'completed'
    result['messages'] = messages[-6:]
    return result


def bounded_stream(path):
    """Keep the initial session event and recent activity, with bounded memory."""
    with path.open('rb') as stream:
        prefix = stream.read(32768)
        stream.seek(0, 2)
        size = stream.tell()
        if size <= 98304:
            stream.seek(0)
            return stream.read().decode('utf-8', errors='replace')
        stream.seek(size - 65536)
        tail = stream.read().decode('utf-8', errors='replace')
    first_lines = prefix.decode('utf-8', errors='replace').splitlines()
    tail_lines = tail.splitlines()
    return '\n'.join(first_lines[:1] + tail_lines[1:])


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def control_snapshot(root):
    path = Path(root) / 'coordination.sqlite'
    if not path.exists():
        return {}, False
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=.2)
        try:
            rows = connection.execute('SELECT id,state,checkpoint FROM tasks').fetchall()
            stopped = connection.execute('SELECT stopped FROM control WHERE id=1').fetchone()
            return {row[0]: dict(json.loads(row[2]), task_state=row[1]) for row in rows}, bool(stopped and stopped[0])
        finally:
            connection.close()
    except (sqlite3.Error, ValueError):
        return {}, False


def sessions(root, goal=None):
    result = []
    runs = Path(root) / 'runs'
    goals, _ = control_snapshot(root)
    for directory in runs.glob('*/*'):
        goal_id = directory.parent.name
        if goal and goal != goal_id:
            continue
        for log in directory.glob('*.log'):
            if log.name.endswith('.stderr.log') or not log.name.startswith(('author-', 'review-', 'codex-demo', 'claude-demo')):
                continue
            defaults = {'goal': goal_id, 'attempt': directory.name, 'log': str(log),
                        'role': log.stem, 'agent': 'unknown', 'session_id': None}
            metadata = read_json(log.with_suffix('.session.json'))
            defaults.update({key: metadata[key] for key in ('agent', 'session_id', 'name') if key in metadata})
            try:
                view = summarize(events_from_text(bounded_stream(log)), defaults)
            except OSError:
                continue
            process = read_json(log.with_suffix(log.suffix + '.process.json'))
            view['pid'] = process.get('pid')
            view['state'] = ('running' if process.get('state') == 'running' else
                             'needs-attention' if process.get('returncode') not in (None, 0) else
                             view.get('result', 'completed' if process.get('returncode') == 0 else 'waiting'))
            view['started_at'] = process.get('started_at', log.stat().st_mtime)
            view['goal_status'] = goals.get(goal_id, {})
            if view['state'] == 'running' and time.time() - process.get('heartbeat_at', view['started_at']) > 10:
                view['state'] = 'stale/unknown'
            if view['session_id'] and view['agent'] in ('codex', 'claude'):
                try:
                    identifier = str(uuid.UUID(view['session_id']))
                except (ValueError, AttributeError):
                    identifier = None
                if identifier:
                    verb = 'resume' if view['agent'] == 'codex' else '--resume'
                    view['resume_command'] = '{} {} {}'.format(view['agent'], verb, identifier)
            result.append(view)
    return sorted(result, key=lambda item: (item['started_at'], item['agent']), reverse=True)


def render(rows, goal=None):
    width = max(50, shutil.get_terminal_size(fallback=(100, 24)).columns - 1)
    active = [row for row in rows if row['state'] == 'running']
    selected_goal = goal or ((active or rows)[0]['goal'] if rows else None)
    latest = {}
    for row in rows:
        if row['goal'] == selected_goal and row['agent'] not in latest:
            latest[row['agent']] = row
    visible = sorted(latest.values(), key=lambda row: row['agent'], reverse=True)[:2]
    status = visible[0].get('goal_status', {}) if visible else {}
    stage = ' | {} | {}%'.format(status.get('phase', status.get('task_state', 'waiting')), status.get('progress_percent', 0)) if status else ''
    lines = ['CATUSMYTHOS | SHARED GOAL SESSIONS',
             'Goal: ' + clean(selected_goal or 'waiting for an approved goal') + clean(stage),
             'Real CLI sessions | live messages and tools | read-only monitor', '']
    if not visible:
        lines += ['No worker sessions yet. The view will update when an approved goal starts.',
                  'No new task is created by watching.']
    for row in visible:
        lines += ['-' * width,
                  '{} | {} | {} | PID {}'.format(clean(row['agent'].upper()), clean(row['role']),
                      clean(row['state'].upper()), row.get('pid') or '-'),
                  'Session: ' + clean(row.get('session_id') or 'starting'),
                  'Name: ' + clean(row.get('name') or row['goal'])]
        if row.get('resume_command'):
            lines.append('Resume after stop: ' + clean(row['resume_command']))
        messages = list(dict.fromkeys(row.get('messages', [])))
        for message in messages[-2:]:
            lines.append('  ' + ' / '.join(clean(message).splitlines()))
        if not messages:
            lines.append('  Waiting for first message/tool event...')
    lines += ['', 'Ctrl+C: close monitor only. Workers keep running.',
              'Stop workers: python3 tools/agent-supervisor/supervisor.py stop']
    return '\n'.join(line[:width] for line in lines)


def watch(root, goal=None, once=False, seconds=3600):
    if not 1 <= seconds <= 86400:
        raise ValueError('watch duration must be 1..86400 seconds')
    deadline = time.monotonic() + seconds
    previous = None
    try:
        while True:
            view = render(sessions(root, goal), goal)
            if view != previous:
                if sys.stdout.isatty():
                    print('\x1b[2J\x1b[H', end='')
                print(view, flush=True)
                previous = view
            if once or time.monotonic() >= deadline:
                return
            time.sleep(.5)
    except KeyboardInterrupt:
        return


def demo(repo, root, goal, seconds=60):
    """Explicit bounded read-only demonstration. Never commits or queues coding tasks."""
    source = Path(__file__).with_name('supervisor.py')
    spec = importlib.util.spec_from_file_location('live_demo_supervisor', source)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    backend.safe_id(goal)
    if not 10 <= seconds <= 300:
        raise ValueError('demo duration must be 10..300 seconds')
    directory = Path(root) / 'runs' / goal / ('view-' + uuid.uuid4().hex[:10])
    directory.mkdir(parents=True)
    if control_snapshot(root)[1]:
        raise RuntimeError('stop switch is set; clear-stop explicitly before starting a demo')
    before = backend.run_git(repo, 'rev-parse', 'HEAD')
    before_status = backend.run_git(repo, 'status', '--porcelain')
    prompt = ('Read-only shared-goal visibility check. Goal: ' + goal +
              '. Inspect tools/agent-supervisor/README.md if available. State briefly what the supervisor does, '
              'which guard prevents unapproved tasks running, and one current limitation. '
              'Do not edit files, run Git mutations, launch agents, or start tasks #6-#8. '
              'This is a bounded demonstration of both providers reporting on the same goal.')
    def heartbeat():
        if control_snapshot(root)[1]:
            raise backend.OwnershipLost('visibility demo stopped by operator')
    def run(agent):
        final = directory / (agent + '-demo.json')
        command = backend.worker_command(agent, True, final, {'claude_max_budget_usd': 1})
        # This is an informational review, not candidate approval; omit result schemas.
        schema_flag = '--output-schema' if agent == 'codex' else '--json-schema'
        if schema_flag in command:
            index = command.index(schema_flag)
            del command[index:index + 2]
        log = directory / (agent + '-demo.log')
        try:
            text = backend.execute(command, repo, prompt, log, seconds, heartbeat)
            if agent == 'claude':
                result = backend.claude_result(text)
                if result.get('is_error') or result.get('permission_denials'):
                    raise RuntimeError('Claude demo failed or a permission was denied')
            return {'agent': agent, 'completed': True}
        except Exception as exc:
            return {'agent': agent, 'completed': False, 'error': str(exc)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, ('codex', 'claude')))
    if backend.run_git(repo, 'rev-parse', 'HEAD') != before or backend.run_git(repo, 'status', '--porcelain') != before_status:
        raise RuntimeError('read-only demonstration changed the checkout; inspect before proceeding')
    return results
