#!/usr/bin/env python3
"""In-process tests for lounge upgrades from the 2026-10-17 PROGRAM_68 hunt."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import seatlib


def tmp_lounge():
    d = Path(tempfile.mkdtemp(prefix='lounge-test-'))
    (d / 'claims').mkdir()
    (d / 'hb').mkdir()
    (d / 'inbox').mkdir()
    (d / 'lock').mkdir()
    (d / 'state').mkdir()
    (d / 'events.jsonl').write_text('')
    (d / 'seq').write_text('0')
    cfg = {
        'program': 'testprog', 'seats': 2, 'state_root': str(d),
        'rate_per_s': 0.5, 'hb_dead_s': 90, 'toolkit': str(HERE),
        'doctrine_dir': '',
    }
    (d / 'lounge.json').write_text(json.dumps(cfg))
    return d


def test_cells_conflict():
    # exact mutex only — sibling axes do not conflict
    assert not seatlib.cells_conflict('POST /graphql', 'POST /graphql DOCUMENT_VERIFICATION loosen')
    assert not seatlib.cells_conflict('POST /rest/graph/tmc', 'POST /rest/graph/tmc verify')
    assert seatlib.cells_conflict(
        'POST /graphql DOCUMENT fields', 'post /graphql DOCUMENT fields')
    assert not seatlib.cells_conflict(
        'POST /graphql DOCUMENT fields', 'POST /graphql DOCUMENT count')
    assert not seatlib.cells_conflict('GET /graphql', 'POST /graphql')
    assert seatlib.cell_too_coarse('POST /graphql')
    assert not seatlib.cell_too_coarse('POST /graphql DOCUMENT fields')
    assert seatlib.normalize_cell('post /graphql?limit=10') == 'POST /graphql'
    assert seatlib.normalize_cell('POST  /rest/graph/tmc/') == 'POST /rest/graph/tmc'


def test_overlap_grant():
    L = tmp_lounge()
    assert not seatlib.grant(L, 'testprog', 'POST /graphql', 'dsclaude')  # coarse
    assert seatlib.grant(L, 'testprog', 'POST /graphql DOCUMENT fields', 'dsclaude')
    assert seatlib.grant(L, 'testprog', 'POST /graphql DOCUMENT count', 'grok3')
    assert not seatlib.grant(L, 'testprog', 'POST /graphql DOCUMENT fields', 'grok3')


def test_token_exit_and_mint():
    L = tmp_lounge()
    env = {**os.environ, 'LOUNGE_DIR': str(L), 'SEAT_ID': 's1'}
    py = [sys.executable, str(HERE / 'seatlib.py')]
    r1 = subprocess.run(py + ['token'], env=env, capture_output=True, text=True)
    j1 = json.loads(r1.stdout)
    assert j1['grant'] is True, r1.stdout
    assert r1.returncode == 0
    r2 = subprocess.run(py + ['token'], env=env, capture_output=True, text=True)
    j2 = json.loads(r2.stdout)
    assert j2['grant'] is False, r2.stdout
    assert r2.returncode == 1
    assert j2['why'] in ('empty', '429-cool')

    L2 = tmp_lounge()
    env2 = {**os.environ, 'LOUNGE_DIR': str(L2), 'SEAT_ID': 's1'}
    # --op read must NOT mint-lock (PROGRAM_68 dsclaude footgun)
    r = subprocess.run(py + ['token', '--op', 'read'], env=env2, capture_output=True, text=True)
    assert json.loads(r.stdout)['grant'] is True
    time.sleep(2.1)  # rate 0.5/s
    r = subprocess.run(py + ['token', '--op', 'read'], env=env2, capture_output=True, text=True)
    j = json.loads(r.stdout)
    assert j.get('why') != 'mint-lock', j
    assert j['grant'] is True, j

    L3 = tmp_lounge()
    env3 = {**os.environ, 'LOUNGE_DIR': str(L3), 'SEAT_ID': 's1'}
    r = subprocess.run(py + ['token', '--op', 'mint'], env=env3, capture_output=True, text=True)
    assert json.loads(r.stdout)['grant'] is True
    r = subprocess.run(py + ['token', '--op', 'mint'], env=env3, capture_output=True, text=True)
    j = json.loads(r.stdout)
    assert j['grant'] is False
    assert j['why'] == 'mint-lock'
    assert r.returncode == 1

    L4 = tmp_lounge()
    env4 = {**os.environ, 'LOUNGE_DIR': str(L4), 'SEAT_ID': 's1'}
    r = subprocess.run(py + ['token', '--op', 'grok4-deposit-config-create'], env=env4, capture_output=True, text=True)
    assert json.loads(r.stdout)['grant'] is True
    r = subprocess.run(py + ['token', '--op', 'grok4-deposit-config-create'], env=env4, capture_output=True, text=True)
    j = json.loads(r.stdout)
    assert j['grant'] is False and j['why'] == 'mint-lock', j


def test_is_mint_op():
    assert not seatlib.is_mint_op(None)
    assert not seatlib.is_mint_op('read')
    assert not seatlib.is_mint_op('probe')
    assert seatlib.is_mint_op('mint')
    assert seatlib.is_mint_op('pay')
    assert seatlib.is_mint_op('mint:write')
    # custom --op is a named mint channel (grok4 used this and thought it locked)
    assert seatlib.is_mint_op('grok4-deposit-config-create')


def test_hypo_reflect_roundtrip():
    L = tmp_lounge()
    env = {**os.environ, 'LOUNGE_DIR': str(L), 'SEAT_ID': 's1'}
    py = [sys.executable, str(HERE / 'seatlib.py')]
    r = subprocess.run(py + [
        'hypo', '--cell', 'POST /graphql DOCUMENT fields',
        '--source', 'widget queryDocument',
        '--oracle', 'FieldUndefined names the node type',
        '--shot', 'nodes { profileType } no fragment',
    ], env=env, capture_output=True, text=True)
    j = json.loads(r.stdout)
    assert j['type'] == 'HYPO' and 'oracle=' in j['note']
    r = subprocess.run(py + [
        'reflect', '--cell', 'POST /graphql DOCUMENT fields',
        '--klass', 'FieldUndefined UserUiConfiguration',
        '--sibling', 'POST /graphql DOCUMENT count',
    ], env=env, capture_output=True, text=True)
    j = json.loads(r.stdout)
    assert j['type'] == 'REFLECT' and 'sibling=' in j['note']


def test_extract_sibling_and_board():
    assert seatlib.extract_sibling(
        'class=200 | sibling=POST /graphql transferMethodConfigurations bankcard'
    ) == 'POST /graphql transferMethodConfigurations bankcard'
    assert seatlib.extract_sibling('class=200 | sibling=prod count-only') == ''
    L = tmp_lounge()
    env = {**os.environ, 'LOUNGE_DIR': str(L), 'SEAT_ID': 's1'}
    py = [sys.executable, str(HERE / 'seatlib.py')]
    r = subprocess.run(py + ['board'], env=env, capture_output=True, text=True)
    assert r.returncode == 0
    assert 'TAKE' in r.stdout
    r = subprocess.run(py + ['take'], env=env, capture_output=True, text=True)
    assert r.returncode == 1
    r = subprocess.run(py + [
        'reflect', '--cell', 'POST /graphql foo bar',
        '--klass', '200', '--sibling', 'prod count-only',
    ], env=env, capture_output=True, text=True)
    assert r.returncode == 1
    assert 'claimable cell' in r.stdout


def test_inotify_wake():
    import threading
    L = tmp_lounge()
    p = L / 'events.jsonl'
    t0 = time.perf_counter()
    def kick():
        time.sleep(0.03)
        p.write_text('{"seq":1}\n')
    threading.Thread(target=kick, daemon=True).start()
    woke = seatlib.wait_paths([p], 1.0)
    dt = (time.perf_counter() - t0) * 1000
    assert woke, 'inotify did not wake'
    assert dt < 200, f'wake {dt:.1f}ms'
    print(f'inotify wake {dt:.1f}ms')


def test_install_parses():
    r = subprocess.run(['bash', '-n', str(HERE / 'install.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(['bash', '-n', str(HERE / 'go.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(['bash', '-n', str(HERE / 'stop.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(['bash', '-n', str(HERE / 'seat_launcher.sh')], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_hooks_do_not_exec_live_talk():
    """F2: exec live_talk made the hunt router dead code."""
    roots = [
        Path.home() / '.grok/mythos',
        Path.home() / '.claude/mythos',
        Path.home() / '.claude-deepseek/mythos',
    ]
    found = 0
    for root in roots:
        for name in ('context_router.sh', 'stop_guard.sh'):
            p = root / name
            if not p.exists():
                continue
            text = p.read_text()
            found += 1
            assert 'exec python3' not in text or 'live_talk.py' not in text.split('exec python3')[-1][:80]
            assert 'live_talk.py' in text
            # exec of live_talk specifically must be gone
            for line in text.splitlines():
                s = line.strip()
                if s.startswith('exec ') and 'live_talk.py' in s:
                    raise AssertionError(f'{p} still execs live_talk: {s}')
    assert found >= 4, f'expected hook files, found {found}'


def test_lounge_session_gate():
    """F3: leftover ~/.lounge role must not hijack a solo session."""
    import live_talk
    os.environ.pop('LOUNGE_JOINED', None)
    os.environ.pop('LOUNGE_SEAT', None)
    os.environ.pop('LOUNGE_ROLE', None)
    os.environ.pop('LOUNGE_DIR', None)
    assert live_talk.lounge_session() is False
    os.environ['LOUNGE_SEAT'] = 'dsclaude'
    assert live_talk.lounge_session() is True
    os.environ.pop('LOUNGE_SEAT', None)
    os.environ['LOUNGE_JOINED'] = '1'
    assert live_talk.lounge_session() is True
    os.environ.pop('LOUNGE_JOINED', None)


def test_reflect_class_alias():
    L = tmp_lounge()
    env = {**os.environ, 'LOUNGE_DIR': str(L), 'SEAT_ID': 's1'}
    py = [sys.executable, str(HERE / 'seatlib.py')]
    r = subprocess.run(py + [
        'reflect', '--cell', 'POST /graphql DOCUMENT fields',
        '--class', 'FieldUndefined',
        '--sibling', 'POST /graphql DOCUMENT count',
    ], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)['type'] == 'REFLECT'


def test_obligation_kill_forces_other_seat():
    L = tmp_lounge()
    kill = {'seq': 10, 'type': 'KILL', 'seat': 'grok4', 'cell': 'GET /v1/apps/{aid} unauth',
            'note': 'axis=secret-leak class=public twin'}
    ob = seatlib.sync_obligation(L, kill)
    assert ob['kind'] == 'bypass' and ob['from'] == 'grok4'
    # author owes nothing
    assert seatlib.owe_view(L, 'grok4') is None
    view = seatlib.owe_view(L, 'dsclaude')
    assert view and view['owe'] and 'DIFFERENT' in view['do']
    # a claim is not a shot — debt stays on grok4's kill
    seatlib.sync_obligation(L, {'seq': 11, 'type': 'CLAIM', 'seat': 'dsclaude',
                                'cell': 'GET /v1/teams/{id}/secrets cross-app', 'note': 'claim'})
    assert seatlib.load_obligation(L)['from'] == 'grok4'
    # a classed reflect on a different cell answers it, then becomes dsclaude's debt
    seatlib.sync_obligation(L, {
        'seq': 12, 'type': 'REFLECT', 'seat': 'dsclaude',
        'cell': 'GET /v1/teams/{id}/secrets cross-app',
        'note': 'class=404 HTML | sibling=GET /api/v1/teams/{id}/secrets dash_bearer',
    })
    answered = seatlib.load_obligation(L)
    assert answered['from'] == 'dsclaude'
    assert answered['sibling'] == ''  # dash_bearer is human-gated, not a shot
    # closed family is a draft, not another probe
    seatlib.sync_obligation(L, {
        'seq': 12, 'type': 'REFLECT', 'seat': 'dsclaude',
        'cell': 'GET /v1/apps/{aid} unauth',
        'note': 'class=CLOSED WAI public twin',
    })
    closed = seatlib.load_obligation(L)
    assert closed['kind'] == 'report' and closed['phase'] == 'draft'
    # confirm reflect becomes a verify debt
    seatlib.sync_obligation(L, {
        'seq': 13, 'type': 'REFLECT', 'seat': 'dsclaude',
        'cell': 'GET /v1/apps/{aid} unauth',
        'note': 'class=200 CONFIRM n=2079 | sibling=GET /v1/apps/{aid}/test_credentials path_vs_secret',
    })
    v = seatlib.owe_view(L, 'grok4')
    assert v['kind'] == 'verify'
    assert 'test_credentials' in v['sibling']
    # report debt clears only on REPORT-OK from the other seat
    seatlib.sync_obligation(L, {'seq': 14, 'type': 'REPORT', 'seat': 'grok4',
                                'cell': 'GET /v1/apps/{aid} unauth', 'note': 'path=reports/x.md poc=curl'})
    assert seatlib.owe_view(L, 'dsclaude')['kind'] == 'report'
    seatlib.sync_obligation(L, {'seq': 15, 'type': 'REPORT-OK', 'seat': 'dsclaude',
                                'cell': 'GET /v1/apps/{aid} unauth', 'note': 'rerun matched'})
    assert seatlib.load_obligation(L) is None
    # a rerun of a same-app report is a climb, and a 404 does not clear it
    seatlib.sync_obligation(L, {
        'seq': 20, 'type': 'REFLECT', 'seat': 'grok4',
        'cell': 'POST /v1/condition_sets/{id}/condition_set_items s12',
        'note': 'class=RERUN matches the report. app secret alone. Operator submits.',
    })
    climb = seatlib.owe_view(L, 'dsclaude')
    assert climb and climb['kind'] == 'climb'
    seatlib.sync_obligation(L, {
        'seq': 21, 'type': 'REFLECT', 'seat': 'dsclaude',
        'cell': 'GET /v1/users/{uid}/kyc basic_a',
        'note': 'class=404 User not found',
    })
    assert seatlib.load_obligation(L)['kind'] == 'climb'
    seatlib.sync_obligation(L, {
        'seq': 22, 'type': 'REFLECT', 'seat': 'dsclaude',
        'cell': 'GET /v1/wallets other_app',
        'note': 'class=200 foreign wallet id and policy of app B',
    })
    assert seatlib.load_obligation(L)['from'] == 'dsclaude'
    assert seatlib._safe_sibling(
        'class=404 | sibling=GET /api/v1/teams/{id}/secrets dash_bearer') == ''
    assert 'dash_bearer' in seatlib.extract_sibling(
        'class=404 | sibling=GET /api/v1/teams/{id}/secrets dash_bearer')


def test_least_loaded_uses_hb_dead_s():
    import conductor
    L = tmp_lounge()
    cfg = json.loads((L / 'lounge.json').read_text())
    cfg['hb_dead_s'] = 90
    (L / 'lounge.json').write_text(json.dumps(cfg))
    now = time.time()
    (L / 'hb' / 'peer.json').write_text(json.dumps({'ts': now - 45, 'wip': 0}))
    # 45s old is dead under the old 30s window, alive under hb_dead_s=90
    got = conductor._least_loaded(L, exclude='me')
    assert got == 'peer', got


if __name__ == '__main__':
    test_cells_conflict()
    test_overlap_grant()
    test_is_mint_op()
    test_token_exit_and_mint()
    test_hypo_reflect_roundtrip()
    test_extract_sibling_and_board()
    test_inotify_wake()
    test_install_parses()
    test_hooks_do_not_exec_live_talk()
    test_lounge_session_gate()
    test_reflect_class_alias()
    test_least_loaded_uses_hb_dead_s()
    test_obligation_kill_forces_other_seat()
    print('OK lounge tests')
