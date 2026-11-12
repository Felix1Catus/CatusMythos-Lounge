#!/usr/bin/env python3
# seatlib.py - PROJECT LOUNGE per-seat client library + CLI.
# Python 3 stdlib only. Importable AND runnable (subcommands).
#
# PROGRAM_68 hunt 2026-10-17 receipts baked in:
#   - exact cell mutex; sibling axes run together
#   - token CLI exits 1 on grant:false
#   - claim CLI exits 1 on DENY
#   - reflect --sibling must be METHOD /path AXIS
#   - follow defaults to this seat's seen cursor, not cat seq
#   - OWNER stores the cell string
#   - CLAIM wait matches claim_seq

import argparse
import ctypes
import hashlib
import json
import os
import select
import shutil
import sys
import time
from pathlib import Path

ISO_TS = lambda: time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + '.%03dZ' % (
    int(time.time() * 1000) % 1000
)

MINT_OPS = {
    'mint', 'write', 'pay', 'charge', 'create', 'delete', 'transfer',
    'submit', 'purchase', 'payout', 'prod-write', 'prod_write',
}

# ---- lounge path resolution -------------------------------------------------
def lounge_dir():
    d = os.environ.get('LOUNGE_DIR')
    if d:
        return Path(d)
    for p in [Path.cwd()]:
        for parent in [p, *p.parents]:
            if (parent / 'lounge.json').exists() and (parent / 'events.jsonl').exists():
                return parent
    return Path.home() / 'targets' / '_shared' / 'lounge'

# ---- filesystem mutex (mkdir atomic, stale-break) ---------------------------
def _acquire(lockdir, name, timeout=30.0, stale=30.0):
    path = Path(lockdir) / f'{name}.lock'
    start = time.time()
    warned = False
    while True:
        try:
            path.mkdir()
            (path / 'owner').write_text(f'{os.getpid()} {time.time()}')
            return True
        except FileExistsError:
            pass
        try:
            mt = path.stat().st_mtime
        except FileNotFoundError:
            continue
        if time.time() - mt > stale and not warned:
            warned = True
            try:
                shutil.rmtree(path)
                continue
            except OSError:
                pass
        if time.time() - start > timeout:
            return False
        time.sleep(0.02)

def _release(lockdir, name):
    p = Path(lockdir) / f'{name}.lock'
    try:
        shutil.rmtree(p)
    except OSError:
        pass

# ---- config -----------------------------------------------------------------
def load_config(L):
    return json.loads((L / 'lounge.json').read_text())

# ---- cell identity (exact mutex; sibling axes do not conflict) --------------
def normalize_cell(cell):
    s = ' '.join((cell or '').split())
    if not s:
        return ''
    parts = s.split(' ', 1)
    method = parts[0].upper()
    rest = parts[1] if len(parts) > 1 else ''
    if rest.startswith('/'):
        path, *extra = rest.split(' ', 1)
        path = path.split('?', 1)[0].rstrip('/') or '/'
        rest = path + ((' ' + extra[0]) if extra else '')
    return (method + (' ' + rest if rest else '')).strip()

def cell_tokens(cell):
    return normalize_cell(cell).split()

def cell_too_coarse(cell):
    """A claim needs METHOD, path, and an axis. Bare POST /graphql locks the table."""
    return len(cell_tokens(cell)) < 3

def cells_conflict(a, b):
    """Exact cell only. Sibling axes on the same path are simultaneous work."""
    na, nb = normalize_cell(a), normalize_cell(b)
    return bool(na) and na == nb

def extract_sibling(note):
    """Pull a claimable cell out of a REFLECT note. Empty if the sibling is prose."""
    if not note or 'sibling=' not in note:
        return ''
    sib = note.split('sibling=', 1)[1]
    sib = sib.split('|')[0].strip()
    methods = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}
    toks = sib.split()
    if not toks or toks[0].upper() not in methods:
        return ''
    for n in range(min(8, len(toks)), 2, -1):
        cand = ' '.join(toks[:n])
        if not cell_too_coarse(cand):
            return normalize_cell(cand)
    return ''

# ---- obligation: the other seat owes the next chain ------------------------
import re as _re
_BLOCK_RE = _re.compile(
    r'\b(400|401|403|404|409|422|429|500|blocked|denied|forbidden|not available|invalid)\b',
    _re.I,
)
_HUMAN_RE = _re.compile(
    r'(bearer|otp|prod[-_ ]write|bridge[-_ ]?sandbox|human[-_ ]gated|\bsubmit\b|dash_bearer)',
    _re.I,
)
_CEILING_RE = _re.compile(
    r'\b(CLOSED|EXHAUSTIVELY|WAI|no reachable)\b',
    _re.I,
)

def _conductor_alive(L):
    """True only if conductor.pid is a live conductor.py, not a recycled pid."""
    try:
        pid = int((Path(L) / 'conductor.pid').read_text().strip())
        os.kill(pid, 0)
        cmd = open(f'/proc/{pid}/cmdline', 'rb').read().replace(b'\x00', b' ').decode('utf-8', 'replace')
    except Exception:
        return False
    return 'conductor.py' in cmd

def obligation_path(L):
    return Path(L) / 'state' / 'obligation.json'

def load_obligation(L):
    try:
        return json.loads(obligation_path(L).read_text())
    except Exception:
        return None

def save_obligation(L, ob):
    p = obligation_path(L)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not ob:
        if p.exists():
            p.unlink()
        return
    p.write_text(json.dumps(ob, indent=2))

def _safe_sibling(note):
    """A sibling that needs a human key is not a shot. Leave it blank."""
    sib = extract_sibling(note)
    if sib and _HUMAN_RE.search(sib):
        return ''
    return sib

def _low_floor(note):
    """A same-app medium, a rerun of a report, or 'operator submits' is not a ceiling."""
    n = (note or '').lower()
    return any(k in n for k in (
        'class=rerun', 'matches the report', 'operator submits', 'do not file',
        'same-app', 'same app', 'app-secret-only', 'app secret alone',
        'severity=medium', 'medium floor', 'below high',
    ))

def _reflect_kind(note):
    # A rerun of a known floor is a climb, not another verify of the same PoC.
    if _low_floor(note):
        return 'climb'
    # A closed/WAI family is a report, not another probe of the same death.
    if _CEILING_RE.search(note or '') and 'CONFIRM' not in (note or '').upper():
        return 'report'
    up = (note or '').upper()
    if 'CONFIRM' in up or 'CLASS=200' in up:
        return 'verify'
    if _BLOCK_RE.search(note or ''):
        return 'bypass'
    return 'bypass'

def sync_obligation(L, ev):
    """Write the debt the other seat must pay. Their later shot clears it."""
    t = (ev.get('type') or '')
    seat = ev.get('seat') or ''
    if seat in ('conductor', '') or seat.startswith('smoke'):
        return load_obligation(L)
    cell = ev.get('cell') or ''
    note = ev.get('note') or ''
    seq = int(ev.get('seq') or 0)
    cur = load_obligation(L)
    if cur and seat != cur.get('from') and seq > int(cur.get('seq') or 0):
        kind = cur.get('kind')
        different = normalize_cell(cell) != normalize_cell(cur.get('cell') or '')
        # A claim or a hypo is not a shot. Only a classed reflect / verdict clears.
        if kind == 'bypass' and t == 'REFLECT' and different:
            save_obligation(L, None)
            cur = None
        elif kind == 'verify' and t in ('VERDICT', 'REFLECT', 'RESULT'):
            save_obligation(L, None)
            cur = None
        elif kind == 'climb' and t == 'REFLECT' and different and not _low_floor(note) and not _BLOCK_RE.search(note or ''):
            save_obligation(L, None)
            cur = None
        elif kind == 'climb' and t == 'REFLECT':
            # A 401/404 or another rerun does not replace the climb.
            return cur
        elif kind == 'report' and t == 'REPORT-FIX':
            save_obligation(L, None)
            cur = None
        elif kind == 'report' and t == 'REPORT-OK' and not _low_floor(note):
            save_obligation(L, None)
            cur = None
    if t in ('REPORT-OK', 'RESULT', 'REFLECT') and _low_floor(note):
        ob = {'seq': seq, 'kind': 'climb', 'from': seat, 'cell': cell,
              'sibling': '', 'phase': 'ceiling', 'note': note[:300]}
        save_obligation(L, ob)
        return ob
    if t == 'KILL':
        ob = {'seq': seq, 'kind': 'bypass', 'from': seat, 'cell': cell,
              'sibling': _safe_sibling(note), 'phase': 'fire', 'note': note[:300]}
        save_obligation(L, ob)
        return ob
    if t == 'REFLECT':
        kind = _reflect_kind(note)
        ob = {'seq': seq, 'kind': kind, 'from': seat, 'cell': cell,
              'sibling': '' if kind == 'report' else _safe_sibling(note),
              'phase': 'draft' if kind == 'report' else 'fire',
              'note': note[:300]}
        save_obligation(L, ob)
        return ob
    if t == 'RESULT':
        ob = {'seq': seq, 'kind': 'verify', 'from': seat, 'cell': cell,
              'sibling': _safe_sibling(note), 'phase': 'fire', 'note': note[:300]}
        save_obligation(L, ob)
        return ob
    if t == 'REPORT':
        ob = {'seq': seq, 'kind': 'report', 'from': seat, 'cell': cell,
              'sibling': '', 'phase': 'check', 'note': note[:300]}
        save_obligation(L, ob)
        return ob
    return load_obligation(L)

def owe_view(L, seat):
    """What this seat must do before it may stop. None if it owes nothing."""
    ob = load_obligation(L)
    if not ob or seat == ob.get('from'):
        return None
    kind = ob.get('kind') or 'bypass'
    sib = ob.get('sibling') or ''
    if kind == 'bypass' and sib:
        do = (
            f"OWE bypass from {ob['from']} seq {ob['seq']}. "
            f"Claim and fire this different chain now: {sib}. "
            f"Do not restate their kill. Do not wait on a human key."
        )
    elif kind == 'bypass':
        do = (
            f"OWE bypass from {ob['from']} seq {ob['seq']}. "
            f"Their cell {ob.get('cell')} is dead (class in the note). "
            f"Claim a DIFFERENT METHOD /path AXIS and fire it this turn."
        )
    elif kind == 'climb':
        do = (
            f"OWE CLIMB from {ob['from']} seq {ob['seq']}. "
            f"The floor on {ob.get('cell')} is below High. Do not rerun that PoC. Do not draft it again. "
            f"Fire a different cell: another app's object, no app secret, a sign or transfer the owner key did not make, "
            f"or the sibling object that same check forgot. A 401 or 404 on the same app does not clear this. "
            f"A 200 object on the new cell does."
        )
    elif kind == 'verify':
        do = (
            f"OWE verify from {ob['from']} seq {ob['seq']}. "
            f"Rerun their command on {ob.get('cell')}. "
            f"Then climb one ceiling shot. Do not stop on a human-gated key. "
            f"If the floor is same-app or medium, this is a climb, not a report."
        )
    elif ob.get('phase') == 'draft':
        do = (
            f"OWE draft from {ob['from']} seq {ob['seq']}. "
            f"This family is closed ({ob.get('cell')}). "
            f"Write targets/<prog>/reports/ with one command, the expected output, "
            f"and what it proves. emit --type REPORT. Do not open a human-gated path."
        )
    else:
        do = (
            f"OWE report from {ob['from']} seq {ob['seq']}. "
            f"Rerun the PoC in the note. "
            f"emit --type REPORT-OK or REPORT-FIX. Do not submit."
        )
    return {'owe': True, 'do': do, **ob}

# ---- event log --------------------------------------------------------------
def _sidecar_seq(L):
    p = L / 'seq'
    try:
        return int(p.read_text().strip())
    except Exception:
        return 0

def _log_tail_seq(L):
    p = L / 'events.jsonl'
    if not p.exists():
        return 0
    try:
        with open(p, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            buf = b''
            chunk = 8192
            while size > 0 and len(buf) < 8192:
                pos = max(0, size - chunk)
                f.seek(pos)
                buf = f.read(size - pos) + buf
                size = pos
                if b'\n' in buf:
                    break
        for line in reversed(buf.decode('utf-8', 'replace').splitlines()):
            if not line.strip():
                continue
            try:
                return json.loads(line).get('seq', 0)
            except Exception:
                continue
    except Exception:
        pass
    return 0

def _last_seq(L):
    return max(_sidecar_seq(L), _log_tail_seq(L))

def _next_seq(L):
    return _last_seq(L) + 1

def _write_seq(L, n):
    (L / 'seq').write_text(str(n))

def _emit(L, seat, etype, cell, ref, note, extra=None):
    L.mkdir(parents=True, exist_ok=True)
    (L / 'lock').mkdir(exist_ok=True)
    (L / 'events.jsonl').touch()
    if not _acquire(L / 'lock', 'events', timeout=30.0, stale=30.0):
        raise RuntimeError('could not acquire events.lock (busy >30s)')
    try:
        seq = _next_seq(L)
        note = (note or '')[:360]
        ev = {
            'seq': seq, 'ts': ISO_TS(), 'seat': seat, 'type': etype,
            'cell': cell or '', 'ref': ref or '', 'note': note,
        }
        if extra:
            ev.update(extra)
        with open(L / 'events.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(ev, ensure_ascii=True) + '\n')
        _write_seq(L, seq)
        return ev
    finally:
        _release(L / 'lock', 'events')

def _read_lines(L, since=0, limit=None):
    p = L / 'events.jsonl'
    if not p.exists():
        return []
    out = []
    with open(p, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get('seq', 0) > since:
                out.append(ev)
    if limit:
        out = out[-limit:]
    return out

def wait_paths(paths, timeout):
    """Block until one path is written, or timeout. Linux inotify; else a short sleep.
    Typical wake is under 5ms. This is the board, not the model."""
    paths = [str(p) for p in paths if p]
    if timeout <= 0 or not paths:
        return False
    try:
        return _inotify_wait(paths, timeout)
    except Exception:
        time.sleep(min(timeout, 0.02))
        return False

def _inotify_wait(paths, timeout):
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
    fd = libc.inotify_init1(0x800)  # IN_NONBLOCK
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'inotify_init1')
    try:
        mask = 0x2 | 0x8 | 0x80 | 0x100  # MODIFY CLOSE_WRITE MOVED_TO CREATE
        watched = 0
        for p in paths:
            target = p if os.path.exists(p) else (os.path.dirname(p) or '.')
            if libc.inotify_add_watch(fd, target.encode(), mask) >= 0:
                watched += 1
        if not watched:
            raise OSError('no watch')
        ready, _, _ = select.select([fd], [], [], timeout)
        if ready:
            try:
                os.read(fd, 65536)
            except OSError:
                pass
            return True
        return False
    finally:
        os.close(fd)

def tail(L, since=0, limit=None, wait_sec=0.0):
    deadline = time.time() + wait_sec
    while True:
        out = _read_lines(L, since=since, limit=limit)
        if out:
            return out
        if time.time() >= deadline:
            return []
        time.sleep(0.2)

# ---- claims -----------------------------------------------------------------
def cell_hash(program, cell):
    return hashlib.sha256((program + '|' + normalize_cell(cell)).encode()).hexdigest()[:16]

def _claims_dir(L):
    return L / 'claims'

def _claim_path(L, program, cell):
    return _claims_dir(L) / cell_hash(program, cell)

def _list_claims(L):
    d = _claims_dir(L)
    if not d.exists():
        return []
    out = []
    for p in d.iterdir():
        if not p.is_dir():
            continue
        try:
            o = json.loads((p / 'OWNER').read_text())
        except Exception:
            continue
        o['_path'] = str(p)
        out.append(o)
    return out

def overlapping_claim(L, cell, exclude_seat=None):
    """Return OWNER dict of a conflicting claim held by another seat."""
    for o in _list_claims(L):
        other = o.get('cell') or ''
        if not other:
            continue
        if exclude_seat and o.get('seat') == exclude_seat:
            continue
        if cells_conflict(cell, other):
            return o
    return None

def claim(L, seat, program, cell, ttl=900):
    """Emit CLAIM and wait for conductor grant/deny via inbox. Returns verdict."""
    cell = normalize_cell(cell)
    ev = _emit(L, seat, 'CLAIM', cell, '', 'claim', {'ttl': ttl})
    want = ev['seq']
    t0 = ev['ts']
    deadline = time.time() + 4.0
    while time.time() < deadline:
        for m in inbox_read(L, seat, clear=False):
            if m.get('cell') != cell:
                continue
            if m.get('type') not in ('CLAIM-GRANTED', 'CLAIM-DENIED'):
                continue
            cs = m.get('claim_seq')
            if cs is not None:
                if cs != want:
                    continue
            elif m.get('ts', '') < t0:
                continue
            return m
        time.sleep(0.2)
    try:
        seats = load_config(L).get('seats', 1)
    except Exception:
        seats = 1
    if seats <= 1:
        if grant(L, program, cell, seat, ttl=ttl):
            return {'type': 'CLAIM-GRANTED', 'cell': cell, 'note': 'solo-self-grant',
                    'claim_seq': want}
    return {'type': 'INCONCLUSIVE', 'cell': cell, 'claim_seq': want}

def grant(L, program, cell, seat, ttl=900):
    """Atomically create the claim. False if too coarse, or the exact cell is already held."""
    cell = normalize_cell(cell)
    if cell_too_coarse(cell):
        return False
    p = _claim_path(L, program, cell)
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = claim_owner(L, program, cell)
    if existing and existing.get('seat') == seat:
        return renew(L, program, cell, seat, ttl=ttl)
    conflict = overlapping_claim(L, cell, exclude_seat=seat)
    if conflict:
        return False
    try:
        p.mkdir()
    except FileExistsError:
        return False
    (p / 'OWNER').write_text(json.dumps({
        'seat': seat, 'ts': time.time(), 'ttl': ttl, 'cell': cell,
    }))
    return True

def renew(L, program, cell, seat, ttl=900):
    cell = normalize_cell(cell)
    p = _claim_path(L, program, cell)
    try:
        owner = json.loads((p / 'OWNER').read_text())
    except Exception:
        return False
    if owner.get('seat') != seat:
        return False
    owner.update({'ts': time.time(), 'ttl': ttl, 'cell': cell})
    (p / 'OWNER').write_text(json.dumps(owner))
    return True

def release(L, program, cell, seat):
    cell = normalize_cell(cell)
    p = _claim_path(L, program, cell)
    try:
        owner = json.loads((p / 'OWNER').read_text())
    except Exception:
        return False
    if owner.get('seat') != seat:
        return False
    shutil.rmtree(p, ignore_errors=True)
    return True

def claim_owner(L, program, cell):
    p = _claim_path(L, program, cell)
    try:
        return json.loads((p / 'OWNER').read_text())
    except Exception:
        return None

# ---- inbox ------------------------------------------------------------------
def _inbox_path(L, seat):
    return L / 'inbox' / f'{seat}.jsonl'

def inbox_send(L, seat, msg):
    p = _inbox_path(L, seat)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'a', encoding='utf-8') as f:
        f.write(json.dumps({**msg, 'ts': ISO_TS()}, ensure_ascii=True) + '\n')

def inbox_read(L, seat, clear=False):
    p = _inbox_path(L, seat)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    if clear:
        p.unlink()
    return out

# ---- heartbeat --------------------------------------------------------------
def heartbeat(L, seat, wip=0, role=None):
    (L / 'hb').mkdir(parents=True, exist_ok=True)
    extra = {}
    if role:
        extra['role'] = role
    (L / 'hb' / f'{seat}.json').write_text(json.dumps(
        {'ts': time.time(), 'wip': wip, **extra}))

def _touch_hb(L, seat):
    try:
        heartbeat(L, seat)
    except Exception:
        pass

def alive_seats(L, dead_s=None):
    if dead_s is None:
        try:
            dead_s = float(load_config(L).get('hb_dead_s', 90))
        except Exception:
            dead_s = 90
    out = []
    d = L / 'hb'
    if not d.exists():
        return out
    for f in d.glob('*.json'):
        if hb_alive(L, f.stem, dead_s):
            out.append(f.stem)
    return out

def hb_alive(L, seat, dead_s=90):
    p = L / 'hb' / f'{seat}.json'
    try:
        ts = json.loads(p.read_text()).get('ts', 0)
    except Exception:
        return False
    return (time.time() - ts) < dead_s

# ---- global rate bucket -----------------------------------------------------
def is_mint_op(op_key):
    """Any --op that is not a read is a 60s mint channel.
    `--op read` stays a normal rate token (PROGRAM_68 2026-10-17).
    A custom key such as grok4-deposit-config-create is a mint: the seat
    asked for a named lock, and a silent rate-only grant let two creates
    through two seconds apart.
    """
    if not op_key:
        return False
    k = op_key.lower().replace('-', '_')
    if k in ('read', 'get', 'head', 'options', 'probe', 'recon', 'status'):
        return False
    return True

def token(L, op_key=None):
    (L / 'lock').mkdir(exist_ok=True)
    (L / 'bucket.json').touch()
    if not _acquire(L / 'lock', 'bucket', timeout=10.0, stale=10.0):
        return {'grant': False, 'wait_ms': 5000, 'why': 'bucket busy'}
    try:
        try:
            b = json.loads((L / 'bucket.json').read_text())
        except Exception:
            b = {}
        try:
            cfg = load_config(L)
            b.setdefault('rate_per_s', float(cfg.get('rate_per_s', 0.5)))
        except Exception:
            b.setdefault('rate_per_s', 0.5)
        b.setdefault('tokens', 1.0)
        b.setdefault('updated', time.time())
        b.setdefault('cool_until', 0.0)
        b.setdefault('mint_locks', {})
        now = time.time()
        if now < b.get('cool_until', 0.0):
            wait_ms = int((b['cool_until'] - now) * 1000)
            return {'grant': False, 'wait_ms': wait_ms, 'why': '429-cool'}
        cap = 1.0
        elapsed = now - b['updated']
        b['tokens'] = min(cap, b['tokens'] + elapsed * b['rate_per_s'])
        b['updated'] = now
        if is_mint_op(op_key):
            last = b['mint_locks'].get(op_key, 0)
            if now - last < 60.0:
                return {'grant': False, 'wait_ms': int((60.0 - (now - last)) * 1000),
                        'why': 'mint-lock'}
        if b['tokens'] >= 1.0:
            b['tokens'] -= 1.0
            if is_mint_op(op_key):
                b['mint_locks'][op_key] = now
            (L / 'bucket.json').write_text(json.dumps(b))
            return {'grant': True, 'wait_ms': 0, 'why': ''}
        wait_ms = int((1.0 - b['tokens']) / b['rate_per_s'] * 1000)
        (L / 'bucket.json').write_text(json.dumps(b))
        return {'grant': False, 'wait_ms': max(100, wait_ms), 'why': 'empty'}
    finally:
        _release(L / 'lock', 'bucket')

def token_wait(L, op_key=None, max_s=120.0):
    deadline = time.time() + max_s
    while True:
        j = token(L, op_key=op_key)
        if j.get('grant'):
            return j
        if time.time() >= deadline:
            return j
        time.sleep(max(0.05, j.get('wait_ms', 200) / 1000.0))

def storm(L):
    (L / 'lock').mkdir(exist_ok=True)
    if not _acquire(L / 'lock', 'bucket', timeout=10.0, stale=10.0):
        return
    try:
        try:
            b = json.loads((L / 'bucket.json').read_text())
        except Exception:
            b = {}
        b['tokens'] = 0.0
        b['cool_until'] = time.time() + 120.0
        b['rate_per_s'] = max(0.1, b.get('rate_per_s', 0.5) / 2)
        (L / 'bucket.json').write_text(json.dumps(b))
    finally:
        _release(L / 'lock', 'bucket')

def status_dict(L, seat):
    try:
        cfg = load_config(L)
    except Exception:
        cfg = {}
    hb = {}
    try:
        hb = json.loads((L / 'hb' / f'{seat}.json').read_text())
        hb_age = time.time() - hb.get('ts', 0)
    except Exception:
        hb_age = None
    bucket = {}
    try:
        bucket = json.loads((L / 'bucket.json').read_text())
    except Exception:
        pass
    inbox_n = 0
    try:
        p = _inbox_path(L, seat)
        if p.exists():
            inbox_n = sum(1 for line in p.read_text().splitlines() if line.strip())
    except Exception:
        pass
    claims = []
    for o in _list_claims(L):
        claims.append({
            'cell': o.get('cell', ''),
            'seat': o.get('seat', ''),
            'age_s': int(time.time() - o.get('ts', 0)),
            'ttl': o.get('ttl', 900),
        })
    return {
        'seat': seat,
        'program': cfg.get('program', ''),
        'seq': _last_seq(L),
        'hb_age_s': None if hb_age is None else round(hb_age, 1),
        'wip': hb.get('wip', 0),
        'inbox': inbox_n,
        'claims': claims,
        'rate_per_s': bucket.get('rate_per_s', cfg.get('rate_per_s', 0.5)),
        'cool_until': bucket.get('cool_until', 0),
    }

# ---- CLI --------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='seatlib')
    ap.add_argument('--lounge', default=None, help='lounge runtime dir (or env LOUNGE_DIR)')
    ap.add_argument('--seat', default=os.environ.get('SEAT_ID', 'grok-1'))
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('seat'); p.add_argument('--role', default='PROBER'); p.add_argument('--doctrine', default='')
    p = sub.add_parser('emit'); p.add_argument('--type', required=True); p.add_argument('--cell', default=''); p.add_argument('--ref', default=''); p.add_argument('--note', default=''); p.add_argument('--program', default='')
    p = sub.add_parser('tail'); p.add_argument('--since', type=int, default=0); p.add_argument('--wait', type=float, default=0.0); p.add_argument('--limit', type=int, default=None)
    p = sub.add_parser('claim'); p.add_argument('--cell', required=True); p.add_argument('--program', default=''); p.add_argument('--ttl', type=int, default=900)
    p = sub.add_parser('renew'); p.add_argument('--cell', required=True); p.add_argument('--program', default=''); p.add_argument('--ttl', type=int, default=900)
    p = sub.add_parser('release'); p.add_argument('--cell', required=True); p.add_argument('--program', default='')
    p = sub.add_parser('token'); p.add_argument('--op', default=None); p.add_argument('--wait', action='store_true', help='block until grant (cap 120s)')
    p.add_argument('--mint', action='store_true', help='force mint-lock even if --op looks like a read')
    p = sub.add_parser('inbox'); p.add_argument('--clear', action='store_true')
    p = sub.add_parser('hb'); p.add_argument('--wip', type=int, default=0); p.add_argument('--role', default=None)
    p = sub.add_parser('hb-loop'); p.add_argument('--interval', type=float, default=5.0); p.add_argument('--pidfile', default=None)
    p = sub.add_parser('storm')
    p = sub.add_parser('status')
    p = sub.add_parser('board')
    p = sub.add_parser('take')
    p = sub.add_parser('push'); p.add_argument('--cell', required=True); p.add_argument('--note', required=True)
    p = sub.add_parser('hypo'); p.add_argument('--cell', required=True); p.add_argument('--source', required=True); p.add_argument('--oracle', required=True); p.add_argument('--shot', required=True)
    p = sub.add_parser('reflect'); p.add_argument('--cell', required=True); p.add_argument('--klass', '--class', dest='klass', required=True); p.add_argument('--sibling', required=True)
    p = sub.add_parser('follow'); p.add_argument('--since', type=int, default=None); p.add_argument('--wait', type=float, default=2.0)
    p = sub.add_parser('next')
    p = sub.add_parser('say'); p.add_argument('--note', required=True); p.add_argument('--cell', default='')
    p = sub.add_parser('join'); p.add_argument('--program', required=True); p.add_argument('--role', default='PROBER')

    a = ap.parse_args()
    L = Path(a.lounge) if a.lounge else lounge_dir()

    # Read-only commands must not refresh a dead seat. hb-loop and shots do.
    if a.cmd not in ('hb-loop', 'next', 'board', 'follow', 'status', 'tail', 'inbox'):
        _touch_hb(L, a.seat)

    if a.cmd == 'seat':
        role = (a.role or 'PROBER').split('--', 1)[0]
        resume = hb_alive(L, a.seat)
        note = f'role={role} doctrine={a.doctrine}'
        if resume:
            note += ' resume=1'
        ev = _emit(L, a.seat, 'SEAT', '', '', note)
        print(json.dumps(ev))
    elif a.cmd == 'emit':
        ev = _emit(L, a.seat, a.type, a.cell, a.ref, a.note)
        print(json.dumps(ev))
    elif a.cmd == 'tail':
        for ev in tail(L, since=a.since, limit=a.limit, wait_sec=a.wait):
            print(json.dumps(ev))
    elif a.cmd == 'claim':
        cfg = load_config(L)
        verdict = claim(L, a.seat, cfg['program'], a.cell, ttl=a.ttl)
        print(json.dumps(verdict))
        sys.exit(0 if verdict.get('type') == 'CLAIM-GRANTED' else 1)
    elif a.cmd == 'renew':
        cfg = load_config(L)
        print(json.dumps({'ok': renew(L, cfg['program'], a.cell, a.seat, ttl=a.ttl)}))
    elif a.cmd == 'release':
        cfg = load_config(L)
        print(json.dumps({'ok': release(L, cfg['program'], a.cell, a.seat)}))
    elif a.cmd == 'token':
        op = a.op
        if a.mint and not is_mint_op(op):
            op = op or 'mint'
            if op not in MINT_OPS:
                # force mint-lock channel without renaming a read
                op = 'mint:' + op
        j = token_wait(L, op_key=op) if a.wait else token(L, op_key=op)
        print(json.dumps(j))
        sys.exit(0 if j.get('grant') else 1)
    elif a.cmd == 'inbox':
        for m in inbox_read(L, a.seat, clear=a.clear):
            print(json.dumps(m))
    elif a.cmd == 'hb':
        heartbeat(L, a.seat, wip=a.wip, role=a.role)
        print('ok')
    elif a.cmd == 'hb-loop':
        while True:
            if a.pidfile:
                try:
                    pid = int(Path(a.pidfile).read_text().strip())
                    os.kill(pid, 0)
                except Exception:
                    break
            heartbeat(L, a.seat)
            time.sleep(a.interval)
    elif a.cmd == 'storm':
        storm(L)
        print('ok')
    elif a.cmd == 'status':
        print(json.dumps(status_dict(L, a.seat), indent=2))
    elif a.cmd == 'next':
        view = owe_view(L, a.seat)
        if not view:
            print(json.dumps({'owe': False, 'seat': a.seat}))
            sys.exit(0)
        print(json.dumps(view))
        sys.exit(2)
    elif a.cmd == 'board':
        cfg = load_config(L)
        print(f"seq {_last_seq(L)}  program {cfg.get('program')}  seat {a.seat}")
        view = owe_view(L, a.seat)
        if view:
            print('OWE')
            print('  ' + view['do'])
            if view.get('sibling'):
                print(f"  claim --cell '{view['sibling']}'")
        print('CLAIMS')
        held = False
        for o in _list_claims(L):
            held = True
            print(f"  {o.get('seat'):10} {o.get('cell')}")
        if not held:
            print('  (none)')
        print('PEER')
        hot = {'HYPO', 'REFLECT', 'PUSH', 'ANOMALY', 'KILL', 'RESULT', 'CHAT', 'DENY'}
        n = 0
        for ev in reversed(_read_lines(L, since=0, limit=80)):
            if ev.get('seat') in (a.seat, 'conductor'):
                continue
            if ev.get('type') not in hot:
                continue
            print(f"  {ev.get('seq'):4} {ev.get('seat'):10} {ev.get('type'):8} {ev.get('cell','')[:50]} {(ev.get('note') or '')[:90]}")
            n += 1
            if n >= 12:
                break
        if n == 0:
            print('  (none)')
        sib = ''
        for ev in reversed(_read_lines(L, since=0, limit=80)):
            if ev.get('seat') in (a.seat, 'conductor'):
                continue
            if ev.get('type') == 'REFLECT':
                sib = _safe_sibling(ev.get('note') or '')
                if sib:
                    print(f'TAKE {sib}   (from {ev.get("seat")} seq {ev.get("seq")})')
                    break
        if not sib:
            print('TAKE (no claimable sibling on the board)')
    elif a.cmd == 'take':
        cfg = load_config(L)
        sib, src = '', None
        for ev in reversed(_read_lines(L, since=0, limit=80)):
            if ev.get('seat') in (a.seat, 'conductor'):
                continue
            if ev.get('type') != 'REFLECT':
                continue
            sib = _safe_sibling(ev.get('note') or '')
            if sib:
                src = ev
                break
        if not sib:
            print(json.dumps({'ok': False, 'error': 'no claimable sibling on the board'}))
            sys.exit(1)
        verdict = claim(L, a.seat, cfg['program'], sib)
        print(json.dumps({'ok': verdict.get('type') == 'CLAIM-GRANTED',
                          'from': src.get('seat') if src else '',
                          'cell': sib, 'verdict': verdict}))
        sys.exit(0 if verdict.get('type') == 'CLAIM-GRANTED' else 1)
    elif a.cmd == 'push':
        ev = _emit(L, a.seat, 'PUSH', a.cell, '', a.note)
        print(json.dumps(ev))
    elif a.cmd == 'hypo':
        note = f"source={a.source} | oracle={a.oracle} | shot={a.shot}"
        ev = _emit(L, a.seat, 'HYPO', a.cell, '', note)
        print(json.dumps(ev))
    elif a.cmd == 'reflect':
        sib = " ".join((a.sibling or "").split())
        if sib.upper() in ("-", "NONE", "CLOSED"):
            note = f"class={a.klass} | sibling="
            ev = _emit(L, a.seat, 'REFLECT', a.cell, '', note)
            print(json.dumps(ev))
            return
        head = sib.split(" ", 1)[0].upper() if sib else ""
        if head not in ("GET", "POST", "PUT", "PATCH", "DELETE") or len(sib.split()) < 3:
            print(json.dumps({
                "ok": False,
                "error": "sibling must be a claimable cell: METHOD /path AXIS",
                "example": "POST /graphql transferMethodConfigurations bankcard",
            }))
            sys.exit(1)
        note = f"class={a.klass} | sibling={normalize_cell(sib)}"
        ev = _emit(L, a.seat, 'REFLECT', a.cell, '', note)
        print(json.dumps(ev))
    elif a.cmd == 'say':
        ev = _emit(L, a.seat, 'CHAT', a.cell, '', a.note)
        print(json.dumps(ev))
    elif a.cmd == 'join':
        # Heartbeat watches the agent (parent of this tool shell), never sleep infinity.
        tool_ppid = os.getppid()
        agent = tool_ppid
        try:
            agent = int(open(f'/proc/{tool_ppid}/stat').read().split()[3])
        except Exception:
            pass
        pidfile = L / 'seats' / f'{a.seat}.pid'
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(agent))
        import subprocess as _sp
        _sp.Popen(
            [sys.executable, str(Path(__file__).resolve()), '--seat', a.seat,
             'hb-loop', '--interval', '5', '--pidfile', str(pidfile)],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            start_new_session=True,
        )
        cfg = load_config(L)
        # conductor
        cpid = L / 'conductor.pid'
        if not _conductor_alive(L):
            log = open(L / 'conductor.log', 'a')
            proc = _sp.Popen(
                [sys.executable, str(Path(__file__).resolve().parent / 'conductor.py'),
                 '--lounge', str(L)],
                stdout=log, stderr=log, start_new_session=True,
            )
            cpid.write_text(str(proc.pid))
        ev = _emit(L, a.seat, 'SEAT', '', '', f'role={a.role} doctrine=')
        home_state = Path.home() / '.lounge'
        home_state.mkdir(parents=True, exist_ok=True)
        (home_state / f'{a.seat}.program').write_text(a.program)
        (home_state / f'{a.seat}.role').write_text(a.role)
        inbox = _inbox_path(L, a.seat)
        if inbox.exists():
            inbox.unlink()
        try:
            (home_state / f'{a.seat}.{a.program}.seen').write_text(str(_last_seq(L)))
        except Exception:
            pass
        print(json.dumps({'ok': True, 'seat': a.seat, 'program': a.program,
                          'agent_pid': agent, 'conductor': cpid.read_text().strip(),
                          'event': ev}))
    elif a.cmd == 'follow':
        if a.since is None:
            try:
                cfg = load_config(L)
                prog = cfg.get('program') or ''
                seenp = Path.home() / '.lounge' / f'{a.seat}.{prog}.seen'
                if not seenp.exists():
                    seenp = Path.home() / '.lounge' / f'{a.seat}.seen'
                a.since = int(seenp.read_text().strip())
            except Exception:
                a.since = max(0, _last_seq(L) - 30)
        hot_types = {
            'ANOMALY', 'KILL', 'RESULT', 'PUSH', 'VERDICT', 'PREDICT',
            'CLAIM', 'HELP-WANTED', 'DENY', 'HYPO', 'REFLECT', 'CHAT',
            'REPORT', 'REPORT-OK', 'REPORT-FIX',
        }
        deadline = time.time() + a.wait
        shown = False
        view = owe_view(L, a.seat)
        if view:
            print(json.dumps({'type': 'OBLIGATION', **view}))
            shown = True
        while True:
            evs = _read_lines(L, since=a.since)
            hot = [e for e in evs if e.get('seat') not in (a.seat,) and e.get('type') in hot_types]
            if hot:
                for e in hot:
                    print(json.dumps(e))
                shown = True
                last = max(int(e.get('seq') or 0) for e in hot)
                try:
                    cfg = load_config(L)
                    prog = cfg.get('program') or ''
                    seenp = Path.home() / '.lounge' / f'{a.seat}.{prog}.seen'
                    seenp.parent.mkdir(parents=True, exist_ok=True)
                    seenp.write_text(str(last))
                except Exception:
                    pass
                break
            if time.time() >= deadline:
                break
            wait_paths(
                [L / 'events.jsonl', L / 'inbox' / f'{a.seat}.jsonl'],
                max(0.0, deadline - time.time()),
            )
        if not shown:
            print(json.dumps({'type': 'QUIET', 'since': a.since, 'wait': a.wait}))

if __name__ == '__main__':
    main()
