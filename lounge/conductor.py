#!/usr/bin/env python3
# conductor.py - PROJECT LOUNGE conductor daemon. Python 3 stdlib only.
# Reads events.jsonl, arbitrates claims, reaps leases, monitors heartbeats,
# owns the global rate cool + gates, rewrites feed.md every cycle.
#
# Run: LOUNGE_DIR=<program>/LOUNGE python3 conductor.py [--once]

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seatlib

SEAT = 'conductor'

ROLE_BY_INDEX = {1: 'RECON', 2: 'PROBER', 3: 'ANALYST'}

# Notes that imply a human-gated action -> auto-GATE. Unambiguous destructive
# terms only; submission/charge/OTP must be explicit GATE events (they are too
# common as substrings to auto-detect without false-freezing a seat mid-work).
PROD_WRITE_RE = re.compile(r'\b(prod write|destructive|mainnet write|deploy)\b', re.I)


def _load_state(L):
    try:
        return json.loads((L / 'state' / 'conductor.json').read_text())
    except Exception:
        return {}

def _save_state(L, s):
    (L / 'state').mkdir(parents=True, exist_ok=True)
    (L / 'state' / 'conductor.json').write_text(json.dumps(s))

def _emit(L, etype, cell, ref, note, extra=None):
    return seatlib._emit(L, SEAT, etype, cell, ref, note, extra=extra)

def _fan(L, exclude, msg):
    """Push a peer event into every other live seat's inbox. Real-time, not end-of-turn."""
    for sid in seatlib.alive_seats(L):
        if sid in (exclude, 'conductor'):
            continue
        seatlib.inbox_send(L, sid, msg)

def _rotate(L):
    p = L / 'events.jsonl'
    try:
        if p.exists() and p.stat().st_size >= 10_000_000:
            (L / 'archive').mkdir(exist_ok=True)
            dst = L / 'archive' / f'events-{int(time.time())}.jsonl'
            shutil.move(str(p), str(dst))
            _emit(L, 'ROTATE', '', '', f'archived to {dst.name}')
    except Exception:
        pass

def _read_new(L, since):
    out, bad = [], []
    p = L / 'events.jsonl'
    if not p.exists():
        return out, bad
    with open(p, encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except Exception:
                bad.append(line)
                continue
            if ev.get('seq', 0) > since:
                out.append(ev)
    return out, bad

def _quarantine(L, bad):
    if not bad:
        return
    (L / 'archive').mkdir(exist_ok=True)
    dst = L / 'archive' / f'corrupt-{int(time.time()*1000)}.jsonl'
    dst.write_text(''.join(bad))
    # remove the corrupt lines from the live log so we never re-quarantine them
    bad_set = set(b.strip() for b in bad)
    p = L / 'events.jsonl'
    if seatlib._acquire(L / 'lock', 'events', timeout=30.0, stale=30.0):
        try:
            keep = [l for l in p.read_text().splitlines(keepends=True)
                    if l.strip() not in bad_set]
            p.write_text(''.join(keep))
        finally:
            seatlib._release(L / 'lock', 'events')
    _emit(L, 'CORRUPT', '', '', f'{len(bad)} unparseable lines -> {dst.name}')

def _seat_num(seat):
    m = re.search(r'(\d+)$', seat)
    return int(m.group(1)) if m else 0

def _least_loaded(L, exclude, cell=None):
    best, bestw = None, 1 << 30
    holders = set()
    try:
        dead_s = float(seatlib.load_config(L).get('hb_dead_s', 90))
    except Exception:
        dead_s = 90.0
    if cell:
        for o in seatlib._list_claims(L):
            other = o.get('cell') or ''
            if other and seatlib.cells_conflict(cell, other):
                holders.add(o.get('seat'))
    for f in (L / 'hb').glob('*.json'):
        sid = f.stem
        if sid == exclude or sid in holders:
            continue
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        if time.time() - d.get('ts', 0) > dead_s:
            continue
        w = d.get('wip', 0)
        if w < bestw:
            best, bestw = sid, w
    return best

def _hb_ts(p):
    try:
        return json.loads(p.read_text()).get('ts', 0)
    except Exception:
        return 0

def _event_age(ts):
    """ISO ts from the log is UTC. Returns seconds ago, or None."""
    if not ts or len(ts) < 19:
        return None
    try:
        import datetime
        dt = datetime.datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S')
        return time.time() - dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    except Exception:
        return None

def _seat_wrote_recently(L, seat, within_s):
    """True if this seat has an event newer than within_s. Tail only."""
    p = L / 'events.jsonl'
    if not p.exists():
        return False
    try:
        with open(p, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            raw = f.read().decode('utf-8', 'replace')
    except Exception:
        return False
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get('seat') != seat:
            continue
        age = _event_age(ev.get('ts') or '')
        if age is None:
            return False
        return age < within_s
    return False

def _feed(L, cfg, gates):
    dead_s = float(cfg.get('hb_dead_s', 90))
    alive = sum(1 for f in (L / 'hb').glob('*.json') if time.time() - _hb_ts(f) < dead_s)
    lines = [f"# {cfg['program']} - LOUNGE feed",
             f"updated {seatlib.ISO_TS()} | seats alive {alive} | rate {cfg.get('rate_per_s',0.5)}/s"]
    if gates:
        lines.append('!! PENDING GATE: ' + ', '.join(f'{k}->{v}' for k, v in gates.items()))
    ob = seatlib.load_obligation(L)
    if ob:
        lines.append(
            f"!! OWE {ob.get('kind')} from {ob.get('from')} seq {ob.get('seq')} "
            f"cell {ob.get('cell','')[:70]} sibling {ob.get('sibling','')}"
        )
    lines.append('')
    for ev in seatlib._read_lines(L, since=0, limit=200):
        cell = ev.get('cell') or ''
        if len(cell) > 72:
            cell = cell[:22] + '…' + cell[-48:]
        lines.append(f"[{ev['seq']:>5}] {ev['ts']} {ev['seat']:<10} {ev['type']:<12} "
                     f"{cell:<72} {ev['note'][:72]}")
    (L / 'feed.md').write_text('\n'.join(lines) + '\n')

def cycle(L):
    cfg = seatlib.load_config(L)
    (L / 'lock').mkdir(exist_ok=True)
    (L / 'events.jsonl').touch()
    state = _load_state(L)
    last = state.get('seq', 0)
    gates = {k: v for k, v in state.get('gates', {}).items()}
    verifies = state.get('verifies', {})

    _rotate(L)
    events, bad = _read_new(L, last)
    if events:
        last = max(ev['seq'] for ev in events)
    _quarantine(L, bad)

    for ev in events:
        t, seat, cell, note = ev['type'], ev['seat'], ev['cell'], ev.get('note', '')
        # auto-GATE: any event implying a human-gated action
        if PROD_WRITE_RE.search(note) and t not in ('GATE', 'GATE-RESUMED'):
            gid = f'gate-{ev["seq"]}'
            gates[gid] = cell
            _emit(L, 'GATE', cell, '', f'{gid} frozen (prod/gated action by {seat})')

        if t == 'SEAT':
            if 'resume=1' in note:
                continue
            m = re.search(r'role=([A-Za-z]+)', note)
            role = m.group(1) if m else ROLE_BY_INDEX.get(_seat_num(seat), 'PROBER')
            seatlib.inbox_send(L, seat, {'type': 'ROLE', 'role': role})
            _emit(L, 'SEAT', '', '', f'{seat} joined as {role}')
        elif t == 'CLAIM':
            if seatlib.cell_too_coarse(cell):
                seatlib.inbox_send(L, seat, {'type': 'CLAIM-DENIED', 'cell': cell,
                                             'claim_seq': ev['seq'],
                                             'note': 'too coarse: METHOD path AXIS (sibling axes may run together)'})
                _emit(L, 'DENY', cell, '', f'{seat} denied; cell too coarse')
                continue
            if cell in gates.values():
                seatlib.inbox_send(L, seat, {'type': 'CLAIM-DENIED', 'cell': cell,
                                             'claim_seq': ev['seq'], 'note': 'GATE_PENDING'})
                _emit(L, 'DENY', cell, '', f'{seat} denied: gate pending')
                continue
            if seatlib.grant(L, cfg['program'], cell, seat, ttl=ev.get('ttl', 900)):
                seatlib.inbox_send(L, seat, {'type': 'CLAIM-GRANTED', 'cell': cell,
                                             'claim_seq': ev['seq']})
            else:
                owner = seatlib.claim_owner(L, cfg['program'], cell)
                overlap = seatlib.overlapping_claim(L, cell, exclude_seat=seat)
                who = owner or overlap or {}
                why = f'owned by {who.get("seat", "?")}'
                if overlap and overlap.get('cell') and overlap.get('cell') != cell:
                    why = f'overlap {overlap.get("cell")} owned by {overlap.get("seat")}'
                seatlib.inbox_send(L, seat, {'type': 'CLAIM-DENIED', 'cell': cell,
                                             'claim_seq': ev['seq'], 'note': why})
                _emit(L, 'DENY', cell, '', f'{seat} denied; {why}')
        elif t == 'RENEW':
            seatlib.renew(L, cfg['program'], cell, seat, ttl=ev.get('ttl', 900))
        elif t == 'RELEASE':
            seatlib.release(L, cfg['program'], cell, seat)
        elif t == 'ANOMALY':
            if cell and not seatlib.claim_owner(L, cfg['program'], cell):
                seatlib.grant(L, cfg['program'], cell, seat, ttl=3600)
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'ANOMALY class=' + note[:220] + ' — name a different axis and fire it this turn'})
        elif t == 'PUSH':
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat, 'note': note})
        elif t == 'CHAT':
            _fan(L, seat, {'type': 'CHAT', 'cell': cell, 'from': seat, 'note': note})
        elif t == 'HYPO':
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'HYPO ' + note[:300] + ' — attack a sibling this turn, or fire the shot if it is yours'})
        elif t == 'REFLECT':
            sib = seatlib.extract_sibling(note)
            take = f'TAKE {sib} — ' if sib else ''
            _fan(L, seat, {'type': 'PUSH', 'cell': sib or cell, 'from': seat,
                           'note': take + 'REFLECT ' + note[:240] + ' — if this is a block, fire one structural bypass now. If it confirms, rerun it and climb.'})
        elif t == 'KILL':
            kills = L.parent / 'STATE' / 'LOUNGE_KILLS.md'
            try:
                kills.parent.mkdir(parents=True, exist_ok=True)
                if not kills.exists():
                    kills.write_text('# LOUNGE KILLS — classed, one line per event\n\n')
                with open(kills, 'a', encoding='utf-8') as f:
                    f.write(f"- _by:lounge {ev['ts']} KILL {cell}: {note} (events.jsonl#seq={ev['seq']})\n")
            except Exception:
                pass
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'KILL is one axis. class=' + note[:180] + ' — name a different chain now (sibling route, other type, nested field, second path) and fire it'})
        elif t == 'VERIFY-ME':
            v = _emit(L, 'VERIFY-ME', cell, '', note)
            target = _least_loaded(L, exclude=seat, cell=cell)
            if target:
                verifies[str(v['seq'])] = seat
                seatlib.inbox_send(L, target, {'type': 'VERIFY-ME', 'cell': cell, 'note': note,
                                               'from': seat, 'vid': v['seq']})
            else:
                _emit(L, 'VERDICT', cell, '', 'INCONCLUSIVE no other seat')
        elif t == 'VERDICT':
            m = re.search(r'vid=(\d+)', note)
            if m and m.group(1) in verifies:
                origin = verifies.pop(m.group(1))
                seatlib.inbox_send(L, origin, {'type': 'VERDICT', 'cell': cell, 'note': note, 'from': seat})
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'VERDICT is not a close. ' + note[:200] + ' — falsify or escalate a different axis'})
        elif t == 'REPORT':
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'REPORT ' + note[:220] + ' — rerun the PoC. Answer REPORT-OK or REPORT-FIX with the failing line. Do not submit.'})
        elif t in ('REPORT-OK', 'REPORT-FIX'):
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': t + ' ' + note[:220] + ' — if FIX, repair and pass it back. If both OK, stop and wait for the operator.'})
        elif t == 'RESULT':
            skeptic = _least_loaded(L, exclude=seat, cell=cell)
            if skeptic:
                seatlib.inbox_send(L, skeptic, {'type': 'VERIFY-ME', 'cell': cell,
                                                'note': 'SKEPTIC review — try to break it, not rubber-stamp', 'from': seat})
            _fan(L, seat, {'type': 'PUSH', 'cell': cell, 'from': seat,
                           'note': 'RESULT floor=' + note[:160] + ' — both verify: rerun the command, climb ceiling, do not wait on a human key'})
        elif t == 'HELP-WANTED':
            tgt = _least_loaded(L, exclude=seat)
            if tgt:
                seatlib.inbox_send(L, tgt, {'type': 'HANDOFF', 'cell': cell, 'note': note, 'from': seat})
        elif t == 'HANDOFF':
            tgt = _least_loaded(L, exclude=seat)
            if tgt:
                seatlib.inbox_send(L, tgt, {'type': 'HANDOFF', 'cell': cell, 'note': note, 'from': seat})
        elif t == '429STORM':
            seatlib.storm(L)
            for f in (L / 'hb').glob('*.json'):
                seatlib.inbox_send(L, f.stem, {'type': 'WAIT', 'note': '429 storm: global cool >=120s'})
            _emit(L, 'WAIT', '', '', '429 storm: global cool 120s')
        elif t == 'GATE':
            gid = note or f'gate-{ev["seq"]}'
            gates[gid] = cell
            _emit(L, 'GATE', cell, '', f'{gid} frozen awaiting operator')
        seatlib.sync_obligation(L, ev)

    # resume gates whose gate_ok/<id> exists
    for gid in list(gates):
        if (L / 'gate_ok' / gid).exists():
            _emit(L, 'GATE-RESUMED', gates[gid], '', gid)
            del gates[gid]

    # reap expired claims (and orphan dirs with no OWNER).
    # A seat whose heartbeat is fresh is still thinking: renew, do not steal the cell.
    dead_s = float(cfg.get('hb_dead_s', 90))
    for p in (L / 'claims').glob('*'):
        try:
            owner = json.loads((p / 'OWNER').read_text())
        except Exception:
            try:
                if time.time() - p.stat().st_mtime > 900:
                    shutil.rmtree(p, ignore_errors=True)
                    _emit(L, 'RELEASE', '', '', 'lease-expired orphan claim')
            except Exception:
                pass
            continue
        if time.time() - owner.get('ts', 0) > owner.get('ttl', 900):
            sid = owner.get('seat') or ''
            hb = L / 'hb' / f'{sid}.json'
            if sid and hb.exists() and (time.time() - _hb_ts(hb)) < dead_s:
                owner['ts'] = time.time()
                try:
                    (p / 'OWNER').write_text(json.dumps(owner))
                except Exception:
                    pass
                continue
            shutil.rmtree(p, ignore_errors=True)
            _emit(L, 'RELEASE', '', '', f'lease-expired owner={owner.get("seat")}')

    # heartbeats -> SEAT-DOWN (default 90s; 45s killed seats during first-read think).
    # A seat that just wrote an event is alive even if the hb file lagged.
    for f in (L / 'hb').glob('*.json'):
        if time.time() - _hb_ts(f) > dead_s and not _seat_wrote_recently(L, f.stem, dead_s):
            sid = f.stem
            for p in (L / 'claims').glob('*'):
                try:
                    o = json.loads((p / 'OWNER').read_text())
                except Exception:
                    continue
                if o.get('seat') == sid:
                    shutil.rmtree(p, ignore_errors=True)
            _emit(L, 'SEAT-DOWN', '', '', f'{sid} dead (hb age >{int(dead_s)}s); claims released')
            try:
                f.unlink()
            except OSError:
                pass

    # include our own emissions in the resume cursor so we never re-process them
    last = seatlib._last_seq(L)
    fed = float(state.get('fed', 0) or 0)
    if events or (time.time() - fed > 2.0):
        _feed(L, cfg, gates)
        fed = time.time()
    _save_state(L, {'seq': last, 'gates': gates, 'verifies': verifies, 'fed': fed})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--lounge', default=None)
    a = ap.parse_args()
    L = Path(a.lounge) if a.lounge else seatlib.lounge_dir()
    if a.once:
        cycle(L)
        return
    while True:
        try:
            cycle(L)
        except Exception as e:
            print('conductor cycle error:', e, file=sys.stderr)
        # inotify on the log: peer PUSH lands in the same millisecond the event is written
        seatlib.wait_paths([L / 'events.jsonl'], 0.05)

if __name__ == '__main__':
    main()
