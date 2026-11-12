#!/usr/bin/env python3
"""Live channel between lounge seats.

UserPromptSubmit and Stop both run this. A role word (prober, analyst, recon,
skeptic) typed into an already-open chat makes that process a seat and waits.
The next message that names a program tells it to join. After that, every
prompt and every stop receives the other seats' HYPO / REFLECT / PUSH /
ANOMALY / KILL / RESULT since this seat last looked. Stop exits 2 when there
is something to answer, so the turn does not end on a silent solo hunt.
"""
import json
import os
import sys
from pathlib import Path

HOME = Path.home()
STATE = HOME / ".lounge"
TOOLKIT = HOME / "targets" / "_shared" / "lounge"
HOT = {"HYPO", "REFLECT", "PUSH", "ANOMALY", "KILL", "RESULT", "CHAT", "REPORT", "REPORT-OK", "REPORT-FIX"}
ROLES = {"recon": "RECON", "prober": "PROBER", "analyst": "ANALYST", "skeptic": "SKEPTIC"}


def lounge_session():
    """True only in a go.sh / seat_launcher process. A leftover ~/.lounge/*.role
    must not hijack a solo grok/claude that typed a program name."""
    return os.environ.get("LOUNGE_JOINED") == "1" or bool(os.environ.get("LOUNGE_SEAT"))


def seat_name():
    blob = " ".join([
        os.environ.get("GROK_HOME", ""),
        os.environ.get("CLAUDE_CONFIG_DIR", ""),
        os.environ.get("LOUNGE_SEAT", ""),
    ])
    order = (
        ("claude-deepseek", "dsclaude"),
        ("claude-account2", "claude2"),
        ("claude-account3", "claude3"),
        (".grok4", "grok4"),
        (".grok3", "grok3"),
        (".grok2", "grok2"),
        (".grok", "grok"),
        (".claude", "claude"),
    )
    for needle, name in order:
        if needle in blob:
            return name
    return os.environ.get("SEAT_ID") or "grok"


def read_input():
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {"prompt": raw}


def prompt_text(d):
    p = (d.get("prompt") or d.get("user_prompt") or d.get("text")
         or d.get("message") or d.get("content") or "")
    if not isinstance(p, str):
        p = str(p)
    return " ".join(p.split())


def programs():
    root = HOME / "targets"
    out = []
    if not root.is_dir():
        return out
    for p in root.iterdir():
        if (p / "LOUNGE" / "lounge.json").is_file():
            out.append(p.name)
    return out


def role_path(seat):
    return STATE / f"{seat}.role"


def seen_path(seat, prog=None):
    if prog:
        return STATE / f"{seat}.{prog}.seen"
    return STATE / f"{seat}.seen"


def prog_path(seat):
    return STATE / f"{seat}.program"


def load_role(seat):
    try:
        return role_path(seat).read_text().strip()
    except Exception:
        return ""


def load_prog(seat):
    # Only the process seat_launcher marked. A leftover LOUNGE_DIR in some
    # other grok must not reopen its turn every time a peer reflects.
    if os.environ.get("LOUNGE_JOINED") != "1":
        return ""
    env = os.environ.get("LOUNGE_DIR", "")
    if env:
        return Path(env).parent.name
    try:
        return prog_path(seat).read_text().strip()
    except Exception:
        return ""


def load_seen(seat, prog=None):
    for p in (seen_path(seat, prog), seen_path(seat)):
        try:
            return int(p.read_text().strip())
        except Exception:
            continue
    return 0


def save_seen(seat, n, prog=None):
    STATE.mkdir(parents=True, exist_ok=True)
    seen_path(seat, prog).write_text(str(n))


def lounge_dir(prog):
    return HOME / "targets" / prog / "LOUNGE"


def peer_events(seat, prog):
    log = lounge_dir(prog) / "events.jsonl"
    since = load_seen(seat, prog)
    if not log.is_file():
        return [], since
    out = []
    last = since
    for line in log.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        seq = int(ev.get("seq") or 0)
        if seq > last:
            last = seq
        if seq <= since:
            continue
        who = ev.get("seat") or ""
        if who in (seat, "conductor", "") or who.startswith(("smoke", "audit")):
            continue
        if ev.get("type") not in HOT:
            continue
        out.append(ev)
    return out, last


def fmt(evs):
    lines = []
    for ev in evs[-8:]:
        note = (ev.get("note") or "").replace("\n", " ")[:220]
        lines.append(
            f"LIVE {ev.get('seat')} {ev.get('type')} {ev.get('cell','')} — {note}"
        )
    return "\n".join(lines)


def say(text):
    print(text)
    sys.stdout.flush()


def cmd_prompt(d):
    seat = seat_name()
    text = prompt_text(d)
    low = text.lower().strip()
    STATE.mkdir(parents=True, exist_ok=True)

    if low in ROLES and len(text) < 40:
        if not lounge_session():
            return 0
        role_path(seat).write_text(ROLES[low])
        try:
            prog_path(seat).unlink()
        except Exception:
            pass
        say(
            f"LOUNGE: you are seat {seat}, role {ROLES[low]}. "
            "No target is loaded. Do not search the disk. Do not open ~/targets. "
            "Do not run probelib. Do not read STATE, memory, or a checkpoint. "
            "Wait. The operator will name the program."
        )
        return 0

    role = os.environ.get("LOUNGE_ROLE") or load_role(seat)
    named = ""
    for name in programs():
        if name.lower() in low.split() or f"{name.lower()} is the target" in low or f"target is {name.lower()}" in low:
            named = name
            break
    if role and named:
        if not lounge_session():
            return 0
        prog_path(seat).write_text(named)
        L = lounge_dir(named)
        say(
            f"LOUNGE: operator named {named}. You are {seat} {role}. "
            "Join now, before any other read, with this and nothing else first:\n"
            f"  export LOUNGE_DIR={L} SEAT_ID={seat}\n"
            f"  python3 {TOOLKIT}/seatlib.py --seat {seat} join --program {named} --role {role}\n"
            f"  python3 {TOOLKIT}/seatlib.py --seat {seat} follow --wait 2\n"
            f"  python3 {TOOLKIT}/seatlib.py --seat {seat} board\n"
            f"  python3 {TOOLKIT}/seatlib.py --seat {seat} take\n"
            "Do not use sleep infinity. Do not hunt until follow returns. "
            "Then GROUND, hypo, one shot, reflect. A LIVE line from another seat "
            "is your next action: answer it with say, reflect, or the sibling shot."
        )
        return 0

    prog = load_prog(seat)
    if not prog:
        return 0
    try:
        evs, last = peer_events(seat, prog)
    except Exception:
        return 0
    owed = _owe_text(seat, prog)
    if not evs:
        if owed:
            say("LOUNGE OWE. This is your shot before anything else.\n" + owed +
                "\npython3 ~/targets/_shared/lounge/seatlib.py next")
        return 0
    save_seen(seat, last, prog)
    say(
        (owed + "\n" if owed else "")
        + f"LOUNGE LIVE on {prog}. Answer before your own next probe. "
        "A KILL or 4xx means name a different chain and fire it. "
        "A confirm means rerun it and climb. Do not stop on a human-gated key.\n"
        + fmt(evs)
    )
    return 0


def _owe_text(seat, prog):
    try:
        import seatlib
        view = seatlib.owe_view(lounge_dir(prog), seat)
    except Exception:
        return ''
    if not view:
        return ''
    return view.get('do') or ''


def cmd_stop():
    seat = seat_name()
    prog = load_prog(seat)
    if not prog:
        return 0
    owed = _owe_text(seat, prog)
    if owed:
        print(
            "LOUNGE OWE. Do not end this turn.\n" + owed + "\n"
            "python3 ~/targets/_shared/lounge/seatlib.py next",
            file=sys.stderr,
        )
        return 2
    try:
        evs, last = peer_events(seat, prog)
    except Exception:
        return 0
    # CHAT alone must not reopen the turn or the two seats ping-pong.
    structural = [e for e in evs if e.get("type") != "CHAT"]
    if not structural:
        return 0
    save_seen(seat, last, prog)
    print(
        f"LOUNGE LIVE on {prog}. Do not end this turn. A peer moved. "
        "KILL or 4xx: push a different chain and fire it. "
        "Confirm: rerun and climb. Report: rerun the PoC. "
        "Do not wait on a human key. Then follow once.\n"
        + fmt(structural),
        file=sys.stderr,
    )
    return 2


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "prompt"
    d = read_input()
    if mode == "stop":
        sys.exit(cmd_stop())
    sys.exit(cmd_prompt(d))


if __name__ == "__main__":
    main()
