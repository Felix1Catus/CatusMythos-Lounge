#!/usr/bin/env python3
"""
MYTHOS CHECKPOINT writer — the INTENT head a raw command log can't capture. (Claude edition)

Writes/merges ~/targets/<prog>/STATE/CHECKPOINT.md : a tiny, fixed-schema block the agent
overwrites at the START of each work item. This is "where am I / where am I heading / what /
how" in a form a cold resume reads in 5 seconds. Merge semantics: unspecified fields keep
their prior value, so you can update just --next without retyping everything.

Usage:
  checkpoint.py <program> [--now "..."] [--goal "..."] [--approach "..."]
                          [--proven "..."] [--next "..."] [--blockers "..."] [--files "..."]
Fields:
  NOW      the work item I am on RIGHT NOW (one line)
  GOAL     where this is heading — the impact / win-condition I'm driving to
  APPROACH how — the method / tool / path I'm using
  PROVEN   the last PROBE-BACKED fact (with the id/status), not a hope
  NEXT     the exact next command or step (copy-pasteable if possible)
  BLOCKERS what's in the way / what I'm waiting on
  FILES    live artifact paths for this work item
LOCATION: ~/.claude/mythos/checkpoint.py
"""
import sys, os, re, datetime

FIELDS = ["NOW", "GOAL", "APPROACH", "PROVEN", "NEXT", "BLOCKERS", "FILES"]
FLAG = {"--now": "NOW", "--goal": "GOAL", "--approach": "APPROACH",
        "--proven": "PROVEN", "--next": "NEXT", "--blockers": "BLOCKERS", "--files": "FILES"}

def parse_existing(path):
    vals = {k: "" for k in FIELDS}
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r'^([A-Z]+)\s*:\s*(.*)$', line.rstrip("\n"))
                if m and m.group(1) in vals:
                    vals[m.group(1)] = m.group(2).strip()
    except FileNotFoundError:
        pass
    return vals

def usage():
    sys.stderr.write("usage: checkpoint.py <program> [--now ...] [--goal ...] "
                     "[--approach ...] [--proven ...] [--next ...] [--blockers ...] [--files ...]\n")
    sys.stderr.write("  -h/--help : show this help (never touches disk)\n")

def main():
    # Handle -h/--help BEFORE treating anything as a program name.
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        usage()
        sys.exit(0 if "-h" in sys.argv or "--help" in sys.argv else 2)
    prog = sys.argv[1]
    # Reject a flag-like program name outright — prevents junk dirs like ~/targets/--help/.
    if prog.startswith("-"):
        sys.stderr.write(f"error: invalid program name '{prog}'\n")
        usage()
        sys.exit(2)
    sdir = os.path.expanduser(f"~/targets/{prog}/STATE")
    os.makedirs(sdir, exist_ok=True)
    path = os.path.join(sdir, "CHECKPOINT.md")

    vals = parse_existing(path)
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in FLAG and i + 1 < len(args):
            vals[FLAG[a]] = args[i + 1].strip()
            i += 2
        else:
            i += 1

    ts = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    lines = [
        f"# ⚡ CHECKPOINT — {prog}   (overwrite at the START of each work item)",
        f"_updated: {ts}_",
        "> The intent head for warm-boot. Raw action trail = STATE/JOURNAL.ndjson (auto). "
        "Narrative = STATE/RESUME.md. If these disagree, trust the JOURNAL + a fresh probe.",
        "",
    ]
    labels = {
        "NOW": "NOW     ", "GOAL": "GOAL    ", "APPROACH": "APPROACH",
        "PROVEN": "PROVEN  ", "NEXT": "NEXT    ", "BLOCKERS": "BLOCKERS", "FILES": "FILES   ",
    }
    for k in FIELDS:
        lines.append(f"{labels[k]}: {vals[k]}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    sys.stderr.write(f"checkpoint written: {path}\n")

if __name__ == "__main__":
    main()
