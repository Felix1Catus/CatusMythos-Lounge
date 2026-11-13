#!/usr/bin/env python3
"""
MYTHOS PostToolUse hook — MECHANICAL PROGRESS JOURNAL (Claude edition).

Fires after EVERY tool call. Appends ONE compact NDJSON line describing what just happened
to the relevant program's ~/targets/<prog>/STATE/JOURNAL.ndjson AND a global daily journal.

Why this exists: RESUME.md is written by the agent only when it remembers. If the session
dies mid-work-item (token exhaustion), the agent's last narrative save is stale. This hook
does NOT depend on the agent — it records every action to disk the instant it completes, so
a resuming session can reconstruct exactly where the dead one was and what it was doing.

Contract: fail-open (any error -> exit 0, never block a tool call), fast (<30ms, no tree walk),
never write to stdout (would pollute the tool result); errors are swallowed silently.
LOCATION: ~/.claude/mythos/journal.py   Reader: resume.sh   Intent head: STATE/CHECKPOINT.md
"""
import json, sys, os, re, datetime

def clip(s, n=150):
    return " ".join(str(s).split())[:n]

def main():
    try:
        d = json.loads(sys.stdin.read())
    except Exception:
        return  # unparseable -> allow silently

    tool = d.get("tool_name") or d.get("toolName") or (d.get("tool") or {}).get("name") or ""
    ti = d.get("tool_input") or d.get("toolInput") or {}
    tr = d.get("tool_response") or d.get("toolResponse") or d.get("result")
    if not isinstance(ti, dict):
        ti = {}

    # --- build a compact human summary of the action ---
    summary = ""
    if tool == "Bash":
        summary = clip(ti.get("command", ""))
    elif tool in ("Write", "Edit"):
        summary = f"{tool} {ti.get('path','') or ti.get('file_path','')}"
    elif tool == "Read":
        summary = f"Read {ti.get('path','') or ti.get('file_path','')}"
    elif tool in ("Grep", "Glob"):
        summary = clip(f"{tool} {ti.get('pattern','')} {ti.get('path','') or ti.get('glob','')}")
    elif tool in ("FetchURL", "WebFetch"):
        summary = clip(f"Fetch {ti.get('url','')}")
    elif tool == "WebSearch":
        summary = clip(f"Search {ti.get('query','')}")
    elif tool in ("Agent", "AgentSwarm", "Task"):
        summary = clip(f"{tool} {ti.get('description','') or ti.get('prompt','')}")
    else:
        summary = clip(ti.get("command", "") or ti.get("path", "") or ti.get("file_path", "") or tool)
    summary = summary.strip()
    if not summary or not tool:
        return

    # --- infer which program this action belongs to ---
    # 1) strongest signal: a targets/<prog>/ path anywhere in the RIGHT field per tool
    #    (a file op belongs to the program of the file it TOUCHES, not a path quoted in content)
    # 2) fallback for probing tools only: the active-target marker set via mtarget.sh
    if tool in ("Read", "Write", "Edit"):
        blob = str(ti.get("path", "") or ti.get("file_path", ""))
    elif tool == "Bash":
        blob = str(ti.get("command", ""))
    elif tool in ("Grep", "Glob"):
        blob = str(ti.get("path", "")) + " " + str(ti.get("glob", "") or ti.get("pattern", ""))
    elif tool in ("FetchURL", "WebFetch", "WebSearch"):
        blob = str(ti.get("url", "")) + " " + str(ti.get("query", ""))
    else:
        blob = json.dumps(ti)
    prog = ""
    m = re.search(r'targets/([A-Za-z0-9_.\-]+)/', blob)
    if m and m.group(1) not in ("_recon", "_cleanup", "misc"):
        prog = m.group(1)
    # active_target fallback applies ONLY to probing tools (live-host requests that carry no
    # local targets/ path). File ops route strictly by path — never guess their program, or
    # OS-meta edits under ~/.claude get misfiled to a stale active target.
    if not prog and tool in ("Bash", "FetchURL", "WebFetch", "WebSearch"):
        try:
            with open(os.path.expanduser("~/.claude/mythos/active_target")) as f:
                _parts = f.read().strip().split()
                prog = _parts[0] if _parts else ""
        except Exception:
            prog = ""

    # --- result class: did it work, and a gist of the output ---
    ok = None
    out = ""
    nbytes = None
    if isinstance(tr, dict):
        if tr.get("interrupted"):
            ok = False
        if tr.get("is_error") or tr.get("error"):
            ok = False
        so = tr.get("stdout")
        if so is None:
            so = tr.get("stderr")
        if so is None and isinstance(tr.get("content"), str):
            so = tr.get("content")
        if isinstance(so, str):
            nbytes = len(so)
            out = clip(so, 100)
    elif isinstance(tr, str):
        nbytes = len(tr)
        out = clip(tr, 100)

    ts = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    rec = {"ts": ts, "tool": tool, "sum": summary}
    if prog:
        rec["prog"] = prog
    if ok is not None:
        rec["ok"] = ok
    if out:
        rec["out"] = out
    if nbytes is not None:
        rec["bytes"] = nbytes
    line = json.dumps(rec, ensure_ascii=False)

    home = os.path.expanduser("~")
    # global daily journal (safety net — always written)
    try:
        gdir = os.path.join(home, ".claude", "mythos", "journal")
        os.makedirs(gdir, exist_ok=True)
        day = datetime.date.today().isoformat()
        with open(os.path.join(gdir, day + ".ndjson"), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    # per-program journal (the clean resume trail)
    if prog:
        try:
            sdir = os.path.join(home, "targets", prog, "STATE")
            os.makedirs(sdir, exist_ok=True)
            with open(os.path.join(sdir, "JOURNAL.ndjson"), "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
