#!/usr/bin/env python3
"""
MYTHOS PreToolUse safety guard — Claude edition.

Fires before Bash tool calls (PreToolUse, matcher "Bash"). Dangerous kernel/disk
primitives -> BLOCK (exit 2 + stderr reason, per Kimi hook contract). Fail-OPEN on
any parse error. Logs matches to ~/.claude/mythos/safety.log.

Kimi hook payload (stdin): {"hook_event_name":"PreToolUse","session_id":...,"cwd":...,
                            "tool_name":"Bash","tool_input":{"command":"..."}}
Blocking: print reason to stderr, exit 2. (JSON hookSpecificOutput.permissionDecision
"deny" also works; stderr+exit2 keeps the reason in context for the model.)

Born from feedback_escape_harness_safety (modprobe/core_pattern left armed twice).
LOCATION: ~/.claude/mythos/pretooluse_guard.py
"""
import json, sys, os, re, datetime

LOG = os.path.expanduser("~/.claude/mythos/safety.log")

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return  # unparseable -> allow silently (fail-open)

    tool = data.get("tool_name") or data.get("toolName") or ""
    tin = data.get("tool_input") or data.get("toolInput") or {}
    if not isinstance(tin, dict):
        tin = {}
    cmd = tin.get("command") or ""

    if tool != "Bash" or not cmd:
        return

    matched = None
    simple = [
        (r"\bmodprobe\b",        "modprobe (kernel module load)"),
        (r"\binsmod\b",          "insmod (kernel module insert)"),
        (r"\brmmod\b",           "rmmod (kernel module remove)"),
        (r"\bmkfs",              "mkfs (filesystem create)"),
        (r"\bswapoff\b",         "swapoff (memory pressure weapon)"),
        (r"chown\s+-R\s+/",      "chown -R / (recursive)"),
        (r"chmod\s+-R\s+/",      "chmod -R / (recursive)"),
    ]
    for rx, label in simple:
        if re.search(rx, cmd):
            matched = label
            break

    # ── /proc/sys/kernel + core_pattern: block WRITES, allow READS ──────────────
    # Audit 2026-07-31 (unified): the old rules matched the bare path, so
    # `cat /proc/sys/kernel/unprivileged_userns_clone` — read-only recon on an
    # AUTHORISED container-escape target (PROGRAM_21/PROGRAM_100 work) — was blocked as
    # "tamper". CL-C bravery: reads are always in bounds; volume/mutation is what
    # is regulated. Only the write shapes are dangerous.
    if matched is None:
        KTARGET = r"(?:/proc/sys/kernel\S*|core_pattern)"
        writes = [
            (r">\s*" + KTARGET,                       "redirect-write to kernel sysctl"),
            (r"\btee\b[^|;]*" + KTARGET,              "tee into kernel sysctl"),
            (r"\bsysctl\b[^|;]*\s-w\b",               "sysctl -w (kernel write)"),
            (r"\bdd\b[^|;]*of=\s*" + KTARGET,         "dd onto kernel sysctl"),
        ]
        for rx, label in writes:
            if re.search(rx, cmd):
                matched = label + " — ESCAPE-HARNESS RULE: never leave it armed; restore+verify"
                break

    # fdisk: block partition mutation, allow the read-only listing (`fdisk -l`).
    if matched is None and re.search(r"\bfdisk\b", cmd) and not re.search(r"\bfdisk\b[^|;]*\s-{1,2}l\b", cmd):
        matched = "fdisk (disk partition mutation)"

    # ── pkill/killall self-or-sibling kill ─────────────────────────────────────
    # Recorded incident, TWICE: "pkill -f self-kill x2 — 2 shells, exit 144"
    # (CLAUDE_DIAGNOSIS C4e). Doctrine has said "comm-exact only" in three places and
    # it still happened, because notes do not load — guards do. TRAPS.md: "pkill
    # patterns can match the running agent". Also protects RESEARCHER's OTHER live agent
    # sessions (Claude/Kimi/Grok run concurrently on this box).
    if matched is None and re.search(r"\b(pkill|killall)\b", cmd):
        SIBLING = r"claude|kimi|grok|node|python3?|bash|sh\b|-f\s+\.|\*"
        if re.search(r"\bpkill\b[^|;]*\s-f\b", cmd) and re.search(SIBLING, cmd, re.I):
            matched = ("pkill -f with a self/sibling-matchable pattern — it can kill THIS agent "
                       "or RESEARCHER's other running sessions. Use probelib.kill_by_comm() or a "
                       "comm-exact match, and never a bare -f substring")
        elif re.search(r"\bkillall\b\s+(-\S+\s+)*(claude|node|python3?|bash)\b", cmd, re.I):
            matched = "killall on an interpreter/agent name — kills sibling agent sessions"
    if matched is None and re.search(r"\brm\b", cmd) and re.search(r"\s-[a-zA-Z]*[rR]", cmd) \
       and re.search(r"(?:^|\s)(?:/|/\*|~|~/\*)(?:\s|$)", cmd):
        matched = "rm -rf on / , /* or ~ (recursive destruction)"
    # dd is only dangerous when it writes to a DEVICE. The old rule fired on any
    # `dd if= of=`, blocking ordinary file->file copies; the device case is the rule
    # below. Caught by this guard's own --selftest, audit 2026-07-31 (unified).
    if matched is None and re.search(r"\bdd\b", cmd) and re.search(r"of=\s*/dev/", cmd):
        matched = "dd of=/dev/... (raw device write)"
    if matched is None and re.search(r"of=\s*/dev/", cmd):
        matched = "raw device write (of=/dev/)"
    if matched is None:
        return

    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(datetime.datetime.now().isoformat(timespec="seconds")
                    + "\tPreToolUse\t" + tool + "\tpattern=" + matched
                    + "\tcmd=" + cmd.replace("\n", "\\n") + "\n")
    except Exception:
        pass

    sys.stderr.write(
        "MYTHOS safety guard: dangerous primitive detected (" + matched + "). "
        "Confirm intentionally with the human, then re-run. Escape-harness rule: never leave "
        "modprobe/core_pattern armed; restore-and-verify after every run."
    )
    sys.exit(2)

def selftest():
    """Known-answer two-arm test (P03). BLOCK arm = must be caught; ALLOW arm = must pass.
    The ALLOW arm is the one that matters: a guard that blocks authorised read-only work
    is not 'safe', it is broken. Run: python3 pretooluse_guard.py --selftest"""
    import io, contextlib
    BLOCK = [
        "modprobe dummy",
        "echo '|/tmp/x' > /proc/sys/kernel/core_pattern",
        "sysctl -w kernel.core_pattern=/tmp/p",
        "echo 0 | tee /proc/sys/kernel/yama/ptrace_scope",
        "pkill -f claude",
        "pkill -f 'python3 battery.py'",
        "killall node",
        "mkfs.ext4 /dev/sdb1",
        "dd if=/dev/zero of=/dev/sda",
        "rm -rf /",
        "fdisk /dev/sda",
    ]
    ALLOW = [
        "cat /proc/sys/kernel/unprivileged_userns_clone",      # authorised escape recon
        "cat /proc/sys/kernel/core_pattern",                   # reading is not tampering
        "grep -r core_pattern ~/targets/PROGRAM_21/notes/",         # reading own notes
        "fdisk -l",                                            # read-only listing
        "curl -s https://example.com",
        "python3 ~/targets/_shared/probelib.py",
        "~/go/bin/httpx -silent -status-code",
        "pkill --signal TERM -x mybinary",                     # comm-exact, allowed
        "rm -rf /tmp/claude-1000/scratch/run1",                # scoped rm, allowed
        "dd if=in.bin of=out.bin bs=1",                        # file->file, not a device
    ]
    def verdict(c):
        buf = io.StringIO()
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": c}})
        old = sys.stdin
        sys.stdin = io.StringIO(payload)
        blocked = False
        try:
            with contextlib.redirect_stderr(buf):
                main()
        except SystemExit as e:
            blocked = (e.code == 2)
        finally:
            sys.stdin = old
        return blocked
    fails = []
    for c in BLOCK:
        if not verdict(c):
            fails.append("MISSED (should block): " + c)
    for c in ALLOW:
        if verdict(c):
            fails.append("FALSE POSITIVE (should allow): " + c)
    print("guard selftest: block-arm %d, allow-arm %d" % (len(BLOCK), len(ALLOW)))
    if fails:
        print("FAIL")
        for f in fails:
            print("  " + f)
        return 1
    print("PASS — both arms clean")
    return 0

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
