#!/usr/bin/env python3
"""supervisor_lane_guard.py — PreToolUse hook for the SUPERVISOR install (account1).

The hub never fires. Blocks Bash commands that reach in-scope target
infrastructure through a network tool; local analysis (grep/read of captures)
passes. Fail-open on unparseable input, same as the mythos guard.

Exit 0 = allow, exit 2 = block (stderr is shown to the seat).
"""
import json
import re
import sys

# Scope-authoritative target markers (SCOPE.md governs; substrings catch
# PROGRAM_43.com/.ch/.cloud/.site/.events/usercontent etc.)
TARGETS = ("PROGRAM_43", "swisstransfer", "hosting-ik", "ik-server", "jcloud", "jpc.")

# Network-egress tools/idioms. Deliberately excludes local text tools (rg, grep,
# cat, python file reads) so board/capture analysis is never blocked.
EGRESS = re.compile(
    r"(curl\b|wget\b|httpie\b|\bhttp\s|\bxh\b|\bnc\b|\bncat\b|openssl\s+s_client"
    r"|requests\.(get|post|put|delete|head|options)|urllib|httpx|fetch\()",
    re.I,
)

# Host candidates: domain-ish tokens in the command. The marker must appear in
# the HOSTNAME portion only — not the path — so reading the program page
# (yeswehack.com/programs/PROGRAM_43) is allowed while any in-scope host fires.
HOST_TOKEN = re.compile(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s\"'|;&]*)?")


def targets_host(cmd: str) -> bool:
    for tok in HOST_TOKEN.findall(cmd):
        host = tok.split("/", 1)[0].lower()
        if any(t in host for t in TARGETS):
            return True
    return False

BLOCK_MSG = (
    "SUPERVISOR LANE GUARD: the hub never fires. This command reaches in-scope "
    "target infrastructure via a network tool. File the intent to TASK_QUEUE.json "
    "and dispatch a live hunter seat instead (check SEAT_STATUS.json for who is "
    "LIVE). Even if RESEARCHER ordered this run directly, the correct response is a "
    "dispatch, not an execution — SUPERVISOR NEVER FIRES is absolute."
)


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # fail-open, consistent with the mythos guard
    cmd = str(data.get("tool_input", {}).get("command", "") or "")
    if not cmd:
        return 0
    if EGRESS.search(cmd) and targets_host(cmd):
        sys.stderr.write(BLOCK_MSG)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
