#!/usr/bin/env python3
"""Verify documented skill script paths and long CLI options against --help."""

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


COMMAND_START = re.compile(r"^\s*python(?:3)?\s+scripts/([A-Za-z0-9_.-]+\.py)(.*)$")
LONG_OPTION = re.compile(r"--[A-Za-z][A-Za-z0-9-]*")


def documented_commands(skill_dir):
    """Yield (script name, options, source line) for Python script examples."""
    doc_path = skill_dir / "SKILL.md"
    lines = doc_path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        match = COMMAND_START.match(lines[index])
        if not match:
            index += 1
            continue
        script_name, tail = match.groups()
        command = tail
        source_line = index + 1
        while command.rstrip().endswith("\\") and index + 1 < len(lines):
            command = command.rstrip()[:-1] + " " + lines[index + 1].strip()
            index += 1
        options = set(LONG_OPTION.findall(command)) - {"--help"}
        yield script_name, options, source_line
        index += 1


def check_skill_docs(skills_root):
    skills_root = Path(skills_root)
    skill_docs = sorted(skills_root.glob("*/SKILL.md"))
    references = 0
    required = defaultdict(list)
    failures = []

    for doc_path in skill_docs:
        skill_dir = doc_path.parent
        for script_name, options, line in documented_commands(skill_dir):
            references += 1
            script_path = skill_dir / "scripts" / script_name
            if not script_path.is_file():
                failures.append("{}:{} references missing scripts/{}".format(doc_path, line, script_name))
                continue
            entry = required[script_path]
            entry.append((doc_path, line, options))

    for script_path, entries in required.items():
        result = subprocess.run(
            [sys.executable, str(script_path), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip().splitlines()
            failures.append("{} --help failed: {}".format(script_path, detail[-1] if detail else "unknown error"))
            continue
        declared = set(LONG_OPTION.findall(result.stdout + "\n" + result.stderr))
        for doc_path, line, options in entries:
            for option in sorted(options - declared):
                failures.append("{}:{} uses unsupported option {} for {}".format(doc_path, line, option, script_path.name))

    return len(skill_docs), references, len(required), failures


def main():
    repo_root = Path(__file__).resolve().parents[1]
    skills_root = repo_root / "skills"
    try:
        skill_count, reference_count, script_count, failures = check_skill_docs(skills_root)
    except (OSError, subprocess.SubprocessError) as exc:
        print("[!!] Skill CLI documentation check failed: {}".format(exc))
        return 1
    if failures:
        print("[!!] Skill command examples are out of sync:")
        for failure in failures:
            print("  - " + failure)
        return 1
    print("[+] Checked {} skill docs, {} command references, and {} distinct CLIs.".format(
        skill_count, reference_count, script_count
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
