#!/usr/bin/env python3
"""
check_common_sync.py - CatusMythos-Lounge dev tool (not part of the plugin
runtime, not wired into any hook).

Each pipeline skill vendors its own scripts/_common.py (see any one of them
for why: the README's "copy one skill directory out of the plugin" install
path means a cross-skill shared module would break). That's intentional
duplication, not a single source of truth -- but it only stays safe to
reason about if the functions EVERY skill's copy shares (log/success/warn)
actually stay identical across copies. This script is the guard against
that silently drifting: it diffs only the shared core, not each skill's own
additional helpers (http_request, cvss_round_up, vuln, error, ...), which
are expected to differ because different skills genuinely need different
things.

Run from the repo root: python scripts/check_common_sync.py
Exits 1 and prints every mismatch if any shared-core function diverges;
exits 0 (silently) if everything is in sync.
"""
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_SKILLS = [
    "recon-dominator",
    "webapp-exploit-hunter",
    "api-breaker",
    "cloud-pivot-finder",
    "attack-path-architect",
    "vuln-chain-composer",
]
# Only these are expected to be identical in every skill's _common.py --
# everything else each skill carries is allowed to be skill-specific.
SHARED_CORE = {"log", "success", "warn"}


def extract(path):
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in SHARED_CORE:
            out[node.name] = ast.dump(node)  # structural compare, ignores comments/whitespace
    return out


def main():
    by_skill = {}
    for skill in PIPELINE_SKILLS:
        path = REPO_ROOT / "skills" / skill / "scripts" / "_common.py"
        if not path.exists():
            print(f"[!] {skill}: no scripts/_common.py found")
            continue
        by_skill[skill] = extract(path)

    canonical_skill = next(iter(by_skill))
    canonical = by_skill[canonical_skill]
    mismatches = []

    for name in SHARED_CORE:
        if name not in canonical:
            mismatches.append(f"{canonical_skill} is missing shared-core function '{name}'")
            continue
        for skill, funcs in by_skill.items():
            if skill == canonical_skill:
                continue
            if name not in funcs:
                mismatches.append(f"{skill} is missing shared-core function '{name}'")
            elif funcs[name] != canonical[name]:
                mismatches.append(
                    f"'{name}' differs between {canonical_skill} and {skill} -- "
                    f"these must stay identical, or stop treating it as shared core"
                )

    if mismatches:
        print("[!!] _common.py shared-core drift detected:")
        for m in mismatches:
            print(f"  - {m}")
        sys.exit(1)

    print(f"[+] Shared core ({', '.join(sorted(SHARED_CORE))}) in sync across "
          f"{len(by_skill)} pipeline skills' _common.py files.")


if __name__ == "__main__":
    main()
