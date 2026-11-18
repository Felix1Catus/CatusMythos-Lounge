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
that silently drifting: it checks the logging functions in every pipeline
skill and the scoped HTTP redirect helpers in the five network skills. It
does not compare skill-specific response wrappers, tuple shapes, limits, or
helpers such as cvss_round_up, vuln, and error.

Run from the repo root: python3 scripts/check_common_sync.py
Exits 1 and prints every mismatch if any shared helper diverges;
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
NETWORK_SKILLS = [
    "recon-dominator",
    "webapp-exploit-hunter",
    "api-breaker",
    "cloud-pivot-finder",
    "attack-path-architect",
]
SHARED_NETWORK_CORE = {
    "_http_origin",
    "same_origin_url",
    "SameOriginRedirectHandler",
    "_reserve_campaign_request",
    "scoped_urlopen",
}


def extract(path):
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in SHARED_CORE.union(SHARED_NETWORK_CORE):
            out[node.name] = ast.dump(node)  # structural compare, ignores comments/whitespace
    return out


def main():
    by_skill = {}
    mismatches = []
    for skill in PIPELINE_SKILLS:
        path = REPO_ROOT / "skills" / skill / "scripts" / "_common.py"
        if not path.exists():
            message = f"{skill}: no scripts/_common.py found"
            print(f"[!!] {message}")
            mismatches.append(message)
            continue
        by_skill[skill] = extract(path)

    def compare(skills, names, label):
        present = [skill for skill in skills if skill in by_skill]
        if not present:
            return
        canonical_skill = present[0]
        canonical = by_skill[canonical_skill]
        for name in names:
            if name not in canonical:
                mismatches.append(f"{canonical_skill} is missing {label} '{name}'")
                continue
            for skill in present[1:]:
                funcs = by_skill[skill]
                if name not in funcs:
                    mismatches.append(f"{skill} is missing {label} '{name}'")
                elif funcs[name] != canonical[name]:
                    mismatches.append(
                        f"'{name}' differs between {canonical_skill} and {skill} -- "
                        f"these must stay identical, or stop treating it as shared core"
                    )

    compare(PIPELINE_SKILLS, SHARED_CORE, "shared-core definition")
    compare(NETWORK_SKILLS, SHARED_NETWORK_CORE, "shared network definition")

    if mismatches:
        print("[!!] _common.py shared-core drift detected:")
        for m in mismatches:
            print(f"  - {m}")
        sys.exit(1)

    print(f"[+] Shared logging core is in sync across {len(by_skill)} pipeline skills; "
          f"scoped HTTP redirect helpers are in sync across {len(NETWORK_SKILLS)} network skills.")


if __name__ == "__main__":
    main()
