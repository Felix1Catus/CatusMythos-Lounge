#!/usr/bin/env python3
"""
CatusMythos-Lounge setup bootstrap.

Wired to the SessionStart hook (.claude-plugin/hooks.json) so the plugin's
optional Python dependencies (requirements.txt) are installed automatically
the first time a session starts after install, without re-running pip on
every single session. It also best-effort installs the Go-based recon
tools the pipeline's own scripts already know how to use when present
(subfinder, httpx, puredns, naabu -- all user-scoped, no sudo needed), and
reports (never silently auto-installs, since these usually need sudo/a
system package manager) anything else that's missing.

Safe to run by hand too: `python scripts/bootstrap.py` from the plugin root,
or `python "${CLAUDE_PLUGIN_ROOT}/scripts/bootstrap.py"` from anywhere.

Always exits 0 -- a SessionStart hook failing should never block a session
over an optional dependency; everything here is best-effort and reported,
not required for the core Felix1Catus pipeline, which is stdlib-only.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Go-based CLI tools the pipeline's own scripts (passive_recon.py,
# active_recon.py, port_scanner.py) already check for with shutil.which /
# try-except and fall back to a built-in method when absent -- installing
# them is a pure speed/coverage upgrade, never required.
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
}

# System-level tools used by one or more skills (nmap by recon-dominator's
# port_scanner.py as a fallback note, dig/whois by recon scripts, perl/yara
# CLI/tshark/binwalk by the respective domain skills' documented workflows).
# These typically need a system package manager (apt/brew/choco), which
# usually needs elevated privileges -- bootstrap reports what's missing and
# the right command for the platform, it does not run sudo on anyone's
# behalf.
SYSTEM_TOOLS = {
    "nmap": {
        "apt": "sudo apt-get install -y nmap",
        "brew": "brew install nmap",
        "choco": "choco install nmap",
    },
    "dig": {
        "apt": "sudo apt-get install -y dnsutils",
        "brew": "brew install bind",
        "choco": "choco install bind-toolsonly",
    },
    "whois": {
        "apt": "sudo apt-get install -y whois",
        "brew": "brew install whois",
        "choco": "choco install whois",
    },
    "perl": {
        "apt": "sudo apt-get install -y perl",
        "brew": "brew install perl",
        "choco": "choco install strawberryperl",
    },
}


def log(msg):
    print(f"[catusmythos-lounge setup] {msg}", flush=True)


def requirements_hash(req_path: Path) -> str:
    try:
        return hashlib.sha256(req_path.read_bytes()).hexdigest()
    except OSError:
        return ""


def load_marker(marker_path: Path) -> dict:
    try:
        return json.loads(marker_path.read_text())
    except Exception:
        return {}


def save_marker(marker_path: Path, data: dict) -> None:
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(data, indent=2))
    except OSError as e:
        log(f"warning: could not write setup marker ({e}); will re-check next session")


def pip_install(requirements: Path, prior_results: dict) -> dict:
    """Install requirements.txt one line at a time so a single package that
    needs a missing system compiler (yara-python on a box with no C
    toolchain is the realistic case) doesn't abort every OTHER package in
    the file, and so a package that can genuinely never build here (same
    case) doesn't get hammered with a fresh pip subprocess every single
    session forever -- only the ones NOT already marked `ok` last time
    against this same requirements.txt are retried.

    Returns {pkg_name: True|False} for every package in requirements.txt.
    """
    try:
        lines = []
        for raw in requirements.read_text().splitlines():
            # Strip a trailing inline comment (every line in this repo's
            # requirements.txt has one noting which skill needs it) -- pip
            # itself handles "pkg>=1.0  # comment" fine when reading the
            # whole FILE via `-r requirements.txt`, but this installs one
            # spec at a time as its own argv entry, so the comment has to
            # come off here or it becomes part of the "package" string and
            # every single install fails.
            line = raw.split("#", 1)[0].strip()
            if line:
                lines.append(line)
    except OSError as e:
        log(f"could not read {requirements}: {e}")
        return dict(prior_results)

    results = dict(prior_results)
    for spec in lines:
        pkg_name = spec.split(">=")[0].split("==")[0].strip()
        if results.get(pkg_name) is True:
            continue  # already confirmed installed against this exact requirements.txt
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", spec],
                capture_output=True, text=True, timeout=180,
            )
        except subprocess.TimeoutExpired:
            log(f"  [TIMEOUT] {pkg_name} (180s) -- will retry next session")
            results[pkg_name] = False
            continue
        if result.returncode == 0:
            log(f"  [OK] {pkg_name}")
            results[pkg_name] = True
        else:
            log(f"  [SKIP] {pkg_name} -- pip failed, that skill's own guarded import will explain this "
                f"if you use it ({_pip_error_summary(result.stderr)})")
            results[pkg_name] = False
    return results


def _pip_error_summary(stderr: str) -> str:
    """Pick the line that actually explains a pip failure, not an arbitrary
    last line -- which, when pip itself raises an unhandled exception, is a
    `~~~~^` caret-pointer continuation from Python's traceback formatting,
    not the error message."""
    lines = [ln for ln in stderr.strip().splitlines() if ln.strip()]
    if not lines:
        return "no output"
    for ln in reversed(lines):
        stripped = ln.strip()
        if stripped.startswith("ERROR:") or stripped.startswith("error:"):
            return stripped
    # No explicit ERROR: line (e.g. the subprocess crashed outright) --
    # the real message is usually the exception type+message at the very
    # end, not a caret-only continuation line.
    for ln in reversed(lines):
        if ln.strip() and not ln.strip().startswith(("~", "^", "File \"")):
            return ln.strip()
    return lines[-1].strip()


def check_go_tools():
    go = shutil.which("go")
    if not go:
        log("go toolchain not found -- skipping subfinder/httpx/puredns/naabu "
            "(optional speed upgrades for recon-dominator; it has a built-in fallback for all of them)")
        return
    for name, module in GO_TOOLS.items():
        if shutil.which(name):
            continue
        log(f"installing {name} via go install (user-scoped, no sudo)...")
        try:
            r = subprocess.run(["go", "install", "-v", module], capture_output=True, text=True, timeout=120)
            log(f"  [OK] {name}" if r.returncode == 0 else f"  [SKIP] {name} -- go install failed, run it yourself if you want it: go install {module}")
        except (subprocess.TimeoutExpired, OSError):
            log(f"  [SKIP] {name} -- timed out or go is unusable here")


def report_system_tools():
    if sys.platform.startswith("linux"):
        mgr = "apt"
    elif sys.platform == "darwin":
        mgr = "brew"
    elif sys.platform.startswith("win"):
        mgr = "choco"
    else:
        mgr = "apt"
    missing = {name: cmds[mgr] for name, cmds in SYSTEM_TOOLS.items() if not shutil.which(name)}
    if not missing:
        return
    log("optional system tools not found on PATH (each skill that uses one degrades or explains "
        "what's missing rather than crashing -- install only what you actually need):")
    for name, cmd in missing.items():
        log(f"  {name}: {cmd}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plugin-root", default=str(Path(__file__).resolve().parent.parent),
                     help="Plugin root (defaults to this script's own parent directory)")
    ap.add_argument("--data-dir", default=None,
                     help="Writable data dir for the setup marker (falls back to the plugin root if unset)")
    ap.add_argument("--force", action="store_true", help="Re-run pip install even if the marker matches")
    args = ap.parse_args()

    plugin_root = Path(args.plugin_root)
    data_dir = Path(args.data_dir) if args.data_dir else plugin_root
    requirements = plugin_root / "requirements.txt"
    marker_path = data_dir / "setup.json"

    if not requirements.exists():
        log(f"no requirements.txt at {requirements}, nothing to do")
        return 0

    current_hash = requirements_hash(requirements)
    marker = load_marker(marker_path)
    expected_pkgs = {
        line.split("#", 1)[0].strip().split(">=")[0].split("==")[0].strip()
        for line in requirements.read_text().splitlines()
        if line.split("#", 1)[0].strip()
    }
    prior_results = marker.get("packages", {}) if marker.get("requirements_hash") == current_hash else {}
    already_attempted = expected_pkgs and expected_pkgs.issubset(prior_results.keys())

    if not args.force and already_attempted:
        # Every package in requirements.txt was already attempted against
        # this exact file (success or failure recorded either way) --
        # SessionStart fires on every session, so this keeps it fast after
        # the first, and critically does NOT re-run pip for a package that
        # can never succeed here (e.g. yara-python with no C compiler
        # available) on every single session forever.
        failed = [p for p, ok in prior_results.items() if not ok]
        if failed:
            log(f"skipping pip install (already attempted this session's requirements.txt; "
                f"still unavailable: {', '.join(sorted(failed))} -- run with --force to retry)")
        check_go_tools()  # cheap (shutil.which first); fine to redo every session
        report_system_tools()
        return 0

    log("installing optional Python dependencies (one-time per requirements.txt version; cached after this)...")
    results = pip_install(requirements, {} if args.force else prior_results)
    check_go_tools()
    report_system_tools()

    save_marker(marker_path, {
        "requirements_hash": current_hash,
        "packages": results,
        "last_run": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    failed = [p for p, ok in results.items() if not ok]
    log("done" if not failed else f"done ({len(failed)} package(s) unavailable here, see above -- won't retry those until requirements.txt changes or --force)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
