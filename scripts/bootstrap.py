#!/usr/bin/env python3
"""Install and verify the dependencies used by CatusMythos-Lounge.

The SessionStart hook runs this script best-effort. It installs declared Python
packages, Playwright's Chromium browser, user-scoped Go tools, and allowlisted
system tools through an already-installed package manager. Every attempted
install is logged. Run ``python3 scripts/bootstrap.py --strict`` before a full
engagement to require the complete managed tool stack; use ``--require-tool``
or ``--require-python`` for a narrower task-specific preflight.

The bootstrap never downloads or executes an installer script itself. It only
invokes the platform package manager when one is already available, with
non-interactive flags and bounded timeouts. A package manager may still need
administrator privileges for system packages; failures are reported and a
strict preflight exits nonzero instead of letting dependent work proceed.
"""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# User-scoped Go tools used by recon-dominator. Amass remains manual: v5 removed
# enum's v4-style file output, and the documented database-readback CLI moved
# across v5.x releases. Do not manage it until the installed CLI has been
# checked directly and both wordlist brute forcing and structured output work.
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
}
MANUAL_OPTIONAL_TOOLS = {
    "amass": (
        "Deferred; do not add to GO_TOOLS yet. Amass v5 dropped enum's one-shot "
        "-o/-json output for a local-database model; Oct 2025 docs pointed to "
        "amass subs -names/-ip/-summary for plain-text readback, but that CLI "
        "surface moved again and the cited subs command was later removed in a "
        "v5.x point release. The Apr 2026 v5.1.1/develop issue also reports "
        "-brute/-w wordlists parsed into config but unused by the engine; this "
        "is an open maintainer question, not an acknowledged/fixed bug. Unblock "
        "only after checking the actually installed `amass --help` and "
        "`amass enum --help`, proving a wordlist run visibly emits guesses, "
        "and proving a reliable structured-output path exists. Treat those "
        "help outputs and a disposable owned-domain fixture as ground truth, "
        "not articles."
    ),
}

# Allowlisted system tools used by the skills. Package names and executable
# aliases are explicit because packages do not always install a command with
# the same name (notably Sysinternals WHOIS on Windows).
SYSTEM_TOOLS = {
    "go": {
        "commands": ("go",),
        "apt": ("golang-go",),
        "dnf": ("golang",),
        "yum": ("golang",),
        "pacman": ("go",),
        "brew": ("go",),
        "choco": ("golang",),
        "winget": ("GoLang.Go",),
    },
    "nmap": {
        "commands": ("nmap",),
        "apt": ("nmap",),
        "dnf": ("nmap",),
        "yum": ("nmap",),
        "pacman": ("nmap",),
        "brew": ("nmap",),
        "choco": ("nmap",),
        "winget": ("Insecure.Nmap",),
    },
    "dig": {
        "commands": ("dig",),
        "apt": ("dnsutils",),
        "dnf": ("bind-utils",),
        "yum": ("bind-utils",),
        "pacman": ("bind",),
        "brew": ("bind",),
        "choco": ("bind-toolsonly",),
        "winget": ("ISC.Bind",),
    },
    "whois": {
        "commands": ("whois", "whois64"),
        "apt": ("whois",),
        "dnf": ("whois",),
        "yum": ("whois",),
        "pacman": ("whois",),
        "brew": ("whois",),
        "choco": ("whois",),
        "winget": ("Microsoft.Sysinternals.Whois",),
    },
    "perl": {
        "commands": ("perl",),
        "apt": ("perl",),
        "dnf": ("perl",),
        "yum": ("perl",),
        "pacman": ("perl",),
        "brew": ("perl",),
        "choco": ("strawberryperl",),
        "winget": ("StrawberryPerl.StrawberryPerl",),
    },
}

# Distribution names and import names are not always identical.
PYTHON_IMPORTS = {
    "requests": "requests",
    "playwright": "playwright",
}

INSTALL_TIMEOUT_SECONDS = 180
GO_INSTALL_TIMEOUT_SECONDS = 180
CHROMIUM_INSTALL_TIMEOUT_SECONDS = 300
DEFAULT_BUDGET_SECONDS = 540  # leave room inside the 10-minute command-hook cap
SYSTEM_TOOL_ORDER = ("go", "nmap", "dig", "whois", "perl")
KNOWN_TOOLS = tuple(SYSTEM_TOOLS) + tuple(GO_TOOLS) + ("chromium",)
_PATH_AT_START = os.environ.get("PATH", "")


def log(message: str) -> None:
    print(f"[catusmythos-lounge setup] {message}", flush=True)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def requirements_hash(req_path: Path) -> str:
    """Hash normalized text so LF/CRLF checkouts share the same marker."""
    try:
        normalized = _read_text(req_path).replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError):
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_marker(marker_path: Path) -> dict:
    try:
        marker = json.loads(_read_text(marker_path))
        return marker if isinstance(marker, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def save_marker(marker_path: Path, data: dict) -> None:
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        log(f"warning: could not write setup marker ({error}); dependencies will be rechecked next run")


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    """Return (distribution name, requirement spec) pairs from requirements text."""
    parsed = []
    for raw in text.splitlines():
        spec = raw.split("#", 1)[0].strip()
        if not spec or spec.startswith(("-", "git+", "http://", "https://")):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if match:
            parsed.append((match.group(1), spec))
    return parsed


def _module_for_distribution(package_name: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", package_name).lower()
    return PYTHON_IMPORTS.get(normalized, package_name.replace("-", "_").replace(".", "_"))


def _requirement_available(package_name: str, spec: str) -> bool:
    """Check both importability and the declared version constraint."""
    module_name = _module_for_distribution(package_name)
    try:
        if importlib.util.find_spec(module_name) is None:
            return False
        installed_version = importlib.metadata.version(package_name)
    except (ImportError, ModuleNotFoundError, importlib.metadata.PackageNotFoundError, ValueError):
        return False

    # pip vendors packaging, so this adds no bootstrap dependency. If it is
    # unavailable or a spec cannot be parsed, re-run pip rather than trusting
    # a stale marker.
    try:
        from pip._vendor.packaging.requirements import Requirement
        from pip._vendor.packaging.version import Version

        requirement = Requirement(spec)
        return Version(installed_version) in requirement.specifier
    except (ImportError, ValueError, TypeError):
        return False


def _remaining(deadline: Optional[float], cap: int) -> int:
    if deadline is None:
        return cap
    remaining = int(deadline - time.monotonic())
    return max(0, min(cap, remaining))


def _run(command: Sequence[str], timeout: int, *, env: Optional[dict] = None):
    if timeout <= 0:
        raise subprocess.TimeoutExpired(command, timeout)
    return subprocess.run(
        list(command), capture_output=True, text=True, timeout=timeout, env=env,
    )


def _error_summary(result: subprocess.CompletedProcess) -> str:
    output = (result.stderr or result.stdout or "").strip().splitlines()
    for line in reversed(output):
        if line.strip():
            return line.strip()[:240]
    return f"process exited {result.returncode} without diagnostic output"


def pip_install(
    requirements: Path,
    prior_results: Optional[dict] = None,
    *,
    package_filter: Optional[Iterable[str]] = None,
    force: bool = False,
    deadline: Optional[float] = None,
) -> Dict[str, bool]:
    """Install missing/outdated dependencies and verify each import afterward.

    A cached success is only a hint: the active interpreter and package
    version are checked every run. A cached failure is retried so transient
    network/proxy errors do not permanently disable a skill.
    """
    try:
        pairs = parse_requirements(_read_text(requirements))
    except (OSError, UnicodeError) as error:
        log(f"could not read {requirements}: {error}")
        return {}

    results = {}
    prior = prior_results or {}
    selected_packages = set(package_filter) if package_filter is not None else None
    for package_name, spec in pairs:
        if selected_packages is not None and package_name not in selected_packages:
            continue
        available = _requirement_available(package_name, spec)
        if not force and available:
            results[package_name] = True
            detail = "cached success revalidated" if prior.get(package_name) is True else "already satisfies requirement"
            log(f"  [OK] {package_name} {detail}")
            continue

        timeout = _remaining(deadline, INSTALL_TIMEOUT_SECONDS)
        if timeout <= 0:
            log(f"  [PENDING] {package_name} -- bootstrap time budget exhausted")
            results[package_name] = False
            continue
        log(f"installing Python dependency {spec} with {sys.executable}...")
        try:
            result = _run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", spec],
                timeout,
            )
        except subprocess.TimeoutExpired:
            log(f"  [TIMEOUT] {package_name} ({timeout}s)")
            results[package_name] = False
            continue
        except OSError as error:
            log(f"  [FAILED] {package_name} -- could not start pip ({error})")
            results[package_name] = False
            continue

        if result.returncode == 0 and _requirement_available(package_name, spec):
            log(f"  [OK] {package_name}")
            results[package_name] = True
        else:
            reason = _error_summary(result) if result.returncode else "installed package is not importable or does not meet its version constraint"
            log(f"  [FAILED] {package_name} -- {reason}")
            results[package_name] = False
    return results


def _available_commands(names: Iterable[str]) -> List[str]:
    return [name for name in names if shutil.which(name)]


def _available_to_invoking_session(names: Iterable[str]) -> bool:
    return any(shutil.which(name, path=_PATH_AT_START) for name in names)


def _system_managers() -> List[str]:
    if sys.platform.startswith("win"):
        # Chocolatey packages are generally current; winget is the built-in
        # fallback and uses immutable package IDs instead of search results.
        return [name for name in ("choco", "winget") if shutil.which(name)]
    if sys.platform == "darwin":
        return ["brew"] if shutil.which("brew") else []
    if sys.platform.startswith("linux"):
        return [
            name for name, command in (
                ("apt", "apt-get"), ("dnf", "dnf"),
                ("yum", "yum"), ("pacman", "pacman"),
            ) if shutil.which(command)
        ]
    return []


def build_install_command(
    tool_name: str,
    manager: str,
    *,
    is_root: Optional[bool] = None,
    sudo_available: Optional[bool] = None,
) -> Optional[List[str]]:
    """Build a noninteractive package-manager command for tests and installs."""
    tool = SYSTEM_TOOLS.get(tool_name)
    if not tool or manager not in tool:
        return None
    packages = list(tool[manager])
    if manager in ("apt", "dnf", "yum", "pacman"):
        if is_root is None:
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root:
            if sudo_available is None:
                sudo_available = bool(shutil.which("sudo"))
            if not sudo_available:
                return None
            prefix = ["sudo", "-n"]
        else:
            prefix = []
        if manager == "apt":
            return prefix + ["apt-get", "install", "-y", *packages]
        if manager in ("dnf", "yum"):
            return prefix + [manager, "install", "-y", *packages]
        return prefix + ["pacman", "-S", "--noconfirm", *packages]
    if manager == "brew":
        return ["brew", "install", *packages]
    if manager == "choco":
        return ["choco", "install", *packages, "-y", "--no-progress"]
    if manager == "winget":
        package_id = packages[0]
        return [
            "winget", "install", "--id", package_id, "--exact", "--silent",
            "--accept-package-agreements", "--accept-source-agreements",
            "--disable-interactivity",
        ]
    return None


def _refresh_windows_path() -> None:
    """Refresh PATH after a package-manager install in the current process."""
    if not sys.platform.startswith("win"):
        return
    try:
        import winreg

        paths = [os.environ.get("PATH", "")]
        for hive, subkey in (
            (winreg.HKEY_CURRENT_USER, "Environment"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        ):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    value, _ = winreg.QueryValueEx(key, "Path")
            except OSError:
                continue
            if isinstance(value, str):
                paths.append(os.path.expandvars(value))
        seen = set()
        combined = []
        for entry in os.pathsep.join(paths).split(os.pathsep):
            normalized = os.path.normcase(os.path.expandvars(entry.strip().strip('"')))
            if normalized and normalized not in seen:
                seen.add(normalized)
                combined.append(entry.strip().strip('"'))
        os.environ["PATH"] = os.pathsep.join(combined)
    except (ImportError, OSError, AttributeError):
        return


def _persist_windows_user_path(path: Path) -> bool:
    """Keep a user-scoped Go bin on future Windows sessions' PATH."""
    if not sys.platform.startswith("win"):
        return False
    try:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, "Environment", 0,
            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
        ) as key:
            try:
                current, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current = ""
            entries = [item.strip().strip('"') for item in str(current).split(os.pathsep) if item.strip()]
            normalized = os.path.normcase(os.path.normpath(str(path)))
            if any(os.path.normcase(os.path.normpath(item)) == normalized for item in entries):
                return True
            entries.append(str(path))
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, os.pathsep.join(entries))
        return True
    except (ImportError, OSError, AttributeError):
        return False


def ensure_system_tool(tool_name: str, deadline: Optional[float] = None) -> bool:
    tool = SYSTEM_TOOLS.get(tool_name)
    if not tool:
        log(f"unknown system tool {tool_name!r}; no installer is configured")
        return False
    available = _available_commands(tool["commands"])
    if available:
        if not _available_to_invoking_session(tool["commands"]):
            log(f"  [INSTALLED] {tool_name} is visible only after PATH refresh; restart the terminal/Claude host before using it")
            return False
        log(f"  [OK] {tool_name} ({available[0]})")
        return True

    managers = _system_managers()
    if not managers:
        log(f"  [MISSING] {tool_name} -- no supported package manager found; install it to PATH")
        return False

    for manager in managers:
        command = build_install_command(tool_name, manager)
        if not command:
            continue
        timeout = _remaining(deadline, INSTALL_TIMEOUT_SECONDS)
        if timeout <= 0:
            log(f"  [PENDING] {tool_name} -- bootstrap time budget exhausted")
            return False
        log(f"missing {tool_name}; installing with {manager} (noninteractive, up to {timeout}s)...")
        env = os.environ.copy()
        if manager == "apt":
            env["DEBIAN_FRONTEND"] = "noninteractive"
        elif manager == "brew":
            env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        try:
            result = _run(command, timeout, env=env)
        except subprocess.TimeoutExpired:
            log(f"  [TIMEOUT] {tool_name} via {manager} ({timeout}s)")
            continue
        except OSError as error:
            log(f"  [FAILED] {tool_name} via {manager} -- {error}")
            continue
        _refresh_windows_path()
        available = _available_commands(tool["commands"])
        if available:
            if not _available_to_invoking_session(tool["commands"]):
                log(f"  [INSTALLED] {tool_name} is installed but the running Claude session has an old PATH; restart the session before using it")
                return False
            log(f"  [OK] {tool_name} installed via {manager} ({available[0]})")
            return True
        if result.returncode == 0:
            log(f"  [PENDING] {tool_name} installer succeeded but its executable is not on PATH yet")
        else:
            log(f"  [FAILED] {tool_name} via {manager} -- {_error_summary(result)}")
    log(f"  [MISSING] {tool_name} remains unavailable after install attempts")
    return False


def _go_bin_directory() -> Optional[Path]:
    go = shutil.which("go")
    if not go:
        return None
    try:
        result = _run([go, "env", "GOBIN", "GOPATH"], 10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    values = result.stdout.splitlines()
    gobin = values[0].strip() if values else ""
    if gobin:
        return Path(gobin)
    gopath = values[1].strip() if len(values) > 1 else ""
    if gopath:
        return Path(gopath.split(os.pathsep)[0]) / "bin"
    return None


def _add_go_bin_to_process_path() -> Optional[Path]:
    go_bin = _go_bin_directory()
    if not go_bin:
        return None
    go_bin_text = str(go_bin)
    current = os.environ.get("PATH", "").split(os.pathsep)
    if not any(os.path.normcase(os.path.normpath(item)) == os.path.normcase(os.path.normpath(go_bin_text)) for item in current if item):
        os.environ["PATH"] = go_bin_text + os.pathsep + os.environ.get("PATH", "")
    if sys.platform.startswith("win"):
        _persist_windows_user_path(go_bin)
    return go_bin


def check_go_tools(
    deadline: Optional[float] = None,
    tool_filter: Optional[Iterable[str]] = None,
) -> Dict[str, bool]:
    requested_tools = set(tool_filter) if tool_filter is not None else None
    selected_tools = [
        name for name in GO_TOOLS
        if requested_tools is None or name in requested_tools
    ]
    go = shutil.which("go")
    if not go:
        log("go toolchain is unavailable; Go recon tools cannot be installed")
        return {name: False for name in selected_tools}

    go_bin = _add_go_bin_to_process_path()
    if go_bin:
        log(f"using Go tool install directory {go_bin}")

    results = {}
    for name in selected_tools:
        module = GO_TOOLS[name]
        executable_names = (name + ".exe", name) if sys.platform.startswith("win") else (name,)
        if _available_to_invoking_session(executable_names):
            results[name] = True
            log(f"  [OK] {name}")
            continue
        if go_bin and any((go_bin / executable).is_file() for executable in executable_names):
            log(f"  [INSTALLED] {name} is at {go_bin}; add that directory to PATH and restart the Claude session before using it")
            results[name] = False
            continue

        timeout = _remaining(deadline, GO_INSTALL_TIMEOUT_SECONDS)
        if timeout <= 0:
            log(f"  [PENDING] {name} -- bootstrap time budget exhausted")
            results[name] = False
            continue
        log(f"missing {name}; installing user-scoped Go tool with go install...")
        try:
            result = _run([go, "install", "-v", module], timeout)
        except subprocess.TimeoutExpired:
            log(f"  [TIMEOUT] {name} ({timeout}s)")
            results[name] = False
            continue
        except OSError as error:
            log(f"  [FAILED] {name} -- {error}")
            results[name] = False
            continue

        _refresh_windows_path()
        go_bin = _add_go_bin_to_process_path()
        found_on_original_path = any(shutil.which(executable, path=_PATH_AT_START) for executable in executable_names)
        found = bool(_available_commands(executable_names))
        if not found and go_bin:
            found = any((go_bin / executable).is_file() for executable in executable_names)
        if result.returncode == 0 and found and found_on_original_path:
            log(f"  [OK] {name}" + (f" ({go_bin})" if go_bin else ""))
            results[name] = True
        elif result.returncode == 0 and found:
            log(f"  [INSTALLED] {name} at {go_bin or 'the Go bin directory'}; restart the Claude session so its PATH includes the tool")
            results[name] = False
        else:
            reason = _error_summary(result) if result.returncode else "go install returned success but the executable was not found"
            log(f"  [FAILED] {name} -- {reason}")
            results[name] = False
    return results


def _chromium_executable() -> Optional[Path]:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        log(f"Playwright is not importable in {sys.executable}: {error}")
        return None


def _install_playwright_system_deps(deadline: Optional[float]) -> bool:
    """Install Playwright's declared Chromium OS dependencies on Linux."""
    if not sys.platform.startswith("linux"):
        return False
    command = [sys.executable, "-m", "playwright", "install-deps", "chromium"]
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if not is_root:
        sudo = shutil.which("sudo")
        if not sudo:
            log("  [MISSING] Chromium OS libraries need administrator install; sudo is unavailable")
            return False
        command = [sudo, "-n", *command]
    timeout = _remaining(deadline, INSTALL_TIMEOUT_SECONDS)
    if timeout <= 0:
        log("  [PENDING] Chromium OS libraries -- bootstrap time budget exhausted")
        return False
    log("Chromium launch reports missing OS libraries; installing Playwright's Chromium dependencies...")
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        result = _run(command, timeout, env=env)
    except subprocess.TimeoutExpired:
        log(f"  [TIMEOUT] Chromium OS library install ({timeout}s)")
        return False
    except OSError as error:
        log(f"  [FAILED] Chromium OS library install -- {error}")
        return False
    if result.returncode != 0:
        log(f"  [FAILED] Chromium OS library install -- {_error_summary(result)}")
        return False
    log("  [OK] Playwright Chromium OS dependencies installed")
    return True


def ensure_chromium(deadline: Optional[float] = None, *, verify_launch: bool = False) -> bool:
    executable = _chromium_executable()
    if executable is None:
        return False
    if not executable.is_file():
        timeout = _remaining(deadline, CHROMIUM_INSTALL_TIMEOUT_SECONDS)
        if timeout <= 0:
            log("  [PENDING] Playwright Chromium -- bootstrap time budget exhausted")
            return False
        log(f"missing Playwright Chromium; installing with {sys.executable} -m playwright install chromium...")
        try:
            result = _run([sys.executable, "-m", "playwright", "install", "chromium"], timeout)
        except subprocess.TimeoutExpired:
            log(f"  [TIMEOUT] Chromium install ({timeout}s)")
            return False
        except OSError as error:
            log(f"  [FAILED] Chromium install -- {error}")
            return False
        executable = _chromium_executable()
        if result.returncode != 0 or executable is None or not executable.is_file():
            reason = _error_summary(result) if result.returncode else "Chromium executable still missing after install"
            log(f"  [FAILED] Chromium install -- {reason}")
            return False
        log("  [OK] Playwright Chromium installed")
    else:
        log(f"  [OK] Playwright Chromium ({executable})")

    if verify_launch:
        timeout = _remaining(deadline, 45)
        if timeout <= 0:
            log("  [PENDING] Chromium launch check -- bootstrap time budget exhausted")
            return False
        smoke_check = (
            "from playwright.sync_api import sync_playwright; "
            "p=sync_playwright().start(); b=p.chromium.launch(headless=True); "
            "b.close(); p.stop()"
        )
        try:
            result = _run([sys.executable, "-c", smoke_check], timeout)
        except subprocess.TimeoutExpired:
            log(f"  [FAILED] Chromium launch smoke check timed out ({timeout}s)")
            return False
        except OSError as error:
            log(f"  [FAILED] Chromium launch smoke check -- {error}")
            return False
        if result.returncode != 0:
            details = _error_summary(result)
            lower_details = details.lower()
            missing_os_deps = any(
                marker in lower_details
                for marker in ("missing dependencies", "missing dependenc", "shared libraries", "shared library")
            )
            if missing_os_deps and _install_playwright_system_deps(deadline):
                timeout = _remaining(deadline, 45)
                if timeout > 0:
                    try:
                        result = _run([sys.executable, "-c", smoke_check], timeout)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        log(f"  [FAILED] Chromium retry after OS dependency install -- {error}")
                        return False
                    if result.returncode == 0:
                        log("  [OK] Chromium headless launch after installing OS dependencies")
                        return True
                    details = _error_summary(result)
            log(f"  [FAILED] Chromium launch smoke check -- {details}")
            return False
        log("  [OK] Chromium headless launch")
    return True


def _all_dependencies_available(requirements: Path, package_results: dict, system_results: dict, go_results: dict, chromium_ok: bool) -> List[str]:
    missing = []
    try:
        pairs = parse_requirements(_read_text(requirements))
    except (OSError, UnicodeError):
        return ["requirements.txt"]
    for package_name, spec in pairs:
        if not package_results.get(package_name) or not _requirement_available(package_name, spec):
            missing.append(f"python:{package_name}")
    missing.extend(name for name in SYSTEM_TOOLS if not system_results.get(name))
    missing.extend(name for name in GO_TOOLS if not go_results.get(name))
    if any(package_name == "playwright" for package_name, _ in pairs) and not chromium_ok:
        missing.append("chromium")
    return missing


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-root", default=str(Path(__file__).resolve().parent.parent),
        help="Plugin root (defaults to this script's parent directory)",
    )
    parser.add_argument(
        "--data-dir", default=None,
        help="Writable marker dir (defaults to the plugin root)",
    )
    parser.add_argument("--force", action="store_true", help="Re-run pip checks even when the marker matches")
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit nonzero unless every managed Python, browser, system, and Go dependency is ready",
    )
    parser.add_argument(
        "--require-tool", action="append", choices=KNOWN_TOOLS, default=[], metavar="NAME",
        help="Require and verify one task-specific tool; repeat as needed (installs it if missing)",
    )
    parser.add_argument(
        "--require-python", action="append", choices=tuple(PYTHON_IMPORTS), default=[], metavar="PACKAGE",
        help="Require and verify one Python dependency; repeat as needed",
    )
    parser.add_argument(
        "--budget-seconds", type=int, default=DEFAULT_BUDGET_SECONDS,
        help="Maximum time spent installing (default: %(default)s; bounded by the hook timeout)",
    )
    args = parser.parse_args(argv)
    deadline = time.monotonic() + max(1, args.budget_seconds)
    _refresh_windows_path()
    plugin_root = Path(args.plugin_root)
    data_dir = Path(args.data_dir) if args.data_dir else plugin_root
    requirements = plugin_root / "requirements.txt"
    marker_path = data_dir / "setup.json"

    if not requirements.is_file():
        log(f"no readable requirements.txt at {requirements}")
        return 1 if args.strict else 0

    try:
        requirements_text = _read_text(requirements)
    except (OSError, UnicodeError) as error:
        log(f"could not read {requirements}: {error}")
        return 1 if args.strict else 0

    current_hash = requirements_hash(requirements)
    marker = load_marker(marker_path)
    prior_results = marker.get("packages", {}) if marker.get("requirements_hash") == current_hash else {}
    if not isinstance(prior_results, dict):
        prior_results = {}
    task_specific = bool(args.require_tool or args.require_python) and not args.strict
    requirements_pairs = parse_requirements(requirements_text)
    requested_packages = set(args.require_python)
    if "chromium" in args.require_tool:
        requested_packages.add("playwright")
    package_filter = requested_packages if task_specific else None
    log(f"checking optional Python dependencies with {sys.executable}...")
    package_results = pip_install(
        requirements, prior_results, package_filter=package_filter,
        force=args.force, deadline=deadline,
    )

    # Install system packages only from the explicit allowlist above, through
    # a package manager already present on the machine.
    system_results = {}
    selected_system = set(SYSTEM_TOOLS) if args.strict else {
        name for name in args.require_tool if name in SYSTEM_TOOLS
    }
    # The normal startup path warms the common CLI toolchain too; strict and
    # task-specific modes verify the exact same tools before reporting ready.
    if not (args.require_tool or args.require_python) and not args.strict:
        selected_system = set(SYSTEM_TOOLS)
    for name in SYSTEM_TOOL_ORDER:
        if name in selected_system:
            system_results[name] = ensure_system_tool(name, deadline)

    go_results = {}
    selected_go = set(GO_TOOLS) if args.strict else {
        name for name in args.require_tool if name in GO_TOOLS
    }
    # The default startup bootstrap continues to install the recon Go tools.
    if not (args.require_tool or args.require_python) and not args.strict:
        selected_go = set(GO_TOOLS)
    if selected_go:
        if not system_results.get("go") and not shutil.which("go"):
            # A specific Go-tool request depends on the Go runtime.
            system_results["go"] = ensure_system_tool("go", deadline)
        all_go = check_go_tools(deadline, selected_go)
        go_results = {name: all_go.get(name, False) for name in selected_go}

    package_names = {name for name, _ in requirements_pairs}
    needs_chromium = "playwright" in package_names
    chromium_required = args.strict or "chromium" in args.require_tool
    chromium_ok = False
    should_prepare_chromium = needs_chromium and (not task_specific or chromium_required)
    if should_prepare_chromium and package_results.get("playwright"):
        chromium_ok = ensure_chromium(deadline, verify_launch=chromium_required)
    elif should_prepare_chromium:
        log("Chromium setup deferred because the Playwright Python package is unavailable")

    marker_packages = dict(prior_results)
    marker_packages.update(package_results)
    marker_system_tools = marker.get("system_tools", {})
    if not isinstance(marker_system_tools, dict):
        marker_system_tools = {}
    marker_system_tools = dict(marker_system_tools)
    marker_system_tools.update(system_results)
    marker_go_tools = marker.get("go_tools", {})
    if not isinstance(marker_go_tools, dict):
        marker_go_tools = {}
    marker_go_tools = dict(marker_go_tools)
    marker_go_tools.update(go_results)
    save_marker(marker_path, {
        "requirements_hash": current_hash,
        "python_executable": sys.executable,
        "packages": marker_packages,
        "system_tools": marker_system_tools,
        "go_tools": marker_go_tools,
        "chromium": chromium_ok,
        "last_run": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    if args.strict:
        # A strict run always checks/installs the full stack, including tools
        # not yet attempted in task-specific mode.
        if set(system_results) != set(SYSTEM_TOOLS):
            for name in SYSTEM_TOOL_ORDER:
                if name not in system_results:
                    system_results[name] = ensure_system_tool(name, deadline)
        if set(go_results) != set(GO_TOOLS):
            all_go = check_go_tools(deadline, set(GO_TOOLS) - set(go_results))
            go_results = {name: all_go.get(name, False) for name in GO_TOOLS}
        missing = _all_dependencies_available(requirements, package_results, system_results, go_results, chromium_ok)
        if missing:
            log("strict preflight failed; do not run dependent tasks until these are available: " + ", ".join(missing))
            return 1
        log("strict preflight passed: all managed dependencies are ready")
    elif args.require_tool or args.require_python:
        missing = []
        for name in args.require_tool:
            if name in SYSTEM_TOOLS and not system_results.get(name):
                missing.append(name)
            elif name in GO_TOOLS and not go_results.get(name):
                missing.append(name)
            elif name == "chromium" and not chromium_ok:
                missing.append(name)
        for package_name in args.require_python:
            matching_spec = next((spec for name, spec in parse_requirements(requirements_text) if name == package_name), None)
            if not matching_spec or not package_results.get(package_name) or not _requirement_available(package_name, matching_spec):
                missing.append(f"python:{package_name}")
        if missing:
            log("required task tools unavailable; do not start dependent checks: " + ", ".join(missing))
            return 1
        required_names = args.require_tool + [f"python:{name}" for name in args.require_python]
        log("task tool preflight passed: " + ", ".join(required_names))
    else:
        unavailable = [name for name, available in package_results.items() if not available]
        unavailable.extend(name for name, available in system_results.items() if not available)
        unavailable.extend(name for name, available in go_results.items() if not available)
        if not chromium_ok and needs_chromium:
            unavailable.append("chromium")
        log("bootstrap finished" + (f"; unresolved: {', '.join(unavailable)}" if unavailable else "; managed dependencies ready"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
