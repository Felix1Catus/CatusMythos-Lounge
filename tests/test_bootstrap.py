"""Offline regression tests for dependency setup and task preflight."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "catusmythos_bootstrap", REPO_ROOT / "scripts" / "bootstrap.py"
)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapParsingTests(unittest.TestCase):
    def test_requirements_parser_strips_comments_and_skips_options(self):
        self.assertEqual(
            bootstrap.parse_requirements(
                "requests>=2.31  # http\n-r other.txt\nplaywright>=1.48\n"
            ),
            [
                ("requests", "requests>=2.31"),
                ("playwright", "playwright>=1.48"),
            ],
        )

    def test_requirements_hash_normalizes_line_endings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_bytes(b"requests>=2.31\nplaywright>=1.48\n")
            lf_hash = bootstrap.requirements_hash(path)
            path.write_bytes(b"requests>=2.31\r\nplaywright>=1.48\r\n")
            self.assertEqual(bootstrap.requirements_hash(path), lf_hash)

    @patch.object(bootstrap.importlib.metadata, "version", return_value="2.31.0")
    @patch.object(bootstrap.importlib.util, "find_spec", return_value=object())
    def test_requirement_availability_checks_version_specifier(self, _find_spec, _version):
        self.assertTrue(bootstrap._requirement_available("requests", "requests>=2.31.0"))
        self.assertFalse(bootstrap._requirement_available("requests", "requests>=3.0.0"))


class BootstrapInstallTests(unittest.TestCase):
    @patch.object(bootstrap, "_requirement_available", side_effect=[False, True])
    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    def test_cached_success_is_retried_if_package_was_removed(self, run, _available):
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("requests>=2.31.0\n", encoding="utf-8")
            results = bootstrap.pip_install(requirements, {"requests": True})
        self.assertEqual(results, {"requests": True})
        self.assertEqual(run.call_count, 1)

    @patch.object(bootstrap, "_requirement_available", side_effect=[False, True])
    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    def test_cached_failure_is_retried_for_transient_errors(self, run, _available):
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("requests>=2.31.0\n", encoding="utf-8")
            results = bootstrap.pip_install(requirements, {"requests": False})
        self.assertEqual(results, {"requests": True})
        self.assertEqual(run.call_count, 1)

    @patch.object(bootstrap, "_requirement_available", return_value=False)
    @patch.object(
        bootstrap,
        "_run",
        return_value=subprocess.CompletedProcess([], 1, "", "network unavailable"),
    )
    def test_failed_package_install_is_not_marked_ready(self, _run, _available):
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("requests>=2.31.0\n", encoding="utf-8")
            results = bootstrap.pip_install(requirements, {"requests": False})
        self.assertEqual(results, {"requests": False})

    @patch.object(bootstrap, "_requirement_available", return_value=True)
    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    def test_force_rechecks_with_pip_even_when_dependency_is_ready(self, run, _available):
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("requests>=2.31.0\n", encoding="utf-8")
            results = bootstrap.pip_install(requirements, {"requests": True}, force=True)
        self.assertEqual(results, {"requests": True})
        run.assert_called_once()

    def test_winget_command_uses_exact_noninteractive_package_id(self):
        command = bootstrap.build_install_command("nmap", "winget")
        self.assertEqual(command[:5], ["winget", "install", "--id", "Insecure.Nmap", "--exact"])
        self.assertIn("--silent", command)
        self.assertIn("--disable-interactivity", command)
        self.assertIn("--accept-package-agreements", command)

    def test_chocolatey_command_is_noninteractive(self):
        self.assertEqual(
            bootstrap.build_install_command("dig", "choco"),
            ["choco", "install", "bind-toolsonly", "-y", "--no-progress"],
        )

    def test_apt_command_never_prompts_for_sudo(self):
        command = bootstrap.build_install_command(
            "nmap", "apt", is_root=False, sudo_available=True
        )
        self.assertEqual(command, ["sudo", "-n", "apt-get", "install", "-y", "nmap"])

    def test_arch_command_uses_confirm_flag(self):
        self.assertEqual(
            bootstrap.build_install_command(
                "dig", "pacman", is_root=True, sudo_available=False
            ),
            ["pacman", "-S", "--noconfirm", "bind"],
        )

    @patch.object(bootstrap.shutil, "which", return_value=None)
    def test_apt_command_is_unavailable_without_root_or_sudo(self, _which):
        self.assertIsNone(
            bootstrap.build_install_command(
                "nmap", "apt", is_root=False, sudo_available=False
            )
        )


class BootstrapRuntimeTests(unittest.TestCase):
    @patch.object(bootstrap, "_run")
    @patch.object(bootstrap, "_chromium_executable")
    def test_missing_chromium_is_installed_and_verified(self, executable, run):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory) / "chrome.exe"
            browser.write_bytes(b"fixture")
            executable.side_effect = [Path(directory) / "missing.exe", browser]
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            self.assertTrue(bootstrap.ensure_chromium())
        self.assertEqual(
            run.call_args.args[0][-4:], ["-m", "playwright", "install", "chromium"]
        )

    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 1, "", "missing runtime"))
    @patch.object(bootstrap, "_chromium_executable")
    def test_chromium_launch_failure_is_not_ready(self, executable, _run):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory) / "chrome.exe"
            browser.write_bytes(b"fixture")
            executable.return_value = browser
            self.assertFalse(bootstrap.ensure_chromium(verify_launch=True))

    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    @patch.object(bootstrap.shutil, "which", return_value="/usr/bin/sudo")
    @patch.object(bootstrap.os, "geteuid", create=True, return_value=1000)
    def test_linux_browser_os_dependency_install_is_noninteractive(
        self, _geteuid, _which, run
    ):
        with patch.object(bootstrap.sys, "platform", "linux"):
            self.assertTrue(bootstrap._install_playwright_system_deps(None))
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/sudo", "-n", bootstrap.sys.executable])
        self.assertIn("install-deps", command)
        self.assertEqual(run.call_args.kwargs["env"]["DEBIAN_FRONTEND"], "noninteractive")

    @patch.object(bootstrap, "_install_playwright_system_deps", return_value=True)
    @patch.object(bootstrap, "_run", side_effect=[
        subprocess.CompletedProcess([], 1, "", "Host system is missing dependencies"),
        subprocess.CompletedProcess([], 0, "", ""),
    ])
    @patch.object(bootstrap, "_chromium_executable")
    def test_linux_missing_browser_libraries_are_installed_then_retested(
        self, executable, run, install_deps
    ):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory) / "chrome"
            browser.write_bytes(b"fixture")
            executable.return_value = browser
            with patch.object(bootstrap.sys, "platform", "linux"):
                self.assertTrue(bootstrap.ensure_chromium(verify_launch=True))
        install_deps.assert_called_once()
        self.assertEqual(run.call_count, 2)

    @patch.object(bootstrap, "_system_managers", return_value=[])
    @patch.object(bootstrap.shutil, "which", return_value=None)
    def test_missing_tool_without_package_manager_is_not_ready(self, _which, _managers):
        self.assertFalse(bootstrap.ensure_system_tool("nmap"))

    @patch.object(bootstrap, "_refresh_windows_path")
    @patch.object(bootstrap, "_system_managers", return_value=["winget"])
    @patch.object(bootstrap, "build_install_command", return_value=["winget", "install"])
    @patch.object(bootstrap, "_run", return_value=subprocess.CompletedProcess([], 0, "", ""))
    @patch.object(bootstrap, "_available_commands", side_effect=[[], ["C:/Tools/nmap.exe"]])
    @patch.object(bootstrap.shutil, "which", return_value=None)
    def test_new_system_tool_outside_original_path_requires_session_restart(
        self, _which, _available, _run, _command, _managers, _refresh
    ):
        self.assertFalse(bootstrap.ensure_system_tool("nmap"))

    @patch.object(bootstrap, "_system_managers")
    @patch.object(bootstrap, "_refresh_windows_path")
    @patch.object(bootstrap, "_available_commands", return_value=["C:/Tools/nmap.exe"])
    @patch.object(bootstrap.shutil, "which", return_value=None)
    def test_refreshed_path_does_not_pass_preflight_for_old_parent_session(
        self, _which, _available, _refresh, managers
    ):
        self.assertFalse(bootstrap.ensure_system_tool("nmap"))
        managers.assert_not_called()

    def test_amass_is_explicitly_deferred_from_automated_installs(self):
        self.assertNotIn("amass", bootstrap.GO_TOOLS)
        self.assertIn("JSON-output compatibility", bootstrap.MANUAL_OPTIONAL_TOOLS["amass"])

    @patch.object(bootstrap, "_add_go_bin_to_process_path")
    @patch.object(bootstrap, "_available_commands", return_value=[])
    @patch.object(bootstrap.shutil, "which", side_effect=lambda name, path=None: "/fake/go.exe" if name == "go" else None)
    @patch.object(bootstrap, "_run")
    def test_go_success_without_path_visible_binary_is_not_ready(
        self, run, _which, _available, _go_bin
    ):
        with tempfile.TemporaryDirectory() as directory:
            go_bin = Path(directory)
            (go_bin / "subfinder.exe").write_bytes(b"binary")
            _go_bin.return_value = go_bin
            with patch.object(bootstrap, "GO_TOOLS", {"subfinder": "example/module@latest"}), patch.object(
                bootstrap, "_PATH_AT_START", ""
            ):
                result = bootstrap.check_go_tools()
        self.assertEqual(result, {"subfinder": False})
        run.assert_not_called()

    @patch.object(bootstrap, "_add_go_bin_to_process_path", return_value=None)
    @patch.object(bootstrap, "_available_commands", return_value=[])
    @patch.object(bootstrap.shutil, "which", side_effect=lambda name, path=None: "/fake/go.exe" if name == "go" else None)
    @patch.object(
        bootstrap,
        "_run",
        return_value=subprocess.CompletedProcess([], 0, "", ""),
    )
    def test_go_success_without_discoverable_binary_is_not_ready(
        self, _run, _which, _available, _go_bin
    ):
        with patch.object(bootstrap, "GO_TOOLS", {"subfinder": "example/module@latest"}), patch.object(
            bootstrap, "_PATH_AT_START", ""
        ):
            result = bootstrap.check_go_tools()
        self.assertEqual(result, {"subfinder": False})

    @patch.object(bootstrap, "_add_go_bin_to_process_path", return_value=None)
    @patch.object(bootstrap, "_available_commands", return_value=[])
    @patch.object(bootstrap.shutil, "which", side_effect=lambda name, path=None: "/fake/go.exe" if name == "go" else None)
    @patch.object(
        bootstrap,
        "_run",
        return_value=subprocess.CompletedProcess([], 1, "", "install failed"),
    )
    def test_go_task_preflight_does_not_install_unrequested_tools(
        self, run, _which, _available, _go_bin
    ):
        modules = {
            "subfinder": "example/subfinder@latest",
            "httpx": "example/httpx@latest",
        }
        with patch.object(bootstrap, "GO_TOOLS", modules), patch.object(
            bootstrap, "_PATH_AT_START", ""
        ):
            result = bootstrap.check_go_tools(tool_filter={"subfinder"})
        self.assertEqual(result, {"subfinder": False})
        run.assert_called_once()

    @patch.object(bootstrap, "_add_go_bin_to_process_path", return_value=None)
    @patch.object(bootstrap, "_available_commands", return_value=[])
    @patch.object(bootstrap.shutil, "which", side_effect=lambda name, path=None: "/fake/go.exe" if name == "go" else None)
    @patch.object(
        bootstrap,
        "_run",
        return_value=subprocess.CompletedProcess([], 1, "", "install failed"),
    )
    def test_filtered_go_install_order_follows_manifest_order(
        self, run, _which, _available, _go_bin
    ):
        modules = {
            "subfinder": "example/subfinder@latest",
            "httpx": "example/httpx@latest",
        }
        with patch.object(bootstrap, "GO_TOOLS", modules), patch.object(
            bootstrap, "_PATH_AT_START", ""
        ):
            result = bootstrap.check_go_tools(tool_filter={"httpx", "subfinder"})
        self.assertEqual(list(result), ["subfinder", "httpx"])
        attempted_modules = [call.args[0][-1] for call in run.call_args_list]
        self.assertEqual(attempted_modules, list(modules.values()))

    def test_hook_and_strict_preflight_keep_python3_and_return_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("", encoding="utf-8")
            with patch.object(bootstrap, "pip_install", return_value={}), patch.object(
                bootstrap, "ensure_system_tool", return_value=False
            ), patch.object(
                bootstrap,
                "check_go_tools",
                return_value={name: False for name in bootstrap.GO_TOOLS},
            ):
                result = bootstrap.main(
                    ["--plugin-root", str(root), "--strict", "--budget-seconds", "1"]
                )
        self.assertEqual(result, 1)

    def test_task_preflight_blocks_when_required_tool_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("", encoding="utf-8")
            with patch.object(bootstrap, "pip_install", return_value={}), patch.object(
                bootstrap, "ensure_system_tool", return_value=False
            ):
                result = bootstrap.main(
                    ["--plugin-root", str(root), "--require-tool", "nmap"]
                )
        self.assertEqual(result, 1)

    @patch.object(bootstrap, "_requirement_available", return_value=False)
    def test_python_dependency_preflight_blocks_when_package_is_unavailable(self, _available):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests>=2.31.0\n", encoding="utf-8")
            with patch.object(bootstrap, "pip_install", return_value={"requests": True}):
                result = bootstrap.main(
                    ["--plugin-root", str(root), "--require-python", "requests"]
                )
        self.assertEqual(result, 1)

    def test_narrow_preflight_does_not_install_unrequested_python_or_browser_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "requests>=2.31.0\nplaywright>=1.48.0\n", encoding="utf-8"
            )
            with patch.object(bootstrap, "pip_install", return_value={}) as install, patch.object(
                bootstrap, "ensure_system_tool", return_value=True
            ), patch.object(bootstrap, "ensure_chromium") as chromium:
                result = bootstrap.main(
                    ["--plugin-root", str(root), "--require-tool", "nmap"]
                )
        self.assertEqual(result, 0)
        self.assertEqual(install.call_args.kwargs["package_filter"], set())
        chromium.assert_not_called()

    def test_unreadable_requirements_stays_nonblocking_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("", encoding="utf-8")
            with patch.object(bootstrap, "_read_text", side_effect=OSError("denied")):
                self.assertEqual(bootstrap.main(["--plugin-root", str(root)]), 0)
                self.assertEqual(
                    bootstrap.main(["--plugin-root", str(root), "--strict"]), 1
                )


class BootstrapHookTests(unittest.TestCase):
    def test_hook_uses_python3_bounded_timeout_and_lf(self):
        hook_path = REPO_ROOT / "hooks" / "hooks.json"
        raw = hook_path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        hook = manifest["hooks"]["SessionStart"][0]["hooks"][0]

        self.assertNotIn(b"\r\n", raw)
        self.assertEqual(hook["command"], "python3")
        self.assertEqual(hook["args"][0], "${CLAUDE_PLUGIN_ROOT}/scripts/bootstrap.py")
        self.assertEqual(hook["timeout"], 600)
