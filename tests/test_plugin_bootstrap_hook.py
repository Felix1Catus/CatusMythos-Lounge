import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class PluginBootstrapHookTests(unittest.TestCase):
    def test_session_start_uses_python3_command(self):
        manifest = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        hook = manifest["hooks"]["SessionStart"][0]["hooks"][0]

        self.assertEqual(hook["command"], "python3")
        self.assertEqual(hook["args"][0], "${CLAUDE_PLUGIN_ROOT}/scripts/bootstrap.py")
