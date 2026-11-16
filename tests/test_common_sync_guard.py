import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_common_sync.py"
SPEC = importlib.util.spec_from_file_location("check_common_sync_for_tests", SCRIPT_PATH)
common_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = common_sync
SPEC.loader.exec_module(common_sync)


class CommonSyncGuardTests(unittest.TestCase):
    def test_missing_required_common_file_fails_the_guard(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(common_sync, "REPO_ROOT", Path(temp_dir)), \
                    patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as caught:
                    common_sync.main()
        self.assertEqual(caught.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
