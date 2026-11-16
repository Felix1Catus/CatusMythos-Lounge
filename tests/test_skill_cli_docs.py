import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_skill_cli_docs.py"
SPEC = importlib.util.spec_from_file_location("check_skill_cli_docs_for_tests", SCRIPT_PATH)
skill_cli_docs = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = skill_cli_docs
SPEC.loader.exec_module(skill_cli_docs)


class SkillCliDocsTests(unittest.TestCase):
    def test_parser_collects_options_across_shell_continuations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            skill_dir = Path(temp_dir) / "sample"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                "```bash\npython scripts/tool.py --first \\\n  --second value\n```\n",
                encoding="utf-8",
            )
            commands = list(skill_cli_docs.documented_commands(skill_dir))
        self.assertEqual(commands, [("tool.py", {"--first", "--second"}, 2)])

    def test_missing_script_reference_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            skills_root = Path(temp_dir)
            skill_dir = skills_root / "sample"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text("python scripts/missing.py --input x\n", encoding="utf-8")
            _, references, script_count, failures = skill_cli_docs.check_skill_docs(skills_root)
        self.assertEqual(references, 1)
        self.assertEqual(script_count, 0)
        self.assertEqual(len(failures), 1)
        self.assertIn("missing.py", failures[0])

    def test_unsupported_documented_option_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            skills_root = Path(temp_dir)
            skill_dir = skills_root / "sample"
            scripts_dir = skill_dir / "scripts"
            scripts_dir.mkdir(parents=True)
            (scripts_dir / "tool.py").write_text(
                "import argparse\nparser = argparse.ArgumentParser()\n"
                "parser.add_argument('--known')\nparser.parse_args()\n",
                encoding="utf-8",
            )
            (skill_dir / "SKILL.md").write_text(
                "python scripts/tool.py --unknown value\n", encoding="utf-8"
            )
            _, _, _, failures = skill_cli_docs.check_skill_docs(skills_root)
        self.assertEqual(len(failures), 1)
        self.assertIn("--unknown", failures[0])


if __name__ == "__main__":
    unittest.main()
