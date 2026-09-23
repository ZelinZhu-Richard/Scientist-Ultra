"""Fresh public-source startup controls; never mint or copy bootstrap authority."""

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


PROJECT = Path(__file__).resolve().parents[1]


class FreshStartupContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="scientist-one-fresh-startup-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name) / "ScientistOne"
        cls.root.mkdir()
        shutil.copytree(PROJECT / "src", cls.root / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (cls.root / "scripts").mkdir()
        shutil.copyfile(PROJECT / "scripts/scientist_one_cli.py", cls.root / "scripts/scientist_one_cli.py")
        shutil.copyfile(PROJECT / "pyproject.toml", cls.root / "pyproject.toml")

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py", *arguments],
            cwd=self.root, capture_output=True, text=True, timeout=30,
            # No private credentials, bootstrap, app settings, or historic state.
            env={"PATH": os.defpath}, check=False,
        )

    def assert_no_authority_or_run_created(self):
        for relative in ("state", "runs", "artifacts", ".scientist-one-build"):
            self.assertFalse((self.root / relative).exists(), relative)

    def test_unsupported_console_entry_is_not_advertised(self):
        metadata = tomllib.loads((self.root / "pyproject.toml").read_text())
        self.assertNotIn("scientist-one", metadata["project"].get("scripts", {}))

    def test_guarded_help_works_without_private_bootstrap(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("start", result.stdout)
        self.assertIn("research-os-fixture", result.stdout)
        self.assert_no_authority_or_run_created()

    def test_fresh_status_is_truthfully_blocked_before_state_creation(self):
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 2, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "ERROR")
        self.assertEqual(payload["error_type"], "OrchestrationError")
        self.assertIn("bootstrap receipt", payload["message"])
        self.assert_no_authority_or_run_created()

    def test_supplied_question_cannot_skip_fresh_admission(self):
        brief = self.root / "question.md"
        brief.write_text("# Research question\nDoes a fixed linear classifier exceed a majority baseline on permitted local data?\n")
        result = self.run_cli("start", "--brief", "question.md")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("bootstrap receipt", json.loads(result.stdout)["message"])
        self.assert_no_authority_or_run_created()

    def test_invalid_command_is_usage_error_not_research_outcome(self):
        result = self.run_cli("not-a-command")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)
        self.assert_no_authority_or_run_created()

    def test_legacy_status_exit_mapping_remains_in_source(self):
        # Read-only compatibility assertion, not an executed successful research
        # run or a forged launch capability. Existing CLI runtime tests retain
        # their separate historical evidence at the unchanged cli.py hash.
        tree = ast.parse((self.root / "src/scientist_one/cli.py").read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        expected = ast.parse('return 0 if result.get("status") == "PASS" else 1').body[0]
        self.assertEqual(ast.dump(main.body[-1]), ast.dump(expected))
