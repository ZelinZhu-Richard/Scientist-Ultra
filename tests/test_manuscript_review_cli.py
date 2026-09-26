"""Read-only review CLI routing, with no fabricated workspace authority."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scientist_one.cli import _dispatch, build_parser


class ReviewStatusDispatchTests(unittest.TestCase):
    def test_exact_run_and_artifact_bindings_reach_consumer(self):
        calls = []

        class Consumer:
            def set_command_context(self, context):
                calls.append(tuple(context))

            def paper_review_status(self, run_id, **kwargs):
                calls.append((run_id, kwargs))
                return {"status": "BLOCKED", "review_status": "NOT_READY"}

        args = build_parser().parse_args([
            "paper-review-status", "review-run",
            "--decision-sha256", "a" * 64,
            "--revision-sha256", "b" * 64,
        ])
        result = _dispatch(Consumer(), args)
        self.assertEqual(result, {"status": "BLOCKED", "review_status": "NOT_READY"})
        self.assertEqual(calls[0], (
            "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
            "paper-review-status", "review-run", "--decision-sha256", "a" * 64,
            "--revision-sha256", "b" * 64,
        ))
        self.assertEqual(calls[1], ("review-run", {
            "decision_artifact_hash": "a" * 64,
            "revision_artifact_hash": "b" * 64,
        }))


class FreshReviewStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scientist-one-review-cli-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name) / "ScientistOne"
        cls.root.mkdir()
        project = Path(__file__).resolve().parents[1]
        shutil.copytree(project / "src", cls.root / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (cls.root / "scripts").mkdir()
        shutil.copyfile(project / "scripts/scientist_one_cli.py", cls.root / "scripts/scientist_one_cli.py")

    def command(self, *args):
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py", *args],
            cwd=self.root, env={"PATH": os.defpath}, capture_output=True,
            text=True, timeout=30, check=False,
        )

    def assert_no_state(self):
        for name in ("state", "runs", "artifacts", ".scientist-one-build"):
            self.assertFalse((self.root / name).exists(), name)

    def test_help_is_honest_about_read_only_operation(self):
        result = self.command("paper-review-status", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--decision-sha256", result.stdout)
        self.assertIn("--revision-sha256", result.stdout)
        self.assert_no_state()

    def test_missing_identity_is_usage_error(self):
        result = self.command("paper-review-status", "review-run")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--decision-sha256", result.stderr)
        self.assert_no_state()

    def test_new_command_does_not_bypass_fresh_admission(self):
        result = self.command("paper-review-status", "review-run", "--decision-sha256", "a" * 64, "--revision-sha256", "b" * 64)
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "ERROR")
        self.assertEqual(value["error_type"], "OrchestrationError")
        self.assertIn("bootstrap receipt", value["message"])
        self.assert_no_state()
