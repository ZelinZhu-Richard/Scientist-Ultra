"""Narrow command-line integration tests for the Research OS vNext fixture."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


# Direct imports in this module are an explicitly marked test capability.  A
# production process cannot obtain this marker from the verified launcher.
sys._scientist_one_test_runner = True  # type: ignore[attr-defined]

from scientist_one.cli import build_parser, main


class ResearchOSFixtureParserTests(unittest.TestCase):
    def test_fixture_run_id_is_an_optional_named_argument(self) -> None:
        parser = build_parser()
        default = parser.parse_args(["research-os-fixture"])
        explicit = parser.parse_args(
            ["research-os-fixture", "--run-id", "vnext-fixture-1"]
        )

        self.assertEqual(default.command, "research-os-fixture")
        self.assertIsNone(default.run_id)
        self.assertEqual(explicit.command, "research-os-fixture")
        self.assertEqual(explicit.run_id, "vnext-fixture-1")
        with self.assertRaises(SystemExit):
            parser.parse_args(["research-os-fixture", "vnext-fixture-1"])


class ResearchOSFixtureDispatchTests(unittest.TestCase):
    def _run_fixture(
        self,
        result: dict[str, object],
        *,
        run_id: str | None = "vnext-fixture-1",
    ) -> tuple[int, str, mock.Mock, mock.Mock]:
        orchestrator = mock.Mock()
        orchestrator.research_os_fixture.return_value = result
        orchestrator_type = mock.Mock(return_value=orchestrator)
        arguments = ["--root", "/requested/scientist-one", "research-os-fixture"]
        if run_id is not None:
            arguments.extend(("--run-id", run_id))
        output = io.StringIO()
        with mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), mock.patch(
            "scientist_one.orchestrator.ScientistOneOrchestrator",
            orchestrator_type,
        ), contextlib.redirect_stdout(output):
            exit_status = main(arguments)
        return exit_status, output.getvalue(), orchestrator, orchestrator_type

    def test_fixture_dispatch_uses_guarded_orchestrator_and_canonical_json(self) -> None:
        exit_status, output, orchestrator, orchestrator_type = self._run_fixture(
            {"status": "PASS", "alpha": 1}
        )

        self.assertEqual(exit_status, 0)
        self.assertEqual(
            output,
            '{\n  "alpha": 1,\n  "status": "PASS"\n}\n',
        )
        orchestrator_type.assert_called_once_with(Path("/requested/scientist-one"))
        orchestrator.research_os_fixture.assert_called_once_with(
            "vnext-fixture-1", restart_from_run_id=None
        )
        orchestrator.set_command_context.assert_called_once_with(
            [
                "python3",
                "-I",
                "-S",
                "-B",
                "scripts/scientist_one_cli.py",
                "research-os-fixture",
                "--run-id",
                "vnext-fixture-1",
            ]
        )

    def test_fixture_without_run_id_passes_none(self) -> None:
        exit_status, _, orchestrator, _ = self._run_fixture(
            {"status": "PASS"}, run_id=None
        )

        self.assertEqual(exit_status, 0)
        orchestrator.research_os_fixture.assert_called_once_with(
            None, restart_from_run_id=None
        )

    def test_only_exact_pass_status_exits_zero(self) -> None:
        for status in ("UNTESTED", "BLOCKED_EXTERNAL", "pass", "FAIL"):
            with self.subTest(status=status):
                exit_status, output, orchestrator, _ = self._run_fixture(
                    {"status": status}
                )
                self.assertEqual(exit_status, 1)
                self.assertEqual(json.loads(output)["status"], status)
                orchestrator.research_os_fixture.assert_called_once_with(
                    "vnext-fixture-1", restart_from_run_id=None
                )


if __name__ == "__main__":
    unittest.main()
