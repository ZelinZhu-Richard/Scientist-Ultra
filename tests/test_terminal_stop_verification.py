"""Integrity of native persisted stops is distinct from permission to resume."""

from dataclasses import replace
from pathlib import Path
import unittest
from unittest import mock

from scientist_one.recovery import ResumeAction
from scientist_one.ledger import EventLedger
from scientist_one.orchestrator import OrchestrationError
from scientist_one.resources import ResourceAction, ResourceController
from tests import test_cli as fixtures


class TerminalStopVerificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.OrchestratorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.orchestrator = self.fixture.orchestrator

    def stopped(self, destination):
        run_id = self.orchestrator.start()["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        self.orchestrator._queue_terminal(
            manifest, destination, "Explicit terminal-integrity test fixture",
            evidence={"test_scope": "typed stop; no scientific execution"},
        )
        self.orchestrator._transition_terminal(manifest)
        self.orchestrator._save_manifest(manifest)
        return run_id, manifest

    def snapshot(self, run_id):
        return (
            self.orchestrator._registry(run_id).verify_all(),
            EventLedger(
                self.orchestrator.root, Path("runs") / run_id / "events.jsonl"
            ).assert_valid(),
        )

    def test_persisted_stops_verify_but_never_resume_or_advance(self):
        for terminal in ("STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY"):
            with self.subTest(terminal=terminal):
                run_id, manifest = self.stopped(terminal)
                recovery = self.orchestrator._recovery_report(manifest)
                self.assertEqual(recovery.action.value, terminal)
                self.assertEqual(
                    recovery.reasons, (f"PERSISTED_TERMINAL_STATE:{terminal}",)
                )
                self.assertFalse(recovery.resumable)
                verification = self.orchestrator.verify(run_id)
                self.assertEqual(verification["status"], "PASS", verification)
                before = self.snapshot(run_id)
                status = self.orchestrator.status(run_id)
                resumed = self.orchestrator.resume(run_id)
                advanced = self.orchestrator.advance_once(run_id)
                for result in (status, resumed, advanced):
                    self.assertEqual(result["status"], terminal)
                    self.assertFalse(result["resumable"])
                    self.assertNotIn("safe_resume_command", result)
                with self.assertRaisesRegex(
                    OrchestrationError, "terminal stop.*reproduction"
                ):
                    self.orchestrator.reproduce(run_id)
                self.assertEqual(self.snapshot(run_id), before)

    def test_stopped_run_cannot_reproduce_completed_architecture_control(self):
        run_id = self.orchestrator.start()["run_id"]

        def continue_decision(controller, *args, **kwargs):
            return replace(
                fixtures.ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        # Only the existing availability-probe seam is controlled. Actual
        # native simulated custody and result owners still execute and verify.
        with mock.patch.object(
            ResourceController, "evaluate", autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "CLAIMS":
                self.orchestrator.advance_once(run_id)
        manifest = self.orchestrator.load_manifest(run_id)
        results = self.orchestrator._json_artifact_payload(manifest, "machine_results")
        self.assertEqual(results["evidence_class"], "ARCHITECTURE_CONTROL")
        self.assertIsNone(manifest.get("reproduction"))
        self.orchestrator._queue_terminal(
            manifest, "STOP_SECURITY", "Actual post-result terminal fixture",
            evidence={"test_scope": "simulated result, no scientific authority"},
        )
        self.orchestrator._transition_terminal(manifest)
        self.orchestrator._save_manifest(manifest)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "PASS")
        run_root = self.orchestrator.root / "runs" / run_id

        def files():
            return tuple(
                (path.relative_to(run_root).as_posix(), path.read_bytes())
                for path in sorted(run_root.rglob("*")) if path.is_file()
            )

        before = self.snapshot(run_id), self.orchestrator.load_manifest(run_id), files()
        with self.assertRaisesRegex(OrchestrationError, "terminal stop.*reproduction"):
            self.orchestrator.reproduce(run_id)
        self.assertEqual(
            (self.snapshot(run_id), self.orchestrator.load_manifest(run_id), files()), before
        )

    def test_an_additional_recovery_failure_is_not_a_verified_persisted_stop(self):
        run_id, manifest = self.stopped("STOP_SECURITY")
        native = self.orchestrator._recovery_report(manifest)
        self.assertTrue(native.ledger_valid)
        self.assertTrue(native.artifacts_valid)
        # Adverse report substitution only: no owner is mocked into success.
        for changes in (
            {"reasons": native.reasons + ("ACTUAL_ADDITIONAL_FAILURE",)},
            {"reasons": ()},
            {"reasons": ("PERSISTED_TERMINAL_STATE:STOP_SCIENTIFIC_INVALIDITY",)},
            {"action": ResumeAction.STOP_SCIENTIFIC_INVALIDITY},
            {"action": ResumeAction.NEW_STUDY_REQUIRED},
            {"action": ResumeAction.RESUME_FROM_LEDGER},
            {"derived_state": "CALIBRATE"},
            {"ledger_valid": False},
            {"artifacts_valid": False},
            {"ledger_head_hash": "0" * 64},
            {"ledger_event_count": native.ledger_event_count - 1},
        ):
            with self.subTest(changes=changes), mock.patch.object(
                self.orchestrator, "_recovery_report",
                return_value=replace(native, **changes),
            ):
                result = self.orchestrator.verify(run_id)
                self.assertEqual(result["status"], "FAIL", result)
