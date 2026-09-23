"""Integrity of native persisted stops is distinct from permission to resume."""

from dataclasses import replace
import os
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

from scientist_one.recovery import ResumeAction
from scientist_one.ledger import EventLedger
from scientist_one.orchestrator import OrchestrationError, ScientistOneOrchestrator
from scientist_one.resources import ResourceAction, ResourceController
from tests import test_cli as fixtures


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CLEANUP_REASONS = frozenset({
    "START_RETURN_ID_UNAVAILABLE", "RETURNED_RUN_ID_INVALID",
    "DUPLICATE_RETURNED_RUN_ID",
})
_CLEANUP_METADATA_LIMIT = 512


class TerminalStopVerificationTests(unittest.TestCase):
    def setUp(self):
        self._owned_run_ids = []
        self._cleanup_incomplete = False
        self.addCleanup(self._archive_owned_runs)
        self.orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)

    @staticmethod
    def _safe_run_id(run_id):
        return type(run_id) is str and _RUN_ID_RE.fullmatch(run_id) is not None

    def _emit_cleanup_incomplete(self, reason):
        self._cleanup_incomplete = True
        try:
            if reason not in _CLEANUP_REASONS:
                return
            message = (
                "TERMINAL_STOP_CLEANUP_INCOMPLETE schema=V2 reason="
                + reason + "\n"
            )
            if len(message.encode("utf-8")) > _CLEANUP_METADATA_LIMIT:
                return
            sys.stderr.write(message)
            sys.stderr.flush()
        except Exception:
            # Best effort only; control-flow exceptions must still propagate.
            return

    def start_run(self):
        try:
            result = self.orchestrator.start()
        except Exception:
            self._emit_cleanup_incomplete("START_RETURN_ID_UNAVAILABLE")
            raise
        run_id = result.get("run_id") if type(result) is dict else None
        if not self._safe_run_id(run_id):
            self._emit_cleanup_incomplete("RETURNED_RUN_ID_INVALID")
            raise AssertionError("orchestrator.start returned an unsafe run ID")
        if run_id in self._owned_run_ids:
            self._emit_cleanup_incomplete("DUPLICATE_RETURNED_RUN_ID")
            raise AssertionError("orchestrator.start returned a duplicate run ID")
        self._owned_run_ids.append(run_id)
        return run_id

    @staticmethod
    def _present(path):
        return path.exists() or path.is_symlink()

    @staticmethod
    def _require_directory(path):
        if path.is_symlink() or not path.is_dir():
            raise AssertionError("unsafe archival parent or directory")

    @staticmethod
    def _require_absent(path):
        if path.exists() or path.is_symlink():
            raise AssertionError("archival destination or reserved subtree conflict")

    @staticmethod
    def _require_authority_kind(path, kind):
        valid = path.is_file() if kind == "file" else path.is_dir()
        if path.is_symlink() or not valid:
            raise AssertionError("unsafe owned archival authority path")

    def _archive_owned_runs(self):
        # A failed start exposes no ID: never discover or adopt its partial run.
        if not self._owned_run_ids:
            return
        try:
            root = PROJECT_ROOT
            if not root.is_absolute() or root.resolve(strict=True) != root:
                raise AssertionError("archival root is not its exact canonical path")
            build = root / ".scientist-one-build"
            runs = root / "runs"
            custody_root = build / "custody"
            resource_root = build / "resource-authority"
            archive = build / "test-runs"
            parents = (root, build, runs, custody_root, resource_root)
            for parent in parents:
                self._require_directory(parent)
            if self._present(archive):
                self._require_directory(archive)
            ids = tuple(self._owned_run_ids)
            if (any(not self._safe_run_id(run_id) for run_id in ids)
                    or len(set(ids)) != len(ids)):
                raise AssertionError("unsafe or duplicate owned run ID")
            plans = []
            # Preflight every known ID before moving any of them.
            for run_id in ids:
                source, destination = runs / run_id, archive / run_id
                self._require_directory(source)
                self._require_absent(source / "external-authority")
                self._require_absent(destination)
                ancillary = []
                for path, name, kind in (
                    (custody_root / (run_id + ".jsonl"), "custody.jsonl", "file"),
                    (resource_root / run_id, "resource", "dir"),
                ):
                    present = self._present(path)
                    if present:
                        self._require_authority_kind(path, kind)
                    ancillary.append((path, name, kind, present))
                plans.append((source, destination, tuple(ancillary)))
            if not self._present(archive):
                archive.mkdir()
            self._require_directory(archive)
            for source, destination, ancillary in plans:
                for parent in (*parents, archive):
                    self._require_directory(parent)
                self._require_directory(source)
                self._require_absent(source / "external-authority")
                self._require_absent(destination)
                os.replace(source, destination)
                external = destination / "external-authority"
                self._require_absent(external)
                if any(present for _, _, _, present in ancillary):
                    external.mkdir()
                for path, name, kind, present in ancillary:
                    for parent in (*parents, archive, destination):
                        self._require_directory(parent)
                    if self._present(path) != present:
                        raise AssertionError("archival authority changed after preflight")
                    if not present:
                        continue
                    self._require_authority_kind(path, kind)
                    self._require_directory(external)
                    target = external / name
                    self._require_absent(target)
                    os.replace(path, target)
            # External checkpoint directories are deliberately retained in place.
        except Exception:
            self._cleanup_incomplete = True
            # Earlier successful moves stay put. No rollback, retry or PASS.
            raise

    def stopped(self, destination):
        run_id = self.start_run()
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
        run_id = self.start_run()

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
