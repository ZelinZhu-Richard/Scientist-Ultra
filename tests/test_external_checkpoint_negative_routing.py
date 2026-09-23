"""NEW_REGRESSION_TEST: read-only checkpoint refusal from actual local owners."""

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from scientist_one import orchestrator as orchestrator_module
from scientist_one.orchestrator import OrchestrationError, ScientistOneOrchestrator
from scientist_one.recovery import LedgerValidationError, RecoveryManager, checkpoint_digest
from scientist_one.resources import ResourceAction, ResourceController
from tests import test_cli as fixtures


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NewExternalCheckpointNegativeRoutingTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)
        self.owner = fixtures._CliFixtureOwner(PROJECT_ROOT)
        self.addCleanup(self.owner.archive)
        self.run_id = self.owner.start(self.orchestrator)["run_id"]

    @staticmethod
    def continue_decision(controller, *args, **kwargs):
        return replace(
            fixtures.ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
            action=ResourceAction.CONTINUE, reasons=(), checkpoint_required=False,
            accept_new_work=True, stop_budget=False, backoff_seconds=0.0,
        )

    def identity(self, run_ids=(), extra_paths=()):
        root = PROJECT_ROOT.lstat()
        rows = [(".", root.st_mode, root.st_dev, root.st_ino, root.st_size,
                 root.st_mtime_ns, root.st_ctime_ns)]
        relatives = [
            Path(".scientist-one-event-ledger.lock"),
            Path(".scientist-one-artifact-registry.lock"),
            *extra_paths,
        ]
        for run_id in (self.run_id, *run_ids):
            relatives.extend((
                Path("runs") / run_id,
                Path(".scientist-one-build/checkpoints") / run_id,
                Path(".scientist-one-build/resource-authority") / run_id,
                Path(".scientist-one-build/custody") / (run_id + ".jsonl"),
            ))
        for relative in relatives:
            target = PROJECT_ROOT / relative
            if not target.exists() and not target.is_symlink():
                rows.append((relative.as_posix(), "ABSENT"))
                continue
            paths = [target]
            if target.is_dir() and not target.is_symlink():
                paths += sorted(target.rglob("*"))
            for path in paths:
                info = path.lstat()
                payload = (os.readlink(path) if stat.S_ISLNK(info.st_mode)
                           else path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
                rows.append((path.relative_to(PROJECT_ROOT).as_posix(), info.st_mode,
                             info.st_dev, info.st_ino, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns, payload))
        return tuple(rows)

    def later_checkpoint_with_earlier_run(self):
        # Real INITIALIZED checkpoint, real CALIBRATE->CHARTER checkpoint; no
        # fabricated event, resource, custody, transition or success receipt.
        temporary = tempfile.TemporaryDirectory(dir=PROJECT_ROOT / ".scientist-one-build/tmp")
        self.addCleanup(temporary.cleanup)
        temporary_root = Path(temporary.name)
        run = PROJECT_ROOT / "runs" / self.run_id
        shutil.copytree(run, temporary_root / "before")
        with mock.patch.object(ResourceController, "evaluate", autospec=True,
                               side_effect=self.continue_decision):
            result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["current_state"], "CHARTER")
        later = self.orchestrator.load_manifest(self.run_id)
        name = f"event-{later['event_count']:04d}-{later['ledger_head_hash'][:12]}.json"
        checkpoint = PROJECT_ROOT / ".scientist-one-build/checkpoints" / self.run_id / name
        self.assertTrue(checkpoint.is_file())
        os.replace(run, temporary_root / "complete")
        os.replace(temporary_root / "before", run)
        return checkpoint

    def assert_negative(self, result):
        self.assertEqual(result["status"], "STOP_SECURITY")
        self.assertEqual(result["terminal_state"], "STOP_SECURITY")
        self.assertFalse(result["persisted"])
        self.assertFalse(result["resumable"])
        self.assertNotIn("safe_resume_command", result)
        self.assertEqual(result["authority_channel"], "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL")
        self.assertEqual(result["recovery"]["action"], "STOP_SECURITY")
        self.assertEqual(result["recovery"]["quarantined"], [])
        self.assertIsNone(result["recovery"]["checkpoint"])

    def test_current_checkpoint_has_no_negative_override(self):
        manifest = self.orchestrator.load_manifest(self.run_id)
        before = self.identity()
        with mock.patch.object(RecoveryManager, "recover", side_effect=AssertionError("no full recovery")), \
             mock.patch.object(RecoveryManager, "repair_truncated_ledger", side_effect=AssertionError("no repair")), \
             mock.patch.object(RecoveryManager, "quarantine_incomplete", side_effect=AssertionError("no quarantine")):
            self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
        self.assertEqual(self.identity(), before)

    def test_real_later_checkpoint_precedes_pilot_without_work_or_writes(self):
        self.later_checkpoint_with_earlier_run()
        partial = PROJECT_ROOT / "runs" / self.run_id / "retained.partial"
        partial.write_bytes(b"owned incomplete bytes must not be quarantined")
        before = self.identity()
        with mock.patch.object(self.orchestrator, "_pilot_operation_disposition", side_effect=AssertionError("conflict precedes pilot")), \
             mock.patch.object(self.orchestrator, "_run_with_resources", side_effect=AssertionError("no work")), \
             mock.patch.object(ResourceController, "acquire", side_effect=AssertionError("no acquire")), \
             mock.patch.object(RecoveryManager, "recover", side_effect=AssertionError("no full recovery")), \
             mock.patch.object(RecoveryManager, "repair_truncated_ledger", side_effect=AssertionError("no repair")), \
             mock.patch.object(RecoveryManager, "quarantine_incomplete", side_effect=AssertionError("no quarantine")):
            result = self.orchestrator.resume(self.run_id)
            self.assert_negative(result)
            self.assertEqual(self.identity(), before)
            replay = self.orchestrator.resume(self.run_id)
            self.assertEqual(replay, result)
        self.assertEqual(self.identity(), before)

    def test_actual_checkpoint_with_conflicting_head_is_negative_only(self):
        manifest = self.orchestrator.load_manifest(self.run_id)
        directory = PROJECT_ROOT / ".scientist-one-build/checkpoints" / self.run_id
        checkpoint = directory / f"event-{manifest['event_count']:04d}-{manifest['ledger_head_hash'][:12]}.json"
        value = json.loads(checkpoint.read_text())
        # Explicit adverse mutation of a genuine published checkpoint. Its
        # recomputed structural digest is not scientific or execution authority.
        value["ledger_head_hash"] = "0" * 64
        value["checkpoint_hash"] = checkpoint_digest(value)
        checkpoint.write_text(json.dumps(value, sort_keys=True) + "\n")
        before = self.identity()
        with mock.patch.object(self.orchestrator, "_pilot_operation_disposition", side_effect=AssertionError("negative conflict only")), \
             mock.patch.object(RecoveryManager, "recover", side_effect=AssertionError("no full recovery")):
            self.assert_negative(self.orchestrator.resume(self.run_id))
        self.assertEqual(self.identity(), before)

    def test_foreign_and_malformed_checkpoint_do_not_invent_conflict(self):
        checkpoint = self.later_checkpoint_with_earlier_run()
        genuine = json.loads(checkpoint.read_text())
        manifest = self.orchestrator.load_manifest(self.run_id)
        foreign = dict(genuine, run_id="run-unrelated")
        foreign["checkpoint_hash"] = checkpoint_digest(foreign)
        bad_hash = dict(genuine, checkpoint_hash="0" * 64)
        wrong_schema = dict(genuine, unknown_field=True)
        wrong_schema["checkpoint_hash"] = checkpoint_digest(wrong_schema)
        for label, raw in (
            ("foreign", json.dumps(foreign).encode()),
            ("bad-hash", json.dumps(bad_hash).encode()),
            ("wrong-schema", json.dumps(wrong_schema).encode()),
            ("malformed", b"{not-json"),
        ):
            with self.subTest(label=label):
                checkpoint.write_bytes(raw)
                before = self.identity()
                self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
                self.assertEqual(self.identity(), before)
        # None means no new override, not permission for the original lifecycle.

    def test_unsafe_checkpoint_is_not_misclassified_as_valid_conflict(self):
        checkpoint = self.later_checkpoint_with_earlier_run()
        preserved = checkpoint.with_suffix(".preserved")
        os.replace(checkpoint, preserved)
        checkpoint.symlink_to(preserved)
        before = self.identity()
        manifest = self.orchestrator.load_manifest(self.run_id)
        self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
        self.assertEqual(self.identity(), before)

    def test_missing_registry_namespaces_are_not_recreated(self):
        manifest = self.orchestrator.load_manifest(self.run_id)
        for name in ("objects", "metadata"):
            with self.subTest(namespace=name):
                original = PROJECT_ROOT / "runs" / self.run_id / "registry" / name
                preserved = original.with_name(name + "-preserved")
                os.replace(original, preserved)
                try:
                    before = self.identity()
                    with mock.patch.object(self.orchestrator, "_registry", side_effect=AssertionError("no initializer")):
                        self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
                    self.assertFalse(original.exists())
                    self.assertEqual(self.identity(), before)
                finally:
                    os.replace(preserved, original)

    def test_invalid_or_truncated_ledger_is_not_repaired(self):
        self.later_checkpoint_with_earlier_run()
        manifest = self.orchestrator.load_manifest(self.run_id)
        ledger = PROJECT_ROOT / "runs" / self.run_id / "events.jsonl"
        original = ledger.read_bytes()
        for label, raw in (("truncated", original + b'{"incomplete":'),
                           ("invalid", b"invalid ledger\n")):
            with self.subTest(label=label):
                ledger.write_bytes(raw)
                before = self.identity()
                with mock.patch.object(RecoveryManager, "repair_truncated_ledger", side_effect=AssertionError("no repair")), \
                     mock.patch.object(RecoveryManager, "quarantine_incomplete", side_effect=AssertionError("no quarantine")):
                    self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
                self.assertEqual(self.identity(), before)
        # Keep the actual faulted bytes; fixture archival is not a repair.

    def test_actual_pilot_completion_and_corrupt_authority_keep_existing_routing(self):
        with mock.patch.object(ResourceController, "evaluate", autospec=True,
                               side_effect=self.continue_decision):
            while self.orchestrator.status(self.run_id)["current_state"] != "CONFIRM":
                self.orchestrator.advance_once(self.run_id)
        manifest = self.orchestrator.load_manifest(self.run_id)
        self.assertIn("resource_runtime_pilot_completion", manifest["artifacts"])
        before = self.identity()
        self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
        self.assertEqual(self.identity(), before)
        authority = sorted((PROJECT_ROOT / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))[-1]
        authority.write_bytes(b"{invalid actual pilot authority")
        before = self.identity()
        # Local ledger/checkpoints are still matched; corrupt resource history
        # must remain with its existing owner, never become a rollback receipt.
        self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
        with mock.patch.object(self.orchestrator, "_run_with_resources", side_effect=AssertionError("no work")), \
             mock.patch.object(ResourceController, "acquire", side_effect=AssertionError("no acquire")):
            with self.assertRaises(OrchestrationError):
                self.orchestrator.resume(self.run_id)
        self.assertEqual(self.identity(), before)

    def lock_paths(self):
        return (
            PROJECT_ROOT / ".scientist-one-event-ledger.lock",
            PROJECT_ROOT / ".scientist-one-artifact-registry.lock",
            PROJECT_ROOT / "runs" / self.run_id / ".events.jsonl.lock",
            PROJECT_ROOT / "runs" / self.run_id / "registry" / ".registry.lock",
        )

    def restore_absent_lock(self, lock, preserved):
        # No overwrite of a recreated lock, even when a control fails. Such a
        # failure retains the original at its exact .v3-preserved path.
        self.assertFalse(lock.exists() or lock.is_symlink(),
                         "unexpected lock entry; original retained, not overwritten")
        os.replace(preserved, lock)

    def test_missing_local_and_project_locks_decline_before_initializers(self):
        manifest = self.orchestrator.load_manifest(self.run_id)
        for lock in self.lock_paths():
            with self.subTest(lock=lock.relative_to(PROJECT_ROOT).as_posix()):
                preserved = lock.with_name(lock.name + ".v3-preserved")
                self.assertTrue(lock.is_file())
                self.assertFalse(preserved.exists() or preserved.is_symlink())
                os.replace(lock, preserved)
                try:
                    before = self.identity(extra_paths=(preserved.relative_to(PROJECT_ROOT),))
                    with mock.patch.object(orchestrator_module, "EventLedger", side_effect=AssertionError("no ledger initializer")), \
                         mock.patch.object(self.orchestrator, "_registry", side_effect=AssertionError("no registry initializer")), \
                         mock.patch.object(self.orchestrator, "_foundation_ledger_validation", side_effect=AssertionError("no adapter")):
                        self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
                    self.assertFalse(lock.exists() or lock.is_symlink())
                    self.assertEqual(self.identity(extra_paths=(preserved.relative_to(PROJECT_ROOT),)), before)
                finally:
                    self.restore_absent_lock(lock, preserved)

    def test_unsafe_local_and_project_locks_decline_before_initializers(self):
        manifest = self.orchestrator.load_manifest(self.run_id)
        for lock in self.lock_paths():
            for kind in ("symlink", "directory"):
                with self.subTest(lock=lock.relative_to(PROJECT_ROOT).as_posix(), kind=kind):
                    preserved = lock.with_name(lock.name + ".v3-preserved")
                    self.assertFalse(preserved.exists() or preserved.is_symlink())
                    os.replace(lock, preserved)
                    if kind == "symlink":
                        lock.symlink_to(preserved)
                    else:
                        lock.mkdir()
                    try:
                        before = self.identity(extra_paths=(preserved.relative_to(PROJECT_ROOT),))
                        with mock.patch.object(orchestrator_module, "EventLedger", side_effect=AssertionError("no ledger initializer")), \
                             mock.patch.object(self.orchestrator, "_registry", side_effect=AssertionError("no registry initializer")), \
                             mock.patch.object(self.orchestrator, "_foundation_ledger_validation", side_effect=AssertionError("no adapter")):
                            self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
                        self.assertEqual(self.identity(extra_paths=(preserved.relative_to(PROJECT_ROOT),)), before)
                    finally:
                        if kind == "symlink":
                            self.assertTrue(lock.is_symlink())
                            self.assertEqual(os.readlink(lock), str(preserved))
                            lock.unlink()
                        else:
                            self.assertFalse(lock.is_symlink())
                            lock.rmdir()  # Empty owned mutant only; never recursive.
                        self.restore_absent_lock(lock, preserved)

    def test_missing_locks_on_conflict_revalidation_do_not_initialize(self):
        self.later_checkpoint_with_earlier_run()
        manifest = self.orchestrator.load_manifest(self.run_id)
        original_select = RecoveryManager.select_checkpoint
        original_adapter = self.orchestrator._foundation_ledger_validation
        for lock in self.lock_paths():
            with self.subTest(lock=lock.relative_to(PROJECT_ROOT).as_posix()):
                preserved = lock.with_name(lock.name + ".v3-preserved")
                self.assertFalse(preserved.exists() or preserved.is_symlink())
                fault_identity = []

                def select_then_remove(manager, *args, **kwargs):
                    try:
                        return original_select(manager, *args, **kwargs)
                    except LedgerValidationError:
                        os.replace(lock, preserved)
                        fault_identity.append(self.identity(
                            extra_paths=(preserved.relative_to(PROJECT_ROOT),)))
                        raise  # Preserve the actual owner's conflict exception.

                try:
                    with mock.patch.object(RecoveryManager, "select_checkpoint", autospec=True, side_effect=select_then_remove) as selector, \
                         mock.patch.object(self.orchestrator, "_foundation_ledger_validation", side_effect=original_adapter) as adapter:
                        with self.assertRaises(OrchestrationError):
                            self.orchestrator._external_checkpoint_conflict_report(manifest)
                    self.assertEqual(selector.call_count, 1)
                    self.assertEqual(adapter.call_count, 1)  # Initial real replay only.
                    self.assertEqual(len(fault_identity), 1)
                    self.assertFalse(lock.exists() or lock.is_symlink())
                    self.assertEqual(self.identity(extra_paths=(preserved.relative_to(PROJECT_ROOT),)), fault_identity[0])
                finally:
                    if preserved.exists():
                        self.restore_absent_lock(lock, preserved)

    def test_genuine_foreign_ledger_never_dispatches_absent_foreign_registry(self):
        self.later_checkpoint_with_earlier_run()
        foreign_id = self.owner.start(self.orchestrator)["run_id"]
        self.assertNotEqual(foreign_id, self.run_id)
        manifest = self.orchestrator.load_manifest(self.run_id)
        requested_ledger = PROJECT_ROOT / "runs" / self.run_id / "events.jsonl"
        foreign_ledger = PROJECT_ROOT / "runs" / foreign_id / "events.jsonl"
        requested_bytes = requested_ledger.read_bytes()
        foreign_bytes = foreign_ledger.read_bytes()
        foreign_registry = PROJECT_ROOT / "runs" / foreign_id / "registry"
        preserved = foreign_registry.with_name("registry-v3-preserved")
        self.assertFalse(preserved.exists() or preserved.is_symlink())
        os.replace(foreign_registry, preserved)
        original_select = RecoveryManager.select_checkpoint
        original_registry = self.orchestrator._registry
        original_adapter = self.orchestrator._foundation_ledger_validation

        def requested_registry(run_id):
            self.assertEqual(run_id, self.run_id, "foreign registry dispatch is forbidden")
            return original_registry(run_id)  # Real registry; no positive mock.

        try:
            requested_ledger.write_bytes(foreign_bytes)
            before = self.identity(run_ids=(foreign_id,))
            with mock.patch.object(self.orchestrator, "_registry", side_effect=AssertionError("no registry dispatch")), \
                 mock.patch.object(self.orchestrator, "_foundation_ledger_validation", side_effect=AssertionError("no foreign adapter replay")):
                self.assertIsNone(self.orchestrator._external_checkpoint_conflict_report(manifest))
            self.assertFalse(foreign_registry.exists() or foreign_registry.is_symlink())
            self.assertEqual(self.identity(run_ids=(foreign_id,)), before)

            # Restore the owned genuine requested prefix solely to reach the
            # actual selector conflict, then substitute B before revalidation.
            requested_ledger.write_bytes(requested_bytes)
            fault_identity = []

            def select_then_substitute(manager, *args, **kwargs):
                try:
                    return original_select(manager, *args, **kwargs)
                except LedgerValidationError:
                    requested_ledger.write_bytes(foreign_bytes)
                    fault_identity.append(self.identity(run_ids=(foreign_id,)))
                    raise

            with mock.patch.object(RecoveryManager, "select_checkpoint", autospec=True, side_effect=select_then_substitute) as selector, \
                 mock.patch.object(self.orchestrator, "_registry", side_effect=requested_registry) as registry, \
                 mock.patch.object(self.orchestrator, "_foundation_ledger_validation", side_effect=original_adapter) as adapter:
                with self.assertRaises(OrchestrationError):
                    self.orchestrator._external_checkpoint_conflict_report(manifest)
            self.assertEqual(selector.call_count, 1)
            self.assertEqual(adapter.call_count, 1)
            self.assertGreaterEqual(registry.call_count, 1)
            self.assertEqual(len(fault_identity), 1)
            self.assertFalse(foreign_registry.exists() or foreign_registry.is_symlink())
            self.assertEqual(self.identity(run_ids=(foreign_id,)), fault_identity[0])
            # The requested ledger remains faulted for ordinary fixture archival.
        finally:
            self.assertFalse(foreign_registry.exists() or foreign_registry.is_symlink(),
                             "unexpected foreign namespace retained; no overwrite")
            os.replace(preserved, foreign_registry)
