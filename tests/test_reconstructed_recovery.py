"""SEMANTIC_RECONSTRUCTION: frozen kernel recovery B-11, 2026-09-19.

New tests from recovered source, not recovered original364 test bytes. All run
events, artifacts and custody mappings are synthetic. Actual EventLedger and
ArtifactRegistry APIs are used; no injected validators or scientific authority.
Recovery plans are inspected without executing experiments or replay callbacks.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState, TerminalState
from scientist_one.recovery import (
    ConfirmatoryRerunError, LedgerValidationError, RecoveryError, RecoveryManager,
    ResumeAction, canonical_json_bytes, event_digest,
)
from scientist_one.roles import Role


class ReconstructedRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.ledger = EventLedger(self.root)
        self.manager = RecoveryManager(self.root)
        self.registry = ArtifactRegistry(self.root)
        self.serial = 0

    def event(self, *, state=MacroState.DISCOVER, event_type="CHECKPOINT", record=None):
        self.serial += 1
        hashes, metadata = (), {}
        if record is not None:
            hashes = (record.sha256,)
            metadata = {"artifact_types": [record.logical_type],
                        "artifact_record_hashes": [record.record_hash]}
        return self.ledger.record(
            run_id="synthetic-recovery", event_id=f"event-{self.serial}",
            timestamp="2026-09-19T12:00:00Z", actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.DISCOVER, requested_state_after=state,
            artifact_hashes=hashes, code_version="synthetic-frozen-code",
            configuration_hash="1" * 64, reason="synthetic recovery fixture",
            event_type=event_type, metadata=metadata,
        )

    def stored_artifact(self):
        return self.registry.put_bytes(
            b"synthetic frozen result", logical_type="synthetic_result",
            origin="semantic reconstruction fixture", creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("synthetic-fixture",), created_at="2026-09-19T12:00:00Z",
        )

    def recover(self, **changes):
        options = {"ledger_path": self.ledger.relative_path,
                   "artifact_registry": self.registry, "incomplete_paths": ()}
        options.update(changes)
        return self.manager.recover(**options)

    def checkpoint_payload(self, event, **changes):
        payload = {"run_id": event.run_id, "event_id": event.event_id,
                   "ledger_head_hash": event.event_hash,
                   "state": event.requested_state_after.value}
        payload.update(changes)
        return payload

    def rewrite_synthetic_events(self, events):
        # Deliberately malformed input is confined to this test's temporary ledger.
        self.ledger.path.write_bytes(b"".join(canonical_json_bytes(event) + b"\n" for event in events))

    def test_existing_empty_ledger_plans_fresh_start(self):
        self.ledger.path.write_bytes(b"")
        report = self.recover()
        self.assertIs(report.action, ResumeAction.START_FRESH)
        self.assertTrue(report.resumable)
        self.assertEqual(report.replay_event_count, 0)
        self.assertEqual(report.ledger_event_count, 0)
        self.assertEqual(report.reasons, ("EMPTY_VALID_LEDGER",))

    def test_valid_actual_ledger_derives_state_without_mutation(self):
        self.event()
        last = self.event(state=MacroState.CANDIDATE)
        before = self.ledger.path.read_bytes()
        report = self.recover()
        self.assertIs(report.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertEqual(report.derived_state, "CANDIDATE")
        self.assertEqual(report.ledger_head_hash, last.event_hash)
        self.assertEqual(report.replay_event_count, 2)
        self.assertEqual(self.ledger.path.read_bytes(), before)
        self.assertTrue(self.ledger.validate().valid)

    def test_malformed_terminated_record_stops_without_repair(self):
        self.event()
        damaged = self.ledger.path.read_bytes() + b"{broken}\n"
        self.ledger.path.write_bytes(damaged)
        report = self.recover()
        self.assertIs(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.ledger_valid)
        self.assertEqual(report.quarantined, ())
        self.assertEqual(self.ledger.path.read_bytes(), damaged)

    def test_rehashed_event_with_wrong_prior_is_refused(self):
        first, second = self.event(), self.event()
        changed = second.to_dict()
        changed["prior_event_hash"] = "f" * 64
        changed["event_hash"] = event_digest(changed)
        self.rewrite_synthetic_events((first.to_dict(), changed))
        result = self.manager.validate_ledger(self.ledger.relative_path)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "BROKEN_HASH_CHAIN")
        self.assertIs(self.recover().action, ResumeAction.STOP_SECURITY)

    def test_valid_hash_does_not_make_incomplete_event_schema_valid(self):
        changed = self.event().to_dict()
        del changed["actor_role"]
        changed["event_hash"] = event_digest(changed)
        self.rewrite_synthetic_events((changed,))
        result = self.manager.validate_ledger(self.ledger.relative_path)
        self.assertFalse(result.valid)
        self.assertTrue(result.error.startswith("INVALID_EVENT_SCHEMA:"))

    def test_duplicate_identity_and_run_change_are_refused_even_with_fresh_hash(self):
        first, second = self.event(), self.event()
        for field, value, error in (("event_id", first.event_id, "DUPLICATE_EVENT_ID"),
                                    ("run_id", "other-synthetic-run", "RUN_ID_CHANGED")):
            with self.subTest(field=field):
                changed = second.to_dict()
                changed[field] = value
                changed["event_hash"] = event_digest(changed)
                self.rewrite_synthetic_events((first.to_dict(), changed))
                result = self.manager.validate_ledger(self.ledger.relative_path)
                self.assertFalse(result.valid)
                self.assertEqual(result.error, error)

    def test_unambiguous_partial_tail_is_quarantined_with_exact_prefix_preserved(self):
        event = self.event()
        prefix = self.ledger.path.read_bytes()
        damaged = prefix + b'{"event_id":'
        self.ledger.path.write_bytes(damaged)
        report = self.recover()
        self.assertIs(report.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertEqual(report.ledger_event_count, 1)
        self.assertEqual(report.ledger_head_hash, event.event_hash)
        self.assertEqual(self.ledger.path.read_bytes(), prefix)
        record, = report.quarantined
        self.assertEqual(record.reason, "TRUNCATED_FINAL_LEDGER_APPEND")
        self.assertEqual((self.root / record.quarantine_relative_path).read_bytes(), damaged)
        self.assertEqual(record.sha256, hashlib.sha256(damaged).hexdigest())
        self.assertTrue(self.ledger.validate().valid)

    def test_partial_tail_repair_can_be_disabled_without_mutation(self):
        self.event()
        damaged = self.ledger.path.read_bytes() + b'{"event_id":'
        self.ledger.path.write_bytes(damaged)
        report = self.recover(repair_truncated_tail=False)
        self.assertIs(report.action, ResumeAction.STOP_SECURITY)
        self.assertEqual(report.quarantined, ())
        self.assertEqual(self.ledger.path.read_bytes(), damaged)

    def test_complete_event_without_newline_is_ambiguous_not_repairable(self):
        self.event()
        self.event(event_type="CONFIRMATORY_STARTED", state=MacroState.CONFIRM)
        damaged = self.ledger.path.read_bytes().removesuffix(b"\n")
        self.ledger.path.write_bytes(damaged)
        result = self.manager.validate_ledger(self.ledger.relative_path)
        self.assertEqual(result.error, "AMBIGUOUS_FINAL_EVENT_WITHOUT_NEWLINE")
        self.assertFalse(result.recoverable_truncated_tail)
        self.assertIs(self.recover().action, ResumeAction.STOP_SECURITY)
        self.assertEqual(self.ledger.path.read_bytes(), damaged)

    def test_actual_registry_corruption_prevents_recovery(self):
        record = self.stored_artifact()
        self.event(record=record)
        self.assertTrue(self.manager.validate_artifacts(self.registry).valid)
        (self.root / record.relative_path).write_bytes(b"changed synthetic result")
        report = self.recover()
        self.assertIs(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.artifacts_valid)
        self.assertTrue(report.artifact_issues)
        self.assertEqual(report.replay_event_count, 0)

    def test_incomplete_file_quarantine_retains_bytes_and_metadata(self):
        source = self.root / "runs" / "draft.partial"
        source.parent.mkdir()
        content = b"synthetic interrupted output"
        source.write_bytes(content)
        record, = self.manager.quarantine_incomplete(("runs/draft.partial",))
        self.assertFalse(source.exists())
        self.assertEqual((self.root / record.quarantine_relative_path).read_bytes(), content)
        metadata = json.loads((self.root / record.metadata_relative_path).read_bytes())
        self.assertEqual(metadata["original_relative_path"], "runs/draft.partial")
        self.assertEqual(metadata["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(metadata["size_bytes"], len(content))
        self.assertEqual(metadata["reason"], "INCOMPLETE_WRITE")

    def test_explicit_quarantine_refuses_authoritative_or_nonpartial_input(self):
        for name, protected in (("bound.partial", ("bound.partial",)), ("finished.json", ())):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"retain this synthetic input")
                with self.assertRaises(RecoveryError):
                    self.manager.quarantine_incomplete((name,), protected_paths=protected)
                self.assertEqual(path.read_bytes(), b"retain this synthetic input")

    def test_automatic_quarantine_skips_protected_partial_and_completed_file(self):
        directory = self.root / "runs"
        directory.mkdir()
        for name in ("bound.partial", "draft.tmp", "completed.json"):
            (directory / name).write_bytes(name.encode())
        records = self.manager.quarantine_incomplete(protected_paths=("runs/bound.partial",))
        self.assertEqual(tuple(record.original_relative_path for record in records), ("runs/draft.tmp",))
        self.assertTrue((directory / "bound.partial").exists())
        self.assertTrue((directory / "completed.json").exists())

    def test_checkpoint_selection_uses_ledger_position_not_mtime_or_timestamp(self):
        first, second = self.event(), self.event(state=MacroState.CANDIDATE)
        older = self.manager.create_checkpoint(self.checkpoint_payload(
            first, checkpoint_id="older", created_at="2026-09-20T12:00:00Z"))
        newer = self.manager.create_checkpoint(self.checkpoint_payload(
            second, checkpoint_id="newer", created_at="2026-09-18T12:00:00Z"))
        os.utime(older, (2_000_000_000, 2_000_000_000))
        os.utime(newer, (1_000_000_000, 1_000_000_000))
        self.event(state=MacroState.CANDIDATE)
        report = self.recover()
        self.assertIs(report.action, ResumeAction.RESUME_FROM_CHECKPOINT)
        self.assertEqual(report.checkpoint.checkpoint["event_id"], second.event_id)
        self.assertEqual(report.checkpoint.ledger_event_index, 1)
        self.assertEqual(report.replay_event_count, 1)

    def test_checkpoint_artifact_projection_matches_actual_registry_metadata(self):
        record = self.stored_artifact()
        event = self.event(record=record)
        self.manager.create_checkpoint(self.checkpoint_payload(
            event, artifact_hashes={record.logical_type: record.sha256},
            artifact_record_hashes={record.logical_type: record.record_hash}))
        self.assertIs(self.recover().action, ResumeAction.RESUME_FROM_CHECKPOINT)
        # A distinct directory carries a validly hashed, wrong-metadata projection.
        self.manager.create_checkpoint(self.checkpoint_payload(
            event, artifact_hashes={record.logical_type: record.sha256},
            artifact_record_hashes={record.logical_type: "f" * 64}), checkpoint_dir="wrong-checkpoints")
        report = self.recover(checkpoint_dir="wrong-checkpoints")
        self.assertIs(report.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertIsNone(report.checkpoint)

    def test_checkpoint_for_absent_later_event_refuses_rolled_back_ledger(self):
        self.event()
        prefix = self.ledger.path.read_bytes()
        later = self.event()
        self.manager.create_checkpoint(self.checkpoint_payload(later))
        self.ledger.path.write_bytes(prefix)
        with self.assertRaisesRegex(LedgerValidationError, "possible ledger rollback"):
            self.manager.select_checkpoint(".scientist-one-build/checkpoints",
                                           self.manager.validate_ledger(self.ledger.relative_path))
        self.assertIs(self.recover().action, ResumeAction.STOP_SECURITY)
        self.assertEqual(self.ledger.path.read_bytes(), prefix)

    def test_checkpoint_is_immutable_and_rejects_inline_mutable_state(self):
        event = self.event()
        payload = self.checkpoint_payload(event)
        path = self.manager.create_checkpoint(payload)
        before = path.read_bytes()
        self.assertEqual(self.manager.create_checkpoint(payload), path)
        with self.assertRaises(RecoveryError):
            self.manager.create_checkpoint({**payload, "state": "CANDIDATE"})
        with self.assertRaisesRegex(RecoveryError, "inline mutable state"):
            self.manager.create_checkpoint({**payload, "cached_state": {"score": 100}})
        self.assertEqual(path.read_bytes(), before)

    def test_confirmatory_start_without_result_requires_new_study(self):
        self.event(event_type="CONFIRMATORY_STARTED", state=MacroState.CONFIRM)
        before = self.ledger.path.read_bytes()
        report = self.recover()
        self.assertIs(report.action, ResumeAction.NEW_STUDY_REQUIRED)
        self.assertTrue(report.confirmatory_touched)
        self.assertFalse(report.confirmatory_completed)
        self.assertFalse(report.resumable)
        self.assertEqual(report.replay_event_count, 0)
        self.assertIn("CONFIRMATORY_RERUN_PROHIBITED", report.reasons)
        self.assertEqual(self.ledger.path.read_bytes(), before)

    def test_completed_and_adverse_terminal_results_never_authorize_rerun(self):
        self.event(event_type="CONFIRMATORY_COMPLETED", state=MacroState.CONFIRM)
        for state in (MacroState.CONFIRM, TerminalState.NEGATIVE_RESULT, TerminalState.INCONCLUSIVE):
            with self.subTest(state=state):
                if state is not MacroState.CONFIRM:
                    self.event(state=state)
                before = self.ledger.path.read_bytes()
                report = self.recover()
                self.assertIs(report.action, ResumeAction.SKIP_COMPLETED)
                self.assertTrue(report.confirmatory_completed)
                self.assertFalse(report.resumable)
                self.assertEqual(report.replay_event_count, 0)
                called = []
                with self.assertRaises(ConfirmatoryRerunError):
                    self.manager.assert_confirmatory_run_allowed(
                        ledger_path=self.ledger.relative_path,
                        admission_callback=lambda: called.append("must not run"))
                self.assertEqual(called, [])
                self.assertEqual(self.ledger.path.read_bytes(), before)

    def test_synthetic_custody_access_prevents_fresh_plan_and_malformed_flags_fail(self):
        self.event()
        report = self.recover(custody_record={"authorized_access_count": 1, "revealed": True})
        self.assertIs(report.action, ResumeAction.NEW_STUDY_REQUIRED)
        self.assertTrue(report.confirmatory_touched)
        self.assertEqual(report.replay_event_count, 0)
        # Inert input mappings model recorded state, not independent custody authority.
        for mapping in ({"authorized_access_count": True}, {"revealed": "yes"}):
            with self.subTest(mapping=mapping):
                self.assertIs(self.recover(custody_record=mapping).action, ResumeAction.STOP_SECURITY)


if __name__ == "__main__":
    unittest.main()
