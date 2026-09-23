"""Real mechanical snapshot replay; no positive scientific source or audit."""

import ast
from dataclasses import replace
import inspect
import unittest

from scientist_one import research_state as rs
from scientist_one.errors import ValidationError
from scientist_one.roles import Role
from tests import test_vnext_state as fixtures


class SnapshotReferenceReplayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ResearchStateRepositoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.repository = self.fixture.repository
        self.registry, self.ledger = self.fixture.registry, self.fixture.ledger
        self.materialized = self.repository.materialize(self.fixture.question("descriptive-only-question"))
        self.snapshot = rs.register_research_state_snapshot(
            self.repository, snapshot_id="mechanical-snapshot", created_at=fixtures.STAMP_2,
            fixture_notice="Mechanical state only; no scientific claim or audit authority.",
        )
        self.state = self._current()
        self.assertTrue(all(item.scientific_evidence_eligible is False for item in self.state.entries))

    def _current(self):
        return rs.resolve_research_state_authority(
            self.registry, self.ledger, run_id="run-1", snapshot_artifact_hash=self.snapshot.sha256,
        )

    def _bound(self):
        return rs.resolve_bound_research_state_authority(
            self.registry, self.ledger, run_id="run-1", snapshot_artifact_hash=self.snapshot.sha256,
            state_artifact_hashes=tuple(item.artifact_sha256 for item in self.state.entries),
            ledger_head_hash=self.state.ledger_head_hash, ledger_event_count=self.state.ledger_event_count,
            expected_code_version=self.state.code_version,
            expected_configuration_hash=self.state.configuration_hash,
        )

    def _append(self, *, metadata=None, event_id="later-source-reference", artifacts=None,
                timestamp="2026-08-29T12:00:02Z"):
        previous = self.ledger.events()[-1]
        return self.ledger.record(
            run_id=previous.run_id, actor_role=Role.ADVERSARIAL_REVIEWER,
            state_before=previous.state_after, requested_state_after=previous.state_after,
            artifact_hashes=(self.snapshot.sha256,) if artifacts is None else artifacts,
            code_version=previous.code_version, configuration_hash=previous.configuration_hash,
            reason="Non-authoritative downstream reference to an already-issued snapshot.",
            event_id=event_id, timestamp=timestamp, event_type="CHECKPOINT",
            metadata={} if metadata is None else metadata,
        )

    def test_later_reference_preserves_full_current_bound_and_idempotent_snapshot_replay(self):
        self._append(metadata={"source_reference": self.snapshot.sha256})
        before = (self.registry.list_records(), self.ledger.validate(raise_on_error=True))
        self.assertEqual(self._current(), self.state)
        self.assertEqual(self._bound(), self.state)
        self.assertEqual(rs.register_research_state_snapshot(
            self.repository, snapshot_id="mechanical-snapshot", created_at=fixtures.STAMP_2,
            fixture_notice="Mechanical state only; no scientific claim or audit authority.",
        ), self.snapshot)
        self.assertEqual((self.registry.list_records(), self.ledger.validate(raise_on_error=True)), before)

    def test_nested_audit_reference_is_not_snapshot_reissuance_or_valid_audit(self):
        # This deliberately malformed audit marker grants no audit authority.
        # Snapshot ownership must not recursively validate its future consumer.
        self._append(metadata={"semantic_challenger_audit_slot": {
            "research_state_snapshot_artifact_hash": self.snapshot.sha256,
            "notice": "Not an issued or valid audit slot",
        }})
        self.assertEqual(self._bound(), self.state)
        from scientist_one.gates import require_semantic_challenger_audit_slot
        with self.assertRaises(ValidationError):
            require_semantic_challenger_audit_slot(
                self.registry, self.ledger, slot_id="absent-authority", expected_run_id="run-1",
            )

    def test_competing_explicit_snapshot_issuance_refuses(self):
        self._append(metadata={"research_state_operation": "SNAPSHOT_ISSUED",
                               "snapshot_artifact_hash": self.snapshot.sha256})
        for owner in (self._current, self._bound):
            with self.assertRaisesRegex(ValidationError, "ambiguous ledger admissions"):
                owner()

    def test_damaged_operation_or_reserved_issuance_markers_cannot_be_references(self):
        for key in ("research_state_operation", "snapshot_artifact_record_hash", "snapshot_id",
                    "snapshot_issued_at", "snapshot_logical_type", "snapshot_schema_version"):
            fixture = SnapshotReferenceReplayTests()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            fixture._append(metadata={key: "DAMAGED"})
            with self.subTest(key=key), self.assertRaisesRegex(ValidationError, "ambiguous ledger admissions"):
                fixture._bound()

    def test_top_level_subject_without_artifact_list_and_rss_alias_refuse(self):
        self._append(metadata={"snapshot_artifact_hash": self.snapshot.sha256}, artifacts=())
        with self.assertRaisesRegex(ValidationError, "ambiguous ledger admissions"):
            self._bound()
        fixture = SnapshotReferenceReplayTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._append(event_id="rss-damaged-alias")
        with self.assertRaisesRegex(ValidationError, "ambiguous ledger admissions"):
            fixture._bound()

    def test_backdated_source_reference_refuses_but_unrelated_backdating_is_unchanged(self):
        self._append(artifacts=(), timestamp=fixtures.STAMP)
        self.assertEqual(self._bound(), self.state)
        self._append(event_id="backdated-S-reference", timestamp=fixtures.STAMP)
        with self.assertRaisesRegex(ValidationError, "reference predates issuance"):
            self._bound()

    def test_exact_issuance_event_remains_mandatory_after_later_reference(self):
        self._append()
        record, _hashes, _types, value = rs._read_canonical_research_state_snapshot(self.registry, self.snapshot.sha256)
        ledger_result = self.ledger.validate(raise_on_error=True)
        events = list(ledger_result.events)
        index = self.state.ledger_event_count - 1
        events[index] = replace(events[index], reason="substituted issuance reason", event_hash=None)
        # Deliberately inert aggregate. The exact event-equality check is
        # exercised directly; this is not a valid issued ledger or science.
        with self.assertRaisesRegex(ValidationError, "issuance event was substituted"):
            rs._require_research_state_snapshot_issuance(
                replace(ledger_result, events=tuple(events)), snapshot_record=record, snapshot_value=value,
            )

    def test_direct_subject_selector_is_shared_by_both_prepublication_collision_checks(self):
        event = self.ledger.events()[-1]
        subject_only = replace(event, artifact_hashes=(), metadata={"snapshot_artifact_hash": self.snapshot.sha256}, event_hash=None)
        nested = replace(event, artifact_hashes=(), metadata={"consumer": {"snapshot_artifact_hash": self.snapshot.sha256}}, event_hash=None)
        prior = replace(event, artifact_hashes=(), metadata={"prior_snapshot_artifact_hash": self.snapshot.sha256}, event_hash=None)
        self.assertTrue(rs._event_names_research_state_snapshot(subject_only, self.snapshot.sha256))
        self.assertFalse(rs._event_names_research_state_snapshot(nested, self.snapshot.sha256))
        self.assertFalse(rs._event_names_research_state_snapshot(prior, self.snapshot.sha256))
        source = ast.parse(inspect.getsource(rs.register_research_state_snapshot))
        calls = [item for item in ast.walk(source) if isinstance(item, ast.Call)
                 and isinstance(item.func, ast.Name) and item.func.id == "_event_names_research_state_snapshot"]
        self.assertEqual(len(calls), 2)

    def test_reference_does_not_override_later_issuance_revocation(self):
        self._append()
        self.ledger.append_correction(
            f"rss-{self.snapshot.sha256[:48]}", actor_role=Role.ORCHESTRATOR,
            reason="Withdraw the mechanical snapshot, not a scientific approval.",
            corrected_fields={"authority": "WITHDRAWN"}, event_id="withdraw-snapshot",
            timestamp="2026-08-29T12:00:03Z",
        )
        with self.assertRaisesRegex(ValidationError, "issuance was later corrected"):
            self._bound()


if __name__ == "__main__":
    unittest.main()
