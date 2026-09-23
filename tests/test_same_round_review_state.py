"""Mechanical/negative shared-state controls, without scientific review reuse."""

import ast
from dataclasses import FrozenInstanceError, replace
import inspect
import unittest

from scientist_one import research_state as rs
from scientist_one.errors import ValidationError
from tests import test_snapshot_reference_replay as fixtures


class SameRoundReviewStateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SnapshotReferenceReplayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.ledger = self.fixture.registry, self.fixture.ledger
        self.state = self.fixture.state
        snapshots = rs._locked_research_state_source_snapshot(
            self.registry, self.ledger, run_id=self.state.run_id,
        )
        # Empty cache only. No completed scientific owner is fabricated.
        self.replay = rs._SameRoundReviewReplay(
            run_id=self.state.run_id, code_version=self.state.code_version,
            configuration_hash=self.state.configuration_hash,
            before_event_index=snapshots[1].event_count,
            registry_snapshot=snapshots[0], ledger_snapshot=snapshots[1], reviews=(),
        )

    def _bound(self, replay=None, **changes):
        arguments = dict(
            run_id=self.state.run_id,
            snapshot_artifact_hash=self.state.snapshot_artifact_sha256,
            state_artifact_hashes=tuple(item.artifact_sha256 for item in self.state.entries),
            ledger_head_hash=self.state.ledger_head_hash,
            ledger_event_count=self.state.ledger_event_count,
            expected_code_version=self.state.code_version,
            expected_configuration_hash=self.state.configuration_hash,
            _review_replay=self.replay if replay is None else replay,
        )
        arguments.update(changes)
        return rs._resolve_bound_research_state_authority(self.registry, self.ledger, **arguments)

    def test_empty_private_context_preserves_actual_mechanical_bound_owner(self):
        before = (self.registry.list_records(), self.ledger.events())
        self.assertEqual(self._bound(), self.state)
        self.assertEqual(self.fixture._bound(), self.state)
        self.assertTrue(all(not item.scientific_evidence_eligible for item in self.state.entries))
        self.assertEqual((self.registry.list_records(), self.ledger.events()), before)

    def test_append_invalidates_ephemeral_context_not_ordinary_historical_state(self):
        self.fixture._append()
        before = (self.registry.list_records(), self.ledger.events())
        with self.assertRaisesRegex(ValidationError, "sources changed during replay"):
            self._bound()
        self.assertEqual(self.fixture._bound(), self.state)
        self.assertEqual((self.registry.list_records(), self.ledger.events()), before)

    def test_private_context_cannot_change_bound_identity(self):
        with self.assertRaisesRegex(ValidationError, "identity changed"):
            self._bound(expected_code_version="substituted-code")
        with self.assertRaisesRegex(ValidationError, "run was substituted"):
            self._bound(replay=replace(self.replay, run_id="another-run"))

    def test_full_snapshot_fields_are_still_checked(self):
        with self.assertRaisesRegex(ValidationError, "issuance identity differs"):
            self._bound(ledger_event_count=self.state.ledger_event_count + 1)
        with self.assertRaisesRegex(ValidationError, "immutable snapshot"):
            self._bound(state_artifact_hashes=("a" * 64,))

    def test_context_is_frozen_bounded_and_chronological(self):
        with self.assertRaises(FrozenInstanceError):
            self.replay.reviews = ()
        for value in (True, 0, self.replay.ledger_snapshot.event_count + 1):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                replace(self.replay, before_event_index=value)
        with self.assertRaises(ValidationError):
            replace(self.replay, reviews=[])

    def test_core_object_cannot_be_reused_as_review(self):
        entry = self.state.entries[0]
        inert = rs._ReplayedCanonicalReview(
            research_object=entry.research_object,
            artifact=self.registry.get_metadata(entry.artifact_sha256),
            authority_records=(), materialization_event_index=entry.materialization_event_index,
        )
        with self.assertRaisesRegex(ValidationError, "exact earlier review"):
            replace(self.replay, reviews=(inert,))

    def test_public_apis_do_not_accept_reuse_or_callbacks(self):
        for function in (rs.resolve_bound_research_state_authority,
                         rs.resolve_current_research_state_bindings):
            self.assertNotIn("_review_replay", inspect.signature(function).parameters)
            tree = ast.parse(inspect.getsource(function))
            self.assertFalse(any(
                keyword.arg == "_review_replay" for node in ast.walk(tree)
                if isinstance(node, ast.Call) for keyword in node.keywords
            ))

    def test_both_scoped_authority_sites_use_same_exact_private_resolver(self):
        tree = ast.parse(inspect.getsource(rs._resolve_current_research_state_bindings))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == "_resolve_object_with_replayed_review"]
        self.assertEqual(len(calls), 2)
        self.assertEqual({node.args[1].id for node in calls}, {"item", "current_item"})
        source = inspect.getsource(rs._resolve_object_with_replayed_review)
        self.assertIn("_validate_canonical_ancestry_budget", source)
        self.assertIn("_authority_records", source)
        self.assertIn("_matching_scoped_materialization_events", source)
        self.assertNotIn("scientific_evidence_eligible=True", source)


if __name__ == "__main__":
    unittest.main()
