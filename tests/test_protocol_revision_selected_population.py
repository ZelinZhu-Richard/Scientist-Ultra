"""Real selected-prefix replay; no reserve, execution or scientific authority."""

from dataclasses import replace
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import scientific_protocol_revision as protocols
from scientist_one.roles import Role
from tests import test_scientific_protocol_revision as fixtures
from tests.test_scientific_design import _timeline_artifact


class ProtocolSelectedPopulationTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.ScientificProtocolRevisionTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        self.registry, self.ledger = self.case.registry, self.case.ledger
        self.publication = self.case.publish()
        self.sealed = self.case.snapshot()

    def replay(self, *, snapshots=None, publication=None):
        selected = self.sealed if snapshots is None else snapshots
        chosen = self.publication if publication is None else publication
        return protocols._validate_publication_at_snapshot(
            self.registry, self.ledger, record=chosen.protocol_record,
            registry_snapshot=selected[0], ledger_snapshot=selected[1],
            require_snapshot_local_dependencies=True,
        )

    def live(self):
        return protocols.require_scientific_protocol_revision(
            self.registry, self.ledger, expected_run_id=fixtures._RUN_ID,
            protocol_artifact_sha256=self.publication.protocol_record.sha256,
        )

    def correct(self, event):
        self.ledger.append_correction(
            event.event_id, actor_role=Role.PROTOCOL_DESIGNER,
            reason="Retract a non-authorizing source after its sealed prefix.",
            corrected_fields={"status": "RETRACTED"},
        )

    def test_selected_read_does_not_call_live_public_amendment_or_snapshot(self):
        with (
            mock.patch.object(protocols, "require_evaluation_contract_amendment",
                              side_effect=AssertionError("live amendment reader")),
            mock.patch.object(amendments, "_locked_checked_result_authority_snapshot",
                              side_effect=AssertionError("live paired snapshot")),
        ):
            self.assertEqual(self.replay(), self.publication)
        self.assertEqual(self.case.snapshot(), self.sealed)

    def test_later_amendment_correction_is_not_in_old_prefix_but_current_refuses(self):
        self.correct(self.case.amendment.event)
        current = self.case.snapshot()
        self.assertEqual(self.replay(), self.publication)
        for replay in (self.live, lambda: self.replay(snapshots=current)):
            with self.subTest(replay=replay):
                with self.assertRaisesRegex(protocols.ScientificProtocolRevisionError,
                                            "amendment source is invalid"):
                    replay()
        self.assertEqual(self.case.snapshot(), current)

    def test_later_protocol_correction_is_not_in_old_prefix_but_current_refuses(self):
        self.correct(self.publication.event)
        current = self.case.snapshot()
        self.assertEqual(self.replay(), self.publication)
        for replay in (self.live, lambda: self.replay(snapshots=current)):
            with self.subTest(replay=replay):
                with self.assertRaisesRegex(protocols.ScientificProtocolRevisionError,
                                            "stale or corrected"):
                    replay()
        self.assertEqual(self.case.snapshot(), current)

    def test_source_map_cannot_substitute_or_omit_amendment(self):
        amendment = self.case.amendment.amendment_record
        for records in (
            tuple(record for record in self.sealed[0].records if record != amendment),
            tuple(replace(record, origin="Substituted historical metadata", record_hash=None)
                  if record == amendment else record for record in self.sealed[0].records),
        ):
            with self.subTest(records=len(records)):
                with self.assertRaises(protocols.ScientificProtocolRevisionError):
                    self.replay(snapshots=(replace(self.sealed[0], records=records),
                                           self.sealed[1]))
        self.assertEqual(self.case.snapshot(), self.sealed)

    def test_selected_amendment_rejects_missing_event_and_wrong_run(self):
        for snapshot, run_id in (
            (replace(self.sealed[1], events=(), head_hash=None, valid_prefix_bytes=0),
             fixtures._RUN_ID),
            (self.sealed[1], "other-selected-run"),
        ):
            with self.subTest(run_id=run_id):
                with self.assertRaises(amendments.EvaluationContractAmendmentError):
                    amendments._require_evaluation_contract_amendment_at_snapshot(
                        self.registry, self.ledger,
                        registry_snapshot=self.sealed[0], ledger_snapshot=snapshot,
                        amendment_artifact_sha256=self.case.amendment.amendment_record.sha256,
                        expected_run_id=run_id,
                    )
        self.assertEqual(self.case.snapshot(), self.sealed)

    def test_live_manifest_population_is_explicitly_unsupported_in_sealed_only_mode(self):
        _timeline_artifact(
            self.registry, b'{"control":"inert, not a scientific manifest"}\n',
            "experiment_output_manifest", Role.ORCHESTRATOR,
        )
        current = self.case.snapshot()
        # Current legacy owner preserves its old unrelated-manifest behavior.
        self.assertEqual(self.live(), self.publication)
        self.assertEqual(self.replay(), self.publication)
        with self.assertRaisesRegex(protocols.ScientificProtocolRevisionError,
                                    "amendment source is invalid"):
            self.replay(snapshots=current)
        self.assertEqual(self.case.snapshot(), current)

    def test_two_generation_parent_replay_does_not_escape_selected_prefix(self):
        child = replace(self.case.child_contract,
                        version=self.case.child_contract.version + 1,
                        success_criteria=("Second non-authorizing criterion.",))
        second_amendment = amendments.register_evaluation_contract_amendment(
            self.registry, self.ledger, run_id=fixtures._RUN_ID,
            amendment_id="selected-population-a2",
            parent_contract_artifact_sha256=self.case.amendment.contract_record.sha256,
            child_contract=child, author_id=child.frozen_by,
            reason="Second non-authorizing protocol revision.",
        )
        second_protocol = replace(
            self.publication.protocol,
            study_version=self.publication.protocol.study_version + 1,
            parent_protocol_hash=self.publication.protocol.sha256,
            revision_reason=second_amendment.authority.amendment.reason,
        )
        second = protocols.register_scientific_protocol_revision(
            self.registry, self.ledger, expected_run_id=fixtures._RUN_ID,
            amendment_artifact_sha256=second_amendment.amendment_record.sha256,
            parent_protocol_artifact_sha256=self.publication.protocol_record.sha256,
            protocol=second_protocol,
        )
        selected = self.case.snapshot()
        self.correct(self.case.amendment.event)
        current = self.case.snapshot()
        with mock.patch.object(amendments, "_locked_checked_result_authority_snapshot",
                               side_effect=AssertionError("live paired snapshot")):
            self.assertEqual(self.replay(snapshots=selected, publication=second), second)
        with self.assertRaises(protocols.ScientificProtocolRevisionError):
            self.replay(snapshots=current, publication=second)
        self.assertEqual(self.case.snapshot(), current)

    def test_public_amendment_keeps_final_current_pair_readback(self):
        original = amendments._require_evaluation_contract_amendment_at_snapshot
        injected = None

        def actual_then_append(*args, **kwargs):
            nonlocal injected
            result = original(*args, **kwargs)
            _timeline_artifact(self.registry, b"real later registry entry\n",
                               "unrelated_selected_control", Role.ORCHESTRATOR)
            injected = self.case.snapshot()
            return result

        with mock.patch.object(amendments, "_require_evaluation_contract_amendment_at_snapshot",
                               side_effect=actual_then_append):
            with self.assertRaisesRegex(amendments.EvaluationContractAmendmentError,
                                        "changed during full readback"):
                amendments.require_evaluation_contract_amendment(
                    self.registry, self.ledger, expected_run_id=fixtures._RUN_ID,
                    amendment_artifact_sha256=self.case.amendment.amendment_record.sha256,
                )
        self.assertIsNotNone(injected)
        self.assertEqual(self.case.snapshot(), injected)


if __name__ == "__main__":
    unittest.main()
