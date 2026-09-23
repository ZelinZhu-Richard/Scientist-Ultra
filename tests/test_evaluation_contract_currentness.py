"""Current-use lineage checks, not reserve or scientific authority fixtures."""

from dataclasses import replace
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as owner
from scientist_one.errors import LedgerError
from scientist_one.models import MacroState
from scientist_one.roles import Role
from tests import test_evaluation_contract_amendment as fixtures


class EvaluationContractCurrentnessTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.EvaluationContractAmendmentTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        self.registry = self.case.registry
        self.ledger = self.case.ledger

    def snapshot(self):
        return self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid()

    def current(self, record=None, *, run_id=fixtures._RUN_ID):
        return owner._require_current_evaluation_contract_lineage(
            self.registry, self.ledger, expected_run_id=run_id,
            contract_artifact_sha256=(record or self.case.parent_record).sha256,
        )

    def append_unrelated(self):
        events = self.ledger.events()
        state = events[-1].requested_state_after if events else MacroState.GROUND
        return self.ledger.append_event(
            run_id=fixtures._RUN_ID, actor_role=Role.ORCHESTRATOR,
            state_before=state, requested_state_after=state,
            artifact_hashes=(), code_version="NON_EVIDENTIARY_CURRENTNESS_TEST",
            configuration_hash="c" * 64, event_type="CHECKPOINT",
            reason="Unrelated native event for paired-readback control.",
        )

    def test_fresh_parent_returns_exact_readonly_source_pair(self):
        before = self.snapshot()
        result = self.current()
        self.assertEqual(result.contract_record, self.case.parent_record)
        self.assertEqual(result.contract, self.case.parent)
        self.assertEqual((result.registry_snapshot, result.ledger_snapshot), before)
        self.assertIsNone(result.selected_amendment_artifact_sha256)
        self.assertEqual(self.snapshot(), before)

    def test_completed_child_is_current_but_parent_stays_historically_readable(self):
        publication = self.case.publish()
        before = self.snapshot()
        historical = owner._require_evaluation_contract_child_lineage(
            self.registry, self.ledger, expected_run_id=fixtures._RUN_ID,
            contract_artifact_sha256=self.case.parent_record.sha256,
        )
        self.assertEqual(historical.contract_record, self.case.parent_record)
        with self.assertRaisesRegex(owner.EvaluationContractAmendmentError, "superseded"):
            self.current()
        current = self.current(publication.contract_record)
        self.assertEqual(current.contract, publication.child_contract)
        self.assertEqual(
            current.selected_amendment_artifact_sha256,
            publication.amendment_record.sha256,
        )
        self.assertEqual(self.snapshot(), before)

    def test_only_exact_latest_descendant_is_current_across_two_amendments(self):
        first = self.case.publish()
        second = owner.register_evaluation_contract_amendment(
            self.registry, self.ledger, run_id=fixtures._RUN_ID,
            amendment_id="amendment-2",
            parent_contract_artifact_sha256=first.contract_record.sha256,
            child_contract=replace(
                first.child_contract, version=first.child_contract.version + 1,
                success_criteria=("Another declared non-authorizing criterion.",),
            ),
            author_id=first.child_contract.frozen_by,
            reason="Record the second prospective contract change.",
            child_evidence_parent_artifact_sha256s=(self.case.evidence.sha256,),
        )
        before = self.snapshot()
        for old in (self.case.parent_record, first.contract_record):
            with self.subTest(old=old.sha256):
                with self.assertRaisesRegex(
                    owner.EvaluationContractAmendmentError, "superseded",
                ):
                    self.current(old)
        self.assertEqual(self.current(second.contract_record).contract_record,
                         second.contract_record)
        for publication in (first, second):
            self.assertEqual(owner.require_evaluation_contract_amendment(
                self.registry, self.ledger,
                amendment_artifact_sha256=publication.amendment_record.sha256,
                expected_run_id=fixtures._RUN_ID,
            ), publication)
        self.assertEqual(self.snapshot(), before)

    def test_incomplete_actual_child_publication_prevents_new_parent_use(self):
        before_publication = self.snapshot()
        with mock.patch.object(self.ledger, "_append_locked",
                               side_effect=LedgerError("interrupted publication")):
            with self.assertRaisesRegex(LedgerError, "interrupted publication"):
                self.case.publish()
        before = self.snapshot()
        self.assertEqual(before[0].count, before_publication[0].count + 2)
        self.assertEqual(before[1], before_publication[1])
        with self.assertRaisesRegex(owner.EvaluationContractAmendmentError, "incomplete"):
            self.current()
        self.assertEqual(self.snapshot(), before)
        publication = self.case.publish()
        self.assertEqual(self.current(publication.contract_record).contract_record,
                         publication.contract_record)

    def test_competing_unamended_root_is_not_a_current_contract(self):
        self.case.inert_contract_record(self.case.child())
        before = self.snapshot()
        with self.assertRaisesRegex(owner.EvaluationContractAmendmentError,
                                    "competing unamended roots"):
            self.current()
        self.assertEqual(self.snapshot(), before)

    def test_unrelated_history_at_entry_is_allowed_but_wrong_run_is_not(self):
        publication = self.case.publish()
        self.append_unrelated()
        before = self.snapshot()
        self.assertEqual(self.current(publication.contract_record).contract_record,
                         publication.contract_record)
        with self.assertRaisesRegex(owner.EvaluationContractAmendmentError, "another run"):
            self.current(publication.contract_record, run_id="different-run")
        self.assertEqual(self.snapshot(), before)

    def test_change_before_inner_owner_does_not_replace_outer_entry_pair(self):
        original = owner._require_evaluation_contract_child_lineage
        after_injection = None

        def actual_replay_after_append(*args, **kwargs):
            nonlocal after_injection
            self.append_unrelated()
            after_injection = self.snapshot()
            return original(*args, **kwargs)

        with mock.patch.object(owner, "_require_evaluation_contract_child_lineage",
                               side_effect=actual_replay_after_append):
            with self.assertRaisesRegex(owner.EvaluationContractAmendmentError,
                                        "changed during full readback"):
                self.current()
        self.assertIsNotNone(after_injection)
        self.assertEqual(self.snapshot(), after_injection)

    def test_change_after_actual_successor_check_is_refused_on_final_pair(self):
        original = owner._require_no_completed_contract_successor_before
        after_injection = None

        def actual_check_then_append(*args, **kwargs):
            nonlocal after_injection
            result = original(*args, **kwargs)
            self.append_unrelated()
            after_injection = self.snapshot()
            return result

        with mock.patch.object(owner, "_require_no_completed_contract_successor_before",
                               side_effect=actual_check_then_append):
            with self.assertRaisesRegex(owner.EvaluationContractAmendmentError,
                                        "changed during full readback"):
                self.current()
        self.assertIsNotNone(after_injection)
        self.assertEqual(self.snapshot(), after_injection)


if __name__ == "__main__":
    unittest.main()
