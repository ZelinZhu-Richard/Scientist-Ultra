"""Actual crash-prefix recovery and retained-native-attempt denial checks.

This private overlay exercises the amendment writer against a real temporary
registry, ledger, resource-authority chain, and native custody fixture.  The
faults run after the real registry writes; no successful publication or native
observation is mocked.  Run-tree copies are confined to each fixture's own
temporary root and are restored before fixture cleanup.
"""

from dataclasses import replace
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
import tests.test_simulated_observation as fixture


from tests.test_resource_prepared_cases import (
    prepared_observed_tests,
)


@prepared_observed_tests
class OrphanGuardTests(unittest.TestCase):
    """Exercise exact A-only/A+C prefixes, recovery, and post-T refusal."""

    def setUp(self):
        self.case = fixture.SimulatedObservationTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()

    @staticmethod
    def _fresh_readers(case):
        registry_base = case.registry.base_path
        ledger_path = case.ledger.relative_path
        case.registry = case.case.registry = ArtifactRegistry(
            case.root, base_path=registry_base
        )
        case.ledger = case.case.ledger = EventLedger(case.root, ledger_path)

    @staticmethod
    def _amend(case, registry=None, ledger=None):
        parent = case.reservation.contract
        return amendments.register_evaluation_contract_amendment(
            registry if registry is not None else case.registry,
            ledger if ledger is not None else case.ledger,
            run_id=case.case.run,
            amendment_id="post-native-observation-v1-probe",
            parent_contract_artifact_sha256=case.reservation.contract_record.sha256,
            child_contract=replace(
                parent,
                version=parent.version + 1,
                success_criteria=("Changed after actual native observation.",),
            ),
            author_id=parent.frozen_by,
            reason="Negative-only default amendment boundary after native observation",
        )

    @staticmethod
    def _registry_write_fault(phase):
        """Raise only after the selected real amendment record is written."""

        original = ArtifactRegistry._put_bytes_locked
        amendment_type = amendments.EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE

        def interrupted(registry, guard, data, **kwargs):
            record = original(registry, guard, data, **kwargs)
            logical_type = kwargs["logical_type"]
            if phase == "a-only" and logical_type == amendment_type:
                raise OSError("actual post-write A interruption")
            if phase == "a-plus-c" and logical_type == "evaluation_contract":
                raise OSError("actual post-write A+C interruption")
            return record

        return mock.patch.object(
            ArtifactRegistry, "_put_bytes_locked", new=interrupted
        )

    def _make_orphan(self, case, phase):
        """Create an actual persisted prefix and return its before/orphan state."""

        before = case.snapshot()
        external_before = case.case.files()
        external_chain_before = tuple(case.case.external())
        with self._registry_write_fault(phase):
            with self.assertRaises(amendments.EvaluationContractAmendmentError) as raised:
                self._amend(case)
        self.assertIsNotNone(raised.exception.__cause__)
        self.assertIsInstance(raised.exception.__cause__.__cause__, OSError)
        orphan = case.snapshot()
        expected_records = before[0][0].count + (1 if phase == "a-only" else 2)
        self.assertEqual(orphan[0][0].count, expected_records)
        self.assertEqual(orphan[0][1].event_count, before[0][1].event_count)
        self.assertEqual(case.case.files(), external_before)
        self.assertEqual(tuple(case.case.external()), external_chain_before)
        return before, orphan, external_before, external_chain_before

    def _assert_recovered(self, phase):
        case = self.case
        before, orphan, external_before, external_chain_before = self._make_orphan(case, phase)
        # Restart from durable registry/ledger readers before attempting the
        # exact recovery path.  This also proves the orphan is not an in-memory
        # patch artifact.
        self._fresh_readers(case)
        self.assertEqual(case.snapshot(), orphan)
        publication = self._amend(case)
        after = case.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 2)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertFalse(publication.authority.amendment.results_already_seen)
        self.assertFalse(publication.authority.amendment.requires_new_confirmatory_reserve)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertEqual(case.case.files(), external_before)
        self.assertEqual(tuple(case.case.external()), external_chain_before)

        # A completed exact publication is idempotent and must not charge or
        # touch the external I/Q bytes on replay.
        replay_before = case.snapshot(), case.case.files()
        repeated = self._amend(case)
        self.assertEqual(repeated, publication)
        self.assertEqual((case.snapshot(), case.case.files()), replay_before)

    def test_a_only_native_registry_orphan_recovers_without_repeat_charge(self):
        self._assert_recovered("a-only")

    def test_a_plus_c_native_registry_orphan_recovers_without_repeat_charge(self):
        self._assert_recovered("a-plus-c")

    def _assert_retained_t_refuses(self, phase):
        case = self.case
        run_path = case.root / "runs" / case.case.run
        with tempfile.TemporaryDirectory(prefix="orphan-guard-run-rollback-") as raw:
            backup = Path(raw)
            pre_orphan = backup / "pre-orphan-run"
            orphan = backup / "orphan-run"
            shutil.copytree(run_path, pre_orphan)
            self._make_orphan(case, phase)
            shutil.copytree(run_path, orphan)

            # Restore the exact pre-orphan run subtree and execute one actual
            # native J through the retained frozen owner.  External I/Q/T and
            # custody journal state live outside this run-tree rollback.
            run_path.rename(backup / "orphan-live-run")
            shutil.copytree(pre_orphan, run_path)
            self._fresh_readers(case)
            prep = case.prepare()
            result = case.run_observation(prep)
            self.assertEqual(result.record.logical_type, "simulated_reserve_observation")
            external_after_t = tuple(case.case.external())
            self.assertEqual(len(external_after_t), 3)
            self.assertEqual(external_after_t[-1]["sequence"], 2)
            journal_after_t = case.snapshot()[2]
            self.assertIsInstance(journal_after_t, bytes)

            # Reinstall the exact orphan bytes with fresh readers while
            # leaving external custody/resource state at retained T.
            run_path.rename(backup / "completed-j-run")
            shutil.copytree(orphan, run_path)
            self._fresh_readers(case)
            orphan_pair = case.snapshot()
            before_retry = (orphan_pair, case.case.files(), journal_after_t)
            with self.assertRaisesRegex(
                amendments.EvaluationContractAmendmentError,
                "simulated external attempt or unsupported successor",
            ):
                self._amend(case)
            after_retry = (case.snapshot(), case.case.files(), case.snapshot()[2])
            self.assertEqual(after_retry, before_retry)
            self.assertEqual(tuple(case.case.external()), external_after_t)
            self.assertEqual(case.snapshot()[2], journal_after_t)

    def test_a_only_orphan_after_retained_t_refuses_without_mutation(self):
        self._assert_retained_t_refuses("a-only")

    def test_a_plus_c_orphan_after_retained_t_refuses_without_mutation(self):
        self._assert_retained_t_refuses("a-plus-c")
