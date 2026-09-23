"""Private v2 amendment orphan and custody-boundary tests.

The fixture performs one actual native J1 observation in a real temporary
project.  A/A+C faults are raised only after the real registry writes.  The
tests do not manufacture an observation, authority, result, or successful
publication; every refusal is checked for a zero-delta durable retry.
"""

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import orchestrator
from scientist_one import simulated_observation as observation
from scientist_one import simulated_resource as resource
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import utc_now
from scientist_one.roles import Role
import tests.test_simulated_observation as fixture


from tests.test_resource_prepared_cases import (
    prepared_observed_tests, verify_observed_amendment_source, observed_orphan_variants,
)


@prepared_observed_tests
class ObservedContractV2OrphanTests(unittest.TestCase):
    """Check explicit-J v2 crash prefixes and refusal boundaries."""

    _AMENDMENT_ID = "post-native-observation-v2-orphan-probe"
    _REASON = "Negative-only v2 amendment boundary after native observation"

    def setUp(self):
        self.case = fixture.SimulatedObservationTests()
        self.addCleanup(self.case.doCleanups)
        self._set_up_case(self.case)

    def _new_case(self):
        case = fixture.SimulatedObservationTests()
        self.addCleanup(case.doCleanups)
        self._set_up_case(case)
        return case

    @staticmethod
    def _set_up_case(case):
        """Include the exact loaded A2 owner in the original I inventory."""

        original = resource.register_simulated_resource_initial_inventories

        def register_with_amendment_source(registry, *args, **kwargs):
            # Parent prepared the actual A owner before normal capture.
            verify_observed_amendment_source(registry, amendments)
            return original(registry, *args, **kwargs)

        with mock.patch.object(
            resource,
            "register_simulated_resource_initial_inventories",
            new=register_with_amendment_source,
        ):
            case.setUp()

    @staticmethod
    def _fresh_readers(case):
        registry_base = case.registry.base_path
        ledger_path = case.ledger.relative_path
        case.registry = case.case.registry = ArtifactRegistry(
            case.root, base_path=registry_base
        )
        case.ledger = case.case.ledger = EventLedger(case.root, ledger_path)

    @classmethod
    def _native_j_request(cls, case):
        """Run actual J1, then construct the explicit post-J C2 request."""

        actual_j = case.run_observation(case.prepare())
        parent = actual_j.preparation.charge.reservation.contract
        child = replace(
            parent,
            version=parent.version + 1,
            frozen_at=utc_now(),
            success_criteria=("Changed after actual native observation.",),
        )
        return actual_j, parent, child

    @classmethod
    def _amend(cls, case, actual_j, parent, child):
        return amendments.register_evaluation_contract_amendment(
            case.registry,
            case.ledger,
            run_id=case.case.run,
            amendment_id=cls._AMENDMENT_ID,
            parent_contract_artifact_sha256=(
                actual_j.preparation.charge.reservation.contract_record.sha256
            ),
            child_contract=child,
            author_id=parent.frozen_by,
            reason=cls._REASON,
            observation_artifact_sha256s=(actual_j.record.sha256,),
        )

    @staticmethod
    def _registry_write_fault(phase):
        """Raise after actual A or C bytes/metadata have been persisted."""

        original = ArtifactRegistry._put_bytes_locked
        amendment_type = amendments.EVALUATION_CONTRACT_AMENDMENT_LOGICAL_TYPE

        def interrupted(registry, guard, data, **kwargs):
            record = original(registry, guard, data, **kwargs)
            logical_type = kwargs["logical_type"]
            if phase == "a-only" and logical_type == amendment_type:
                raise OSError("actual post-write v2 A interruption")
            if phase == "a-plus-c" and logical_type == "evaluation_contract":
                raise OSError("actual post-write v2 A+C interruption")
            return record

        return mock.patch.object(
            ArtifactRegistry, "_put_bytes_locked", new=interrupted
        )

    @staticmethod
    def _exception_text(error):
        values = []
        current = error
        while current is not None:
            values.append(str(current))
            current = current.__cause__
        return " | ".join(values)

    def _make_orphan(self, case, actual_j, parent, child, phase):
        before = case.snapshot()
        external_before = tuple(case.case.external())
        with self._registry_write_fault(phase):
            with self.assertRaises(Exception) as raised:
                self._amend(case, actual_j, parent, child)
        self.assertIn("actual post-write v2", self._exception_text(raised.exception))
        orphan = case.snapshot()
        expected_delta = 1 if phase == "a-only" else 2
        self.assertEqual(orphan[0][0].count, before[0][0].count + expected_delta)
        self.assertEqual(orphan[0][1].event_count, before[0][1].event_count)
        self.assertEqual(orphan[1], before[1])
        self.assertEqual(orphan[2], before[2])
        self.assertEqual(tuple(case.case.external()), external_before)
        return before, orphan, external_before

    def _assert_recovered(self, phase):
        case = self.case
        actual_j, parent, child = self._native_j_request(case)
        before, orphan, external_before = self._make_orphan(
            case, actual_j, parent, child, phase
        )
        self._fresh_readers(case)
        self.assertEqual(case.snapshot(), orphan)

        publication = self._amend(case, actual_j, parent, child)
        after = case.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 2)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(
            publication.authority.schema_version,
            amendments.EVALUATION_CONTRACT_OBSERVED_AMENDMENT_SCHEMA,
        )
        self.assertEqual(
            tuple(item.observation_artifact_sha256
                  for item in publication.authority.observed_controls),
            (actual_j.record.sha256,),
        )
        self.assertTrue(publication.authority.amendment.results_already_seen)
        self.assertTrue(publication.authority.amendment.requires_new_confirmatory_reserve)
        self.assertFalse(publication.authority.confirmation_authorized)
        self.assertEqual(case.case.files(), before[1])
        self.assertEqual(tuple(case.case.external()), external_before)
        self.assertEqual(case.snapshot()[2], before[2])

        replay_before = case.snapshot()
        repeated = self._amend(case, actual_j, parent, child)
        self.assertEqual(repeated, publication)
        self.assertEqual(case.snapshot(), replay_before)

    def test_a_only_v2_orphan_recovers_exactly_and_is_idempotent(self):
        self._assert_recovered("a-only")

    def test_a_plus_c_v2_orphan_recovers_exactly_and_is_idempotent(self):
        self._assert_recovered("a-plus-c")

    def _assert_refusal_without_delta(self, case, actual_j, parent, child, mutate):
        _before, _orphan, external_after_j = self._make_orphan(
            case, actual_j, parent, child, "a-only"
        )
        mutate(case, child)
        self._fresh_readers(case)
        before_retry = case.snapshot()
        external_before_retry = tuple(case.case.external())
        with self.assertRaises(Exception) as raised:
            self._amend(case, actual_j, parent, child)
        self.assertIsInstance(
            raised.exception, amendments.EvaluationContractAmendmentError
        )
        after_retry = case.snapshot()
        self.assertEqual(after_retry, before_retry)
        self.assertEqual(case.case.files(), before_retry[1])
        self.assertEqual(case.snapshot()[2], before_retry[2])
        self.assertEqual(tuple(case.case.external()), external_before_retry)
        self.assertEqual(tuple(case.case.external()), external_after_j)

    def test_v2_orphan_refuses_competing_source_event_and_child_metadata(self):
        mutations = (
            (
                "source",
                lambda case, _child: case.note(
                    {"kind": "competing source append after v2 A orphan"}
                ),
            ),
            (
                "event",
                lambda case, _child: case.case.note(
                    {"kind": "competing event append after v2 A orphan"}
                ),
            ),
            (
                "orphan-metadata",
                lambda case, child: case.registry.put_bytes(
                    amendments._child_bytes(child),
                    logical_type="inert_competing_contract_metadata",
                    origin="v2 orphan metadata collision test",
                    creator_role=Role.ORCHESTRATOR,
                ),
            ),
        )
        for index, (label, mutate) in observed_orphan_variants(mutations):
            with self.subTest(mutation=label):
                # Each ordered variant has its own captured setup/root.
                case = self.case
                actual_j, parent, child = self._native_j_request(case)
                self._assert_refusal_without_delta(
                    case, actual_j, parent, child, mutate
                )

    def test_v2_orphan_refuses_actual_native_journal_inode_drift(self):
        case = self.case
        actual_j, parent, child = self._native_j_request(case)
        self._make_orphan(case, actual_j, parent, child, "a-only")
        journal_path = case.root / observation._journal_path(case.charge)
        journal_bytes = journal_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix="v2-journal-drift-") as raw:
            displaced = Path(raw) / "original-journal"
            journal_mode = journal_path.stat().st_mode & 0o777
            journal_path.replace(displaced)
            journal_path.write_bytes(journal_bytes)
            os.chmod(journal_path, journal_mode)
            self._fresh_readers(case)
            before_retry = case.snapshot()
            external_before_retry = tuple(case.case.external())
            inode_before_retry = journal_path.stat().st_ino
            with self.assertRaises(Exception) as raised:
                self._amend(case, actual_j, parent, child)
            self.assertIn("custody", self._exception_text(raised.exception).lower())
            self.assertEqual(case.snapshot(), before_retry)
            self.assertEqual(tuple(case.case.external()), external_before_retry)
            self.assertEqual(journal_path.read_bytes(), journal_bytes)
            self.assertEqual(journal_path.stat().st_ino, inode_before_retry)

    def test_completed_v2_replay_ignores_unrelated_later_registry_append(self):
        case = self.case
        actual_j, parent, child = self._native_j_request(case)
        publication = self._amend(case, actual_j, parent, child)
        case.note({"kind": "unrelated later registry append"})
        self._fresh_readers(case)
        before_replay = case.snapshot()
        with mock.patch.object(
            orchestrator,
            "_read_resource_authority_records",
            side_effect=AssertionError("completed v2 replay consulted current external"),
        ):
            repeated = self._amend(case, actual_j, parent, child)
        self.assertEqual(repeated, publication)
        self.assertEqual(case.snapshot(), before_replay)
