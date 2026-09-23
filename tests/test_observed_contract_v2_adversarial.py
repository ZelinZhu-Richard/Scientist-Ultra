"""Actual public A2 counterexamples and prospective bookkeeping boundaries."""
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one.models import utc_now
from scientist_one.roles import Role
from scientist_one.resources import ResourceController
import tests.test_observed_contract_v2 as fixtures


from tests.test_resource_prepared_cases import (
    prepared_observed_tests,
)


@prepared_observed_tests
class ObservedContractV2AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.owner = fixtures.ObservedContractV2Tests()
        self.addCleanup(self.owner.doCleanups)
        self.owner.setUp()

    def assert_refused_unchanged(self, operation):
        before = self.owner.case.snapshot()
        error = None
        try:
            operation()
        except amendments.EvaluationContractAmendmentError as exc:
            error = exc
        after = self.owner.case.snapshot()
        print("ACTUAL_A2_BOUNDARY", dict(refused=error is not None, reason=None if error is None else str(error),
              records_before=before[0][0].count, records_after=after[0][0].count,
              events_before=before[0][1].event_count, events_after=after[0][1].event_count,
              native_unchanged=before[1:] == after[1:]), flush=True)
        with self.subTest(check="expected typed refusal"):
            self.assertIsNotNone(error)
        self.assertEqual(after, before)

    def test_renamed_unknown_payload_version_targeting_same_slot_refuses(self):
        result = self.owner.publish()
        self.owner.case.registry.put_json(
            {"renamed": {**result.authority.to_dict(), "schema_version": "evaluation-contract-amendment/v999"}},
            logical_type="renamed_unknown_authority", origin="adversarial unsupported version",
            creator_role=Role.ORCHESTRATOR,
        )
        self.assert_refused_unchanged(lambda: self.owner.require(result))

    def test_renamed_unknown_artifact_version_targeting_same_slot_refuses(self):
        result = self.owner.publish()
        self.owner.case.registry.put_json(
            {"amendment_id": result.authority.amendment.amendment_id},
            schema_version="eval-contract-amendment/v999", logical_type="renamed_unknown_metadata",
            origin="adversarial unsupported metadata version", creator_role=Role.ORCHESTRATOR,
        )
        self.assert_refused_unchanged(lambda: self.owner.require(result))

    def test_mapping_publication_key_with_only_same_J_reference_refuses(self):
        result = self.owner.publish()
        original = result.event
        event = type(original).create(
            run_id=original.run_id, event_id="later-same-observation-mapping", timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR, state_before=original.requested_state_after,
            requested_state_after=original.requested_state_after, event_type="CHECKPOINT",
            artifact_hashes=(), code_version=original.code_version,
            configuration_hash=original.configuration_hash, reason="Malformed same-J amendment event control",
            prior_event_hash=self.owner.case.ledger.assert_valid().head_hash,
            metadata={"evaluation_contract_amendment": {
                "schema_version": "evaluation-contract-amendment/v2",
                "observed_controls": [{"observation_artifact_sha256": self.owner.j.record.sha256}],
            }},
        )
        self.owner.case.ledger.append(event)
        self.assert_refused_unchanged(lambda: self.owner.require(result))

    def test_exhausted_disk_reserve_refuses_before_A_C_event_writes(self):
        with mock.patch.object(ResourceController, "_probe_disk", return_value=(10**9, 0, None)):
            self.assert_refused_unchanged(self.owner.publish)

    def test_empty_mapping_key_cannot_hide_sibling_same_J_publication_alias(self):
        result = self.owner.publish()
        original = result.event
        event = type(original).create(
            run_id=original.run_id, event_id="later-empty-binding-sibling-alias", timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR, state_before=original.requested_state_after,
            requested_state_after=original.requested_state_after, event_type="CHECKPOINT",
            artifact_hashes=(), code_version=original.code_version,
            configuration_hash=original.configuration_hash, reason="Empty mapping cannot hide selected sibling alias",
            prior_event_hash=self.owner.case.ledger.assert_valid().head_hash,
            metadata={"evaluation_contract_amendment": {}, "renamed": {
                "schema_version": "evaluation-contract-amendment/v2",
                "observation_artifact_sha256": self.owner.j.record.sha256,
            }},
        )
        self.owner.case.ledger.append(event)
        self.assert_refused_unchanged(lambda: self.owner.require(result))

    def test_exhausted_artifact_budget_refuses_before_A_C_event_writes(self):
        maximum = self.owner.case.initialization.config.maximum_artifact_bytes
        with mock.patch.object(ResourceController, "artifact_usage", return_value=maximum):
            self.assert_refused_unchanged(self.owner.publish)

    def test_empty_mapping_cannot_hide_event_prefix_and_owned_J_reference(self):
        result = self.owner.publish()
        original = result.event
        event = type(original).create(
            run_id=original.run_id, event_id="evt-contract-amendment-foreign", timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR, state_before=original.requested_state_after,
            requested_state_after=original.requested_state_after, event_type="CHECKPOINT",
            artifact_hashes=(self.owner.j.record.sha256,), code_version=original.code_version,
            configuration_hash=original.configuration_hash, reason="Empty mapping cannot hide publication-shaped event ID",
            prior_event_hash=self.owner.case.ledger.assert_valid().head_hash,
            metadata={"evaluation_contract_amendment": {}},
        )
        self.owner.case.ledger.append(event)
        self.assert_refused_unchanged(lambda: self.owner.require(result))
