"""Actual native J1 -> explicit A2/C2 -> P2, never scientific authority."""
from dataclasses import replace
from pathlib import Path
from unittest import mock
import unittest

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import simulated_observation as observation
from scientist_one import simulated_resource as accounting
from scientist_one import scientific_protocol_revision as protocols
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.models import utc_now
from scientist_one.roles import Role
from scientist_one.scientific_design import HypothesisRole, HypothesisTiming
from scientist_one.security import canonical_json_bytes, safe_json_loads
import tests.test_simulated_observation as fixtures


from tests.test_resource_prepared_cases import (
    prepared_observed_tests, verify_observed_amendment_source,
)


@prepared_observed_tests
class ObservedContractV2Tests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.SimulatedObservationTests()
        self.addCleanup(self.case.doCleanups)
        real_producer = accounting.register_simulated_resource_initial_inventories
        def capture_actual_A_before_I(registry):
            # Actual A bytes were copied before capture; verify loaded identity
            # without rewriting a captured input's physical identity.
            verify_observed_amendment_source(registry, amendments)
            return real_producer(registry)
        with mock.patch.object(accounting, "register_simulated_resource_initial_inventories", side_effect=capture_actual_A_before_I):
            self.case.setUp()
        self.j = self.case.run_observation(self.case.prepare())
        self.parent = self.case.reservation.contract
        self.child = replace(self.parent, version=self.parent.version + 1, frozen_at=utc_now(),
                             stopping_criteria=(*self.parent.stopping_criteria, "Stop the new version at its declared second reserve boundary."))

    def publish(self, **changes):
        args = dict(run_id=self.case.case.run, amendment_id="observed-contract-v2",
                    parent_contract_artifact_sha256=self.case.reservation.contract_record.sha256,
                    child_contract=self.child, author_id=self.parent.frozen_by,
                    reason="Record changed stopping discipline after actual non-evidentiary J1.",
                    observation_artifact_sha256s=(self.j.record.sha256,))
        args.update(changes)
        return amendments.register_evaluation_contract_amendment(self.case.registry, self.case.ledger, **args)

    def require(self, result, registry=None, ledger=None):
        return amendments.require_evaluation_contract_amendment(
            registry or self.case.registry, ledger or self.case.ledger,
            amendment_artifact_sha256=result.amendment_record.sha256,
            expected_run_id=self.case.case.run,
        )

    def assert_refuses_unchanged(self, operation):
        before = self.case.snapshot()
        with self.assertRaises(amendments.EvaluationContractAmendmentError):
            operation()
        self.assertEqual(self.case.snapshot(), before)

    def test_actual_J_A_C_P_sequence_derives_exposure_without_confirmation(self):
        before = self.case.snapshot()
        result = self.publish()
        self.assertTrue(result.authority.amendment.results_already_seen)
        self.assertTrue(result.authority.amendment.requires_new_confirmatory_reserve)
        self.assertFalse(result.authority.confirmation_authorized)
        self.assertFalse(result.child_contract.results_seen_at_freeze)
        self.assertEqual(result.authority.visible_results, ())
        self.assertEqual(result.amendment_record.parent_artifacts,
                         (self.case.reservation.contract_record.sha256, self.j.record.sha256))
        self.assertEqual(result.contract_record.parent_artifacts, (result.amendment_record.sha256,))
        self.assertEqual(result.authority.schema_version, "evaluation-contract-amendment/v2")
        self.assertEqual(result.amendment_record.schema_version, "eval-contract-amendment/v2")
        control, = result.authority.observed_controls
        self.assertEqual((control.observation_artifact_sha256, control.observation_event_hash, control.observed_at),
                         (self.j.record.sha256, self.j.event.event_hash, self.j.record.created_at))
        self.assertFalse(control.scientific_authority)
        self.assertEqual(control.evidence_class, "NON_EVIDENTIARY")
        self.assertEqual(amendments.EvaluationContractAmendmentAuthority.from_dict(result.authority.to_dict()), result.authority)
        self.assertEqual(self.case.snapshot()[1:], before[1:])
        self.assertEqual(self.publish(), result)
        parent_p = self.case.reservation.protocol
        child_p = replace(parent_p, study_version=parent_p.study_version + 1,
                          parent_protocol_hash=parent_p.sha256, revision_reason=result.authority.amendment.reason,
                          stopping_rules=self.child.stopping_criteria)
        revised = protocols.register_scientific_protocol_revision(
            self.case.registry, self.case.ledger, expected_run_id=self.case.case.run,
            amendment_artifact_sha256=result.amendment_record.sha256,
            parent_protocol_artifact_sha256=self.case.reservation.protocol_record.sha256,
            protocol=child_p,
        )
        self.assertTrue(revised.authority.results_seen_at_amendment)
        self.assertTrue(revised.authority.requires_new_confirmatory_reserve_at_amendment)
        self.assertEqual(revised.amendment_publication, result)
        self.assertEqual(self.require(result), result)
        self.assertEqual(self.case.snapshot()[1:], before[1:])
        print("ACTUAL_J_A2_C2_P2", dict(amendment_schema=result.authority.schema_version,
              protocol_schema=revised.authority.schema_version, seen=True, fresh_required=True,
              confirmation_authorized=False, native_confirmatory_used=self.j.attempt.preparation.charge.runtime_state.confirmatory_used), flush=True)

    def test_explicit_empty_null_list_duplicate_or_non_native_selector_never_downgrades(self):
        class StringSubclass(str):
            pass
        for selector in (None, (), [], [self.j.record.sha256], (True,), (StringSubclass(self.j.record.sha256),),
                         (self.j.record.sha256, self.j.record.sha256), ("g" * 64,)):
            with self.subTest(selector=type(selector).__name__):
                self.assert_refuses_unchanged(lambda: self.publish(observation_artifact_sha256s=selector))

    def test_post_observation_parent_rewrite_and_backdated_child_refuse(self):
        rewritten = replace(self.parent.hypothesis_register.primary, statement="Changed after observing J1.")
        bad = replace(self.child, hypothesis_register=replace(self.parent.hypothesis_register, hypotheses=(rewritten,)))
        self.assert_refuses_unchanged(lambda: self.publish(child_contract=bad))
        self.assert_refuses_unchanged(lambda: self.publish(child_contract=replace(self.child, frozen_at=self.parent.frozen_at)))

    def test_posthoc_secondary_addition_positive_and_preplanned_addition_negative(self):
        new = replace(self.parent.hypothesis_register.primary, hypothesis_id="posthoc-secondary-control",
                      planned_experiment="posthoc-secondary-experiment", role=HypothesisRole.SECONDARY,
                      statement="A descriptive follow-up formed after the observed control.")
        register = replace(self.parent.hypothesis_register, hypotheses=(*self.parent.hypothesis_register.hypotheses, new))
        child = replace(self.child, hypothesis_register=register)
        self.assert_refuses_unchanged(lambda: self.publish(child_contract=child))
        new = replace(new, timing=HypothesisTiming.POST_HOC, formed_after_observation=True)
        child = replace(child, hypothesis_register=replace(register, hypotheses=(*self.parent.hypothesis_register.hypotheses, new)))
        result = self.publish(child_contract=child)
        self.assertTrue(result.authority.amendment.results_already_seen)
        self.assertEqual(result.child_contract.hypothesis_register.hypotheses[-1], new)

    def test_completed_history_after_append_uses_sealed_J_not_live_current_inputs(self):
        result = self.publish()
        self.case.registry.put_json({"ordinary": "later unrelated record"}, logical_type="ordinary_later_note",
                                    origin="historical control", creator_role=Role.ORCHESTRATOR)
        registry = ArtifactRegistry(self.case.root, base_path=self.case.registry.base_path)
        ledger = EventLedger(self.case.root, self.case.ledger.relative_path)
        before = self.case.snapshot()
        with mock.patch.object(accounting, "_read_resource_authority_records", side_effect=AssertionError("historical replay read current resource")), \
             mock.patch.object(observation, "_provider", side_effect=AssertionError("historical replay opened live custody")), \
             mock.patch.object(accounting, "_charge_current_contract", side_effect=AssertionError("historical replay requires obsolete C1")):
            self.assertEqual(self.require(result, registry, ledger), result)
            self.assertEqual(self.publish(), result)
        self.assertEqual(self.case.snapshot(), before)

    def test_completed_retry_cannot_omit_or_change_observation_selection(self):
        result = self.publish()
        self.assertEqual(self.require(result), result)
        args = dict(run_id=self.case.case.run, amendment_id="observed-contract-v2",
                    parent_contract_artifact_sha256=self.case.reservation.contract_record.sha256,
                    child_contract=self.child, author_id=self.parent.frozen_by,
                    reason=result.authority.amendment.reason)
        self.assert_refuses_unchanged(lambda: amendments.register_evaluation_contract_amendment(self.case.registry, self.case.ledger, **args))
        self.assert_refuses_unchanged(lambda: self.publish(observation_artifact_sha256s=(self.j.preparation.record.sha256,)))

    def test_later_correction_to_each_native_dependency_refuses_selected_outer_replay(self):
        result = self.publish()
        # Appending each actual correction does not rewrite the old sealed edge.
        sealed = self.case.case.snapshot()
        for original in self.j.ledger_snapshot.events:
            with self.subTest(event=original.event_id):
                self.case.ledger.append_correction(original.event_id, actor_role=Role.ORCHESTRATOR,
                                                  reason="Adversarial dependency correction", corrected_fields={"status": "RETRACTED"})
                with self.assertRaisesRegex(amendments.EvaluationContractAmendmentError, "dependency was corrected"):
                    self.require(result)
        # Explicit historical selection is independent of the later corrections.
        self.assertEqual(amendments._require_evaluation_contract_amendment_at_snapshot(
            self.case.registry, self.case.ledger, registry_snapshot=sealed[0], ledger_snapshot=sealed[1],
            amendment_artifact_sha256=result.amendment_record.sha256, expected_run_id=self.case.case.run,
        ), result)

    def test_v2_codec_requires_exact_schema_and_non_evidentiary_observation(self):
        result = self.publish()
        value = result.authority.to_dict()
        for changed in (
            {**value, "schema_version": "evaluation-contract-amendment/v1"},
            {key: item for key, item in value.items() if key != "observed_controls"},
            {**value, "observed_controls": []},
            {**value, "observed_controls": [{**value["observed_controls"][0], "scientific_authority": True}]},
            {**value, "observed_controls": [{**value["observed_controls"][0], "observation_event_index": True}]},
        ):
            with self.subTest(keys=tuple(changed)):
                with self.assertRaises(amendments.EvaluationContractAmendmentError):
                    amendments.EvaluationContractAmendmentAuthority.from_dict(changed)
        raw = self.case.registry.get_bytes(result.amendment_record.sha256)
        self.assertEqual(raw, canonical_json_bytes(safe_json_loads(raw)) + b"\n")

    def test_later_renamed_slot_alias_refuses_but_ordinary_prose_reference_does_not(self):
        result = self.publish()
        self.case.registry.put_json(
            {"note": "evaluation-contract-amendment/v2 " + self.j.record.sha256},
            logical_type="ordinary_prose_reference", origin="negative selection control", creator_role=Role.ORCHESTRATOR,
        )
        self.assertEqual(self.require(result), result)
        self.case.registry.put_json(
            {"renamed": result.authority.to_dict()}, logical_type="renamed_a2_slot",
            origin="adversarial alias", creator_role=Role.ORCHESTRATOR,
        )
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_null_amendment_event_key_is_not_an_unrelated_later_reference(self):
        result = self.publish()
        original = result.event
        event = type(original).create(
            run_id=original.run_id, event_id="later-null-amendment-key", timestamp=utc_now(),
            actor_role=Role.ORCHESTRATOR, state_before=original.requested_state_after,
            requested_state_after=original.requested_state_after, event_type="CHECKPOINT",
            artifact_hashes=(result.amendment_record.sha256,), code_version=original.code_version,
            configuration_hash=original.configuration_hash, reason="Adversarial null alias control",
            prior_event_hash=self.case.ledger.assert_valid().head_hash,
            metadata={"evaluation_contract_amendment": None},
        )
        self.case.ledger.append(event)
        self.assert_refuses_unchanged(lambda: self.require(result))
