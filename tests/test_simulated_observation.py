"""Actual native S/Q/SEAL/STARTED/RELEASE/terminal/J in independent temp roots.

Private captured-fixture evidence only: actual owner bytes are prepared before
normal capture and inventoried; this is not host or scientific attestation. Faults interrupt real owners; none return mock
successful authority, fabricated review artifacts, or fabricated evaluator data.
"""

from dataclasses import replace
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
import shutil
import os
import tempfile
import unittest
from unittest import mock

from scientist_one import holdout, recovery, orchestrator
from scientist_one import simulated_observation as observation
from scientist_one import simulated_resource as resource
from scientist_one import simulated_reserve as reserve
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.protocol import StudyVersion
from scientist_one.resources import ResourceConfig, ResourceController
from scientist_one.security import canonical_json_bytes, safe_json_loads, sha256_bytes
from scientist_one.ledger import EventLedger
from scientist_one.models import utc_now
from scientist_one.roles import Role
import tests.test_simulated_resource as fixtures
import tests.test_simulated_reserve as allocation_fixtures

from tests.test_resource_prepared_cases import (
    prepared_observation_tests, prepared_observation_setup, observation_phase,
    verify_observation_loaded_sources, observation_journal_path,
    emit_observation_request, observation_request, observation_schemas,
    observation_forms, owned_observation_root,
)


@prepared_observation_tests
class SimulatedObservationTests(unittest.TestCase):
    def setUp(self):
        if prepared_observation_setup(self):
            return
        self.case = fixtures.SimulatedResourceTests()
        self.case.prepare(ResourceConfig(memory_soft_fraction=0.98, memory_hard_fraction=0.99,
                          minimum_free_disk_bytes=1, minimum_free_disk_fraction=0.01), freeze=False)
        self.addCleanup(self.case.doCleanups)
        self.registry, self.ledger, self.root = self.case.registry, self.case.ledger, self.case.root
        # The parent copied actual bytes before capture; never rewrite a loaded
        # captured source, even to identical bytes (physical identity matters).
        verify_observation_loaded_sources(self.root,
            (holdout, recovery, orchestrator, observation, resource, reserve))
        source, config = resource.register_simulated_resource_initial_inventories(self.registry)
        self.initialization = resource.initialize_simulated_resource_authority(self.registry, self.ledger,
            expected_run_id=self.case.run, protocol_artifact_sha256=self.case.protocol_record.sha256,
            contract_artifact_sha256=self.case.contract_record.sha256, population_artifact_sha256=self.case.population.sha256,
            frozen_source_inventory_artifact_sha256=source.sha256, frozen_configuration_inventory_artifact_sha256=config.sha256)
        self.reservation = reserve.register_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.run, protocol_artifact_sha256=self.case.protocol_record.sha256,
            contract_artifact_sha256=self.case.contract_record.sha256, population_artifact_sha256=self.case.population.sha256,
            window_index=1, initialization_artifact_sha256=self.initialization.record.sha256)
        self.charge = resource.charge_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.run, reservation_artifact_sha256=self.reservation.record.sha256)

    def prepare(self):
        return observation.prepare_simulated_reserve_reveal(self.registry, self.ledger,
            expected_run_id=self.case.run, reservation_artifact_sha256=self.reservation.record.sha256,
            charge_artifact_sha256=self.charge.record.sha256)

    def run_observation(self, prep):
        return observation.run_simulated_reserve_observation(self.registry, self.ledger,
            expected_run_id=self.case.run, preparation_artifact_sha256=prep.record.sha256)

    def require(self, result):
        return observation.require_simulated_reserve_observation(self.registry, self.ledger,
            expected_run_id=self.case.run, observation_artifact_sha256=result.record.sha256)

    def snapshot(self):
        relative = observation_journal_path(self)
        path = self.root / (observation._journal_path(self.charge) if relative is None else relative)
        return self.case.snapshot(), self.case.files(), path.read_bytes() if path.exists() else None

    def native_attempt(self, prep, **changes):
        provider = observation._provider(self.registry, self.charge, existing=True)
        provider.seal(self.reservation.evaluator_payload, **observation._seal_fields(self.registry, self.charge), nonblocking=True)
        at = utc_now()
        args = dict(ledger_path=self.ledger.relative_path, study_version=StudyVersion(self.reservation.protocol),
            fresh_custody_evidence=recovery.FreshCustodyEvidence(prep.record.sha256, prep.record.record_hash, prep.event.event_id),
            reveal_authority=recovery.SimulatedReserveRevealSelection(
                recovery.RegisteredArtifactSelector(self.reservation.record.sha256, self.reservation.record.record_hash),
                recovery.RegisteredArtifactSelector(self.charge.record.sha256, self.charge.record.record_hash)),
            artifact_registry=self.registry, custody_provider=provider, validity_snapshot=observation._budget(self.charge),
            start_event=observation._started(self.registry, prep, at), evaluator_spec=holdout.ConfirmatoryEvaluatorSpec(),
            requester=observation.REQUESTER, reason=observation.REASON, requested_at=at)
        args.update(changes)
        return recovery.RecoveryManager.run_non_evidentiary_simulated_fixture(recovery.RecoveryManager(self.root), **args)

    def assert_refuses_unchanged(self, operation):
        before = self.snapshot()
        with self.assertRaises(Exception):
            operation()
        self.assertEqual(self.snapshot(), before)

    def test_T_preflight_reserves_known_files_and_bounded_observation_before_external_advance(self):
        prep = self.prepare()
        before = self.snapshot()
        original = observation._live
        estimates = {}
        def constrained_live(registry, ledger, pair, q, **kwargs):
            if not kwargs.get("new_attempt"):
                return original(registry, ledger, pair, q, **kwargs)
            capacity = kwargs["capacity"]
            self.assertGreater(capacity, 4 * resource._MAX_BYTES)
            estimates["capacity"] = capacity
            config = q.initialization.config
            total = 10 ** 9
            reserve_bytes = observation.conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
            with mock.patch.object(ResourceController, "_probe_disk", return_value=(total, reserve_bytes + capacity, None)):
                return original(registry, ledger, pair, q, **kwargs)
        with mock.patch.object(observation, "_live", constrained_live):
            with self.assertRaisesRegex(Exception, "DISK_RESERVE_BREACH"):
                self.run_observation(prep)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("capacity", estimates)

    def note(self, value):
        return self.registry.put_json(value, logical_type="inert_note", origin="negative observation test", creator_role=Role.ORCHESTRATOR)

    def journal_fault(self, phase, *, after=False):
        original = holdout.SimulatedHoldoutCustody._append_journal_locked
        def interrupted(provider, descriptor, event_type, payload):
            if event_type == phase:
                if after:
                    original(provider, descriptor, event_type, payload)
                raise OSError("actual native " + phase + " interruption")
            return original(provider, descriptor, event_type, payload)
        return mock.patch.object(holdout.SimulatedHoldoutCustody, "_append_journal_locked", interrupted)

    def event_fault(self, key, *, after=False):
        original = self.ledger.__class__._append_locked
        def interrupted(ledger, guard, builder):
            event = builder(ledger._validate_bytes(ledger._read_raw_locked(guard)))
            if key in event.metadata:
                if after:
                    original(ledger, guard, builder)
                raise OSError("actual publication interruption")
            return original(ledger, guard, builder)
        return mock.patch.object(self.ledger.__class__, "_append_locked", interrupted)

    def test_actual_native_positive_whole_flow_and_exact_accounting_repeat(self):
        files = self.case.files()
        prep = self.prepare()
        self.assertEqual(prep.record.logical_type, "fresh_custody_receipt")
        p = safe_json_loads(self.registry.get_bytes(prep.record.sha256))
        self.assertEqual(p["interpretation_anchor_sha256"], self.reservation.contract_record.sha256)
        self.assertEqual(p["source_ledger_event_count"], 3)
        result = self.run_observation(prep)
        self.assertEqual((prep.event_index, result.attempt.event_index, result.event_index), (3, 4, 6))
        self.assertEqual(tuple(x.event_type for x in holdout.SimulatedHoldoutCustody(authorized_requesters=(observation.REQUESTER,))._parse_journal_bytes(result.custody_journal_bytes)),
                         ("SEAL", "RELEASE", "EVALUATION_SUCCEEDED"))
        self.assertEqual(result.started_event.artifact_hashes, (result.attempt.record.sha256,))
        self.assertEqual(result.started_event.metadata["resource_authority_checkpoint"], result.attempt.event.metadata["resource_authority_checkpoint"])
        self.assertNotIn("resource_authority_checkpoint", prep.event.metadata)
        self.assertNotIn("resource_authority_checkpoint", result.event.metadata)
        self.assertEqual(result.capture_mode, observation._CAPTURE_MODES[0])
        value = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertEqual(value["native_violation_reasons"], [observation._INVALID_REASON])
        self.assertIs(value["confirmatory_claims_valid"], False)
        self.assertEqual(value["charged_units"], 8)
        self.assertEqual(self.case.files()[:2], files)
        self.assertEqual(len(self.case.files()), 3)
        t = safe_json_loads(self.registry.get_bytes(result.attempt.record.sha256))
        self.assertEqual(t["runtime_state"], self.charge.runtime_state.to_dict())
        self.assertEqual(t["additional_validity_units"], 0)
        self.assertEqual(self.case.external()[-1]["state_sha256"], result.attempt.record.sha256)
        self.assertNotIn("started_event_hash", t)
        orchestrator._validate_resource_authority_ledger_for(self.case.external(), self.case.snapshot()[1].events)
        self.assertEqual(self.require(result), result)

    def test_completed_idempotency_never_releases_recharges_or_observes_clock(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        before = self.snapshot()
        with mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("double charge")), \
             mock.patch.object(ResourceController, "observe_wall_time", side_effect=AssertionError("clock update")), \
             mock.patch.object(recovery.RecoveryManager, "run_non_evidentiary_simulated_fixture", side_effect=AssertionError("rerelease")):
            self.assertEqual(self.run_observation(prep), result)
            self.assertEqual(self.require(result), result)
        self.assertEqual(self.snapshot(), before)

    def test_clean_seal_before_receipt_failure_can_finish_once(self):
        with mock.patch.object(observation, "_publish", side_effect=OSError("before receipt")):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.prepare()
        self.assertEqual(self.case.snapshot()[1].event_count, 3)
        raw = self.snapshot()[2]
        prep = self.prepare()
        self.assertEqual(prep.custody_journal_bytes, raw)
        self.assertEqual(self.prepare(), prep)
        self.run_observation(prep)

    def test_exact_preparation_record_orphan_recovers_event_only(self):
        with self.event_fault(observation.PREPARATION_KEY):
            with self.assertRaises(Exception):
                self.prepare()
        before = self.snapshot()
        prep = self.prepare()
        self.assertEqual(self.case.snapshot()[0], before[0][0])
        self.assertEqual(self.case.files(), before[1])
        self.assertEqual(self.snapshot()[2], before[2])
        self.assertEqual(prep.event_index, 3)

    def test_native_wrong_reason_refuses_before_started_or_release(self):
        prep = self.prepare()
        self.assert_refuses_unchanged(lambda: self.native_attempt(prep, reason="caller substituted reason"))

    def test_native_wrong_validity_snapshot_refuses_before_started(self):
        prep = self.prepare()
        bad = replace(observation._budget(self.charge), confirmatory_used=True)
        self.assert_refuses_unchanged(lambda: self.native_attempt(prep, validity_snapshot=bad))

    def test_native_wrong_started_resource_reference_refuses_before_append(self):
        prep = self.prepare()
        event = observation._started(self.registry, prep, utc_now())
        wrong = replace(event, artifact_hashes=(self.initialization.record.sha256,), event_hash=None)
        self.assert_refuses_unchanged(lambda: self.native_attempt(prep, start_event=wrong, requested_at=wrong.timestamp))

    def test_native_before_release_failure_retains_started_and_never_retries(self):
        prep = self.prepare()
        with self.journal_fault("RELEASE"):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertEqual(self.case.snapshot()[1].event_count, 6)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))
        self.assertEqual(self.case.external()[-1]["state"]["runtime_state"]["confirmatory_used"], 8)

    def test_native_after_release_failure_retains_pending_and_never_retries(self):
        prep = self.prepare()
        with self.journal_fault("RELEASE", after=True):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_native_before_terminal_failure_never_retries(self):
        prep = self.prepare()
        with self.journal_fault("EVALUATION_SUCCEEDED"):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_native_after_terminal_failure_recovers_without_original_guard_claim(self):
        prep = self.prepare()
        with self.journal_fault("EVALUATION_SUCCEEDED", after=True):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        result = self.run_observation(prep)
        self.assertEqual(result.capture_mode, observation._CAPTURE_MODES[1])
        self.assertIs(safe_json_loads(self.registry.get_bytes(result.record.sha256))["original_release_guard_exit_observed"], False)

    def test_real_native_terminal_without_J_is_observation_only_recovery(self):
        prep = self.prepare()
        self.native_attempt(prep)
        raw, files = self.snapshot()[2], self.case.files()
        with mock.patch.object(recovery.RecoveryManager, "run_non_evidentiary_simulated_fixture", side_effect=AssertionError("must not rerelease")):
            result = self.run_observation(prep)
        self.assertEqual(result.capture_mode, observation._CAPTURE_MODES[1])
        self.assertEqual(self.snapshot()[2], raw)
        self.assertEqual(self.case.files(), files)

    def test_J_record_only_orphan_recovers_exact_event_without_new_capture(self):
        prep = self.prepare()
        with self.event_fault(observation.OBSERVATION_KEY):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        before = self.snapshot()
        result = self.run_observation(prep)
        self.assertEqual(self.case.snapshot()[0], before[0][0])
        self.assertEqual(self.snapshot()[1:], before[1:])
        self.assertEqual(result.capture_mode, observation._CAPTURE_MODES[0])

    def test_J_event_postwrite_failure_is_completed_zero_delta(self):
        prep = self.prepare()
        with self.event_fault(observation.OBSERVATION_KEY, after=True):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        before = self.snapshot()
        result = self.run_observation(prep)
        self.assertEqual(result.capture_mode, observation._CAPTURE_MODES[0])
        self.assertEqual(self.snapshot(), before)

    def test_passive_S_and_historical_Q_consume_full_completed_owner(self):
        prep = self.prepare()
        self.run_observation(prep)
        pair = self.case.snapshot()
        self.assertEqual(reserve.require_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.run, reservation_artifact_sha256=self.reservation.record.sha256).record, self.reservation.record)
        self.assertEqual(resource._require_simulated_confirmatory_charge_at_snapshot(self.registry, self.ledger,
            expected_run_id=self.case.run, charge_artifact_sha256=self.charge.record.sha256,
            registry_snapshot=pair[0], ledger_snapshot=pair[1]).record, self.charge.record)
        self.assert_refuses_unchanged(lambda: resource.require_simulated_confirmatory_charge(self.registry, self.ledger,
            expected_run_id=self.case.run, charge_artifact_sha256=self.charge.record.sha256))

    def test_extra_renamed_observation_alias_is_not_skipped(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        self.note({"nested": {"schema_version": observation.OBSERVATION_SCHEMA}})
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_corrected_started_refuses_without_refund(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        self.ledger.append_correction(result.started_event.event_id, actor_role=Role.ORCHESTRATOR,
            reason="retained correction, not refund", corrected_fields={"reason": "invalid attempt"})
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_current_source_drift_refuses_before_new_attempt(self):
        if observation_phase() == "seed":
            prep = self.prepare()
            emit_observation_request(self, prep)
            return
        # The parent appended the original exact comment between captures.
        # The same public owner resolves these actual seed selectors itself.
        self.assert_refuses_unchanged(lambda: observation.run_simulated_reserve_observation(
            self.registry, self.ledger, **observation_request(self)))

    def test_later_external_head_refuses_before_new_attempt(self):
        prep = self.prepare()
        orchestrator._persist_resource_authority_for(self.root, self.case.run, "resource_runtime_unprojected_stage", self.charge.runtime_state.to_dict())
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_capacity_refuses_before_native_seal(self):
        with mock.patch.object(resource, "MAX_REGISTRY_RECORDS", self.case.snapshot()[0].count):
            self.assert_refuses_unchanged(self.prepare)

    def test_native_noncanonical_journal_bytes_refuse_observation(self):
        prep = self.prepare()
        self.native_attempt(prep)
        path = self.root / observation._journal_path(self.charge)
        raw = path.read_bytes()
        path.write_bytes(b" " + raw)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_observation_orphan_after_source_delta_cannot_recover(self):
        prep = self.prepare()
        with self.event_fault(observation.OBSERVATION_KEY):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.note({"kind": "INERT"})
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def rewrite_native_journal(self, mutate):
        """Negative fixture: rehash actual native events, never fabricate success."""
        path = self.root / observation._journal_path(self.charge)
        events = [safe_json_loads(line) for line in path.read_bytes().splitlines()]
        mutate(events)
        previous = "0" * 64
        for event in events:
            event["prior_event_hash"] = previous
            unsigned = {key: value for key, value in event.items() if key != "event_hash"}
            event["event_hash"] = previous = sha256_bytes(canonical_json_bytes(unsigned))
        path.write_bytes(b"".join(canonical_json_bytes(event) + b"\n" for event in events))
        # Before-failure control: actual native parser/restore accepts this
        # normalization; the closed J owner must independently reject it.
        native = observation._provider(self.registry, self.charge, existing=True)
        with native.admission_guard(nonblocking=True) as snapshot:
            self.assertTrue(snapshot.revealed)
        return path.read_bytes()

    def test_duplicate_native_requester_policy_normalization_is_not_J_authority(self):
        prep = self.prepare()
        self.native_attempt(prep)
        self.rewrite_native_journal(lambda events: events[0]["payload"].update(authorized_requesters=[observation.REQUESTER, observation.REQUESTER]))
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_bool_native_release_count_normalization_is_not_J_authority(self):
        prep = self.prepare()
        self.native_attempt(prep)
        def mutate(events):
            release = events[1]["payload"]["release"]
            release["authorized_access_count"] = True
            release["release_id"] = holdout._release_id(holdout.HoldoutRelease(**release))
            events[2]["payload"]["release_id"] = release["release_id"]
        self.rewrite_native_journal(mutate)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_native_result_hash_is_not_membership_recomputation(self):
        prep = self.prepare()
        self.native_attempt(prep)
        def mutate(events):
            terminal = events[2]["payload"]
            result = terminal["result"]
            result["control_mean"] += 20.0
            result["treatment_mean"] += 20.0
            result["primary_estimate"] = result["treatment_mean"] - result["control_mean"]
            terminal["result_sha256"] = sha256_bytes(canonical_json_bytes(result))
        self.rewrite_native_journal(mutate)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_native_release_requester_must_belong_to_exact_policy(self):
        prep = self.prepare()
        self.native_attempt(prep)
        def mutate(events):
            release, record = (events[1]["payload"][name] for name in ("release", "record"))
            release["requester"] = record["requester"] = "not-the-native-policy-requester"
            release["release_id"] = holdout._release_id(holdout.HoldoutRelease(**release))
            record["event_id"] = holdout._access_record_id(0, holdout.HoldoutAccessRecord(**record))
            events[2]["payload"]["release_id"] = release["release_id"]
        self.rewrite_native_journal(mutate)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_failed_native_terminal_is_retained_and_never_retried(self):
        prep = self.prepare()
        self.native_attempt(prep)
        path = self.root / observation._journal_path(self.charge)
        events = [safe_json_loads(line) for line in path.read_bytes().splitlines()]
        event = events[-1]
        event["event_type"] = "EVALUATION_FAILED"
        event["payload"].update(outcome="FAILED", result=None, result_sha256=None)
        event["event_hash"] = sha256_bytes(canonical_json_bytes({key: value for key, value in event.items() if key != "event_hash"}))
        path.write_bytes(b"".join(canonical_json_bytes(item) + b"\n" for item in events))
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_final_live_inventory_external_drift_is_detected_before_J_event(self):
        prep = self.prepare()
        self.native_attempt(prep)
        original = resource._inventory
        calls = 0
        def drift(registry, records, record, index, *, live):
            nonlocal calls
            result = original(registry, records, record, index, live=live)
            if live and index == 1:
                calls += 1
                # Initial run currentness, then publication currentness, then
                # the native final prewrite live read under paired locks.
                if calls == 3:
                    orchestrator._persist_resource_authority_for(self.root, self.case.run,
                        "resource_runtime_late_drift", self.charge.runtime_state.to_dict())
            return result
        before = self.case.snapshot()
        with mock.patch.object(resource, "_inventory", drift):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertEqual(calls, 3)
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(len(self.case.external()), 4)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_live_current_contract_source_pair_drift_refuses_before_started(self):
        prep = self.prepare()
        original = resource._charge_current_contract
        called = False
        def drift(registry, ledger, pair, reservation):
            nonlocal called
            original(registry, ledger, pair, reservation)
            if not called:
                called = True
                self.note({"kind": "LATE_PAIRED_SOURCE_DRIFT"})
        before = self.case.snapshot()[1]
        with mock.patch.object(resource, "_charge_current_contract", drift):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertTrue(called)
        self.assertEqual(self.case.snapshot()[1], before)

    def test_current_resource_configuration_drift_refuses_observation(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        path = self.root / "configs/resource_limits.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_actual_current_contract_successor_refuses_attempt(self):
        from scientist_one.evaluation_contract_amendment import register_evaluation_contract_amendment
        prep = self.prepare()
        child = replace(self.case.contract, version=2, success_criteria=("Changed criteria before actual native attempt.",))
        successor = register_evaluation_contract_amendment(self.registry, self.ledger,
            run_id=self.case.run, amendment_id="pre-native-attempt-successor",
            parent_contract_artifact_sha256=self.case.contract_record.sha256, child_contract=child,
            author_id=self.case.contract.frozen_by, reason="Actual contract revision, not receipt permission.",
            child_evidence_parent_artifact_sha256s=self.case.contract_record.parent_artifacts)
        self.assertEqual(successor.child_contract, child)
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_generic_recovery_must_refuse_new_profile_namespace(self):
        prep = self.prepare()
        self.run_observation(prep)
        for selection in ({"artifact_registry": self.registry, "expected_run_id": self.case.run}, {}):
            with self.subTest(supplied_registry=bool(selection)):
                report = self.assert_generic_denial(self.ledger.relative_path, expected_touched=True, **selection)
                self.assertEqual(report.ledger_event_count, 7)

    def recovery_tree(self):
        return tuple((path.relative_to(self.root).as_posix(), path.stat().st_ino,
                      path.stat().st_mtime_ns, path.read_bytes())
                     for path in sorted(self.root.rglob("*")) if path.is_file())

    def assert_generic_denial(self, path, *, expected_touched=False, **changes):
        before = self.recovery_tree()
        report = recovery.RecoveryManager(self.root).recover(
            **{"ledger_path": path, "repair_truncated_tail": True,
               "incomplete_paths": (), **changes})
        self.assertEqual(report.action, recovery.ResumeAction.STOP_SECURITY)
        self.assertEqual(report.reasons, ("SIMULATED_RESERVE_REQUIRES_PROFILE_OWNER", "SIMULATED_RESERVE_CUSTODY_UNASSESSED"))
        self.assertIs(report.confirmatory_touched, expected_touched)
        self.assertIs(report.confirmatory_completed, False)
        self.assertIs(report.new_study_protocol_accepted, False)
        self.assertIs(report.artifacts_valid, False)
        self.assertEqual(report.quarantined, ())
        self.assertIsNone(report.checkpoint)
        self.assertEqual(self.recovery_tree(), before)
        return report

    def test_generic_recovery_before_preparation_denies_without_registry(self):
        self.assertIsNone(self.snapshot()[2])
        report = self.assert_generic_denial(self.ledger.relative_path)
        self.assertEqual(report.ledger_event_count, 3)
        self.assertIsNone(self.snapshot()[2])

    def test_generic_recovery_actual_run_under_alternate_path_denies(self):
        prep = self.prepare()
        self.run_observation(prep)
        alternate = self.root / "alternate-events.jsonl"
        alternate.write_bytes((self.root / self.ledger.relative_path).read_bytes())
        # No registry, expected run, or canonical path hint: intrinsic run ID
        # alone must route negatively before any generic recovery action.
        report = self.assert_generic_denial(alternate.relative_to(self.root), expected_touched=True)
        self.assertEqual(report.ledger_event_count, 7)

    def test_generic_recovery_expected_run_denies_unrelated_malformed_path(self):
        alternate = self.root / "unrelated-malformed-events.jsonl"
        alternate.write_bytes(b"{malformed first event}\n")
        report = self.assert_generic_denial(alternate.relative_to(self.root), expected_run_id=self.case.run)
        self.assertIs(report.ledger_valid, False)
        self.assertEqual(report.ledger_event_count, 0)

    def test_generic_recovery_canonical_malformed_first_event_does_not_quarantine(self):
        marker = self.root / "pending-observation.tmp"
        marker.write_bytes(b"incomplete marker must remain verbatim\n")
        (self.root / self.ledger.relative_path).write_bytes(b"{malformed first event}\n")
        report = self.assert_generic_denial(self.ledger.relative_path,
            incomplete_paths=(marker.relative_to(self.root),), repair_truncated_tail=True)
        self.assertIs(report.ledger_valid, False)
        self.assertEqual(report.ledger_event_count, 0)
        self.assertEqual(marker.read_bytes(), b"incomplete marker must remain verbatim\n")

    def test_generic_recovery_canonical_truncated_tail_is_never_repaired(self):
        marker = self.root / "pending-observation.tmp"
        marker.write_bytes(b"incomplete marker must remain verbatim\n")
        path = self.root / self.ledger.relative_path
        path.write_bytes(path.read_bytes() + b'{"event_type":')
        intrinsic = recovery.RecoveryManager(self.root).validate_ledger(self.ledger.relative_path)
        self.assertIs(intrinsic.recoverable_truncated_tail, True)
        report = self.assert_generic_denial(self.ledger.relative_path,
            incomplete_paths=(marker.relative_to(self.root),), repair_truncated_tail=True)
        self.assertIs(report.ledger_valid, False)
        self.assertEqual(report.ledger_event_count, 3)
        self.assertEqual(marker.read_bytes(), b"incomplete marker must remain verbatim\n")

    def test_receipt_clock_before_actual_SEAL_must_not_publish_unowned_receipt(self):
        before = self.case.snapshot()
        q_at = self.charge.record.created_at
        with mock.patch.object(observation, "utc_now", side_effect=(utc_now(), q_at)):
            with self.assertRaises(Exception):
                self.prepare()
        after = self.case.snapshot()
        raw = self.snapshot()[2]
        seal_at = safe_json_loads(raw.splitlines()[0])["payload"]["seal"]["sealed_at"]
        self.assertGreater(observation._time(seal_at), observation._time(q_at))
        print("ACTUAL_RECEIPT_CLOCK_FAULT", {"q_at": q_at, "seal_at": seal_at,
              "records_before": before[0].count, "records_after": after[0].count,
              "events_before": before[1].event_count, "events_after": after[1].event_count}, flush=True)
        self.assertEqual(after, before)

    def test_native_SEAL_clock_before_Q_must_not_leave_irrecoverable_SEAL(self):
        before = self.case.snapshot()
        earlier = (observation._time(self.charge.record.created_at) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        try:
            with mock.patch.object(holdout, "_now", return_value=earlier):
                self.prepare()
        except (ValueError, holdout.HoldoutCustodyError, orchestrator.OrchestrationError):
            self.assertEqual(self.case.snapshot(), before)
        raw = self.snapshot()[2]
        if raw:
            seal_at = safe_json_loads(raw.splitlines()[0])["payload"]["seal"]["sealed_at"]
            print("ACTUAL_SEAL_CLOCK_FAULT", {"q_at": self.charge.record.created_at,
                  "native_seal_at": seal_at, "ledger_events": self.case.snapshot()[1].event_count}, flush=True)
            self.assertGreaterEqual(observation._time(seal_at), observation._time(self.charge.record.created_at))

    def test_actual_run_tree_rollback_to_completed_Q_cannot_release_same_units_twice(self):
        backup = tempfile.TemporaryDirectory(prefix="simulated-run-rollback-control-")
        self.addCleanup(backup.cleanup)
        saved = Path(backup.name).resolve()
        run_path = self.root / "runs" / self.case.run
        self.assertEqual(run_path.parent.parent, self.root)
        self.assertTrue(owned_observation_root(self.root))
        shutil.copytree(run_path, saved / "completed-q-preimage")
        external_before = self.case.files()
        first_p = self.prepare()
        first_j = self.run_observation(first_p)
        first_value = safe_json_loads(self.registry.get_bytes(first_j.record.sha256))
        self.assertEqual(self.case.files()[:2], external_before)
        external_before = self.case.files()
        # Recoverable move of the exact fixture run subtree: the actual first
        # execution remains inspectable in this separate temporary backup.
        # Native project-level external accounting is deliberately not touched.
        run_path.rename(saved / "actual-complete-j-run")
        shutil.copytree(saved / "completed-q-preimage", run_path)
        # A real restart constructs fresh native readers. Reusing the original
        # live EventLedger would correctly reject the substituted inode before
        # testing durable rollback authority at all.
        self.registry = self.case.registry = ArtifactRegistry(self.root, Path("runs") / self.case.run / "registry")
        self.ledger = self.case.ledger = EventLedger(self.root, Path("runs") / self.case.run / "events.jsonl")
        self.assertEqual(self.case.files(), external_before)
        restored_pair = self.case.snapshot()
        current_q = resource._require_simulated_confirmatory_charge_at_snapshot(self.registry, self.ledger,
            expected_run_id=self.case.run, charge_artifact_sha256=self.charge.record.sha256,
            registry_snapshot=restored_pair[0], ledger_snapshot=restored_pair[1])
        self.assertEqual(current_q.record, self.charge.record)
        self.assertEqual(current_q.runtime_state.confirmatory_used, 8)
        self.assert_generic_denial(self.ledger.relative_path)
        before_retry = self.snapshot()
        try:
            second_p = self.prepare()
            second_j = self.run_observation(second_p)
        except (ValueError, holdout.HoldoutCustodyError, orchestrator.OrchestrationError):
            self.assertEqual(self.snapshot(), before_retry)
            return
        second_value = safe_json_loads(self.registry.get_bytes(second_j.record.sha256))
        print("ACTUAL_RUN_TREE_ROLLBACK_DOUBLE_RELEASE", {
            "accounting_sha256": self.charge.record.sha256,
            "first_native_release_id": first_value["native_release_id"],
            "second_native_release_id": second_value["native_release_id"],
            "first_J": first_j.record.sha256, "second_J": second_j.record.sha256,
            "external_files_unchanged": self.case.files() == external_before,
            "confirmatory_used": self.case.external()[-1]["state"]["runtime_state"]["confirmatory_used"],
        }, flush=True)
        self.fail("actual run-tree rollback allowed a second native release for the same Q eight-unit charge")

    @contextmanager
    def attempt_fault(self, phase):
        persist = resource._persist_resource_authority_for
        put = resource._put
        append = EventLedger._append_locked
        def external(root, run, family, value):
            if family.startswith(observation.ATTEMPT_LOGICAL_PREFIX) and phase.startswith("external"):
                if phase == "external-after":
                    persist(root, run, family, value)
                raise OSError("actual native T external interruption")
            return persist(root, run, family, value)
        def artifact(registry, guard, record, raw):
            if record.schema_version == observation.ATTEMPT_SCHEMA and phase.startswith("artifact"):
                if phase == "artifact-after":
                    put(registry, guard, record, raw)
                raise OSError("actual native T artifact interruption")
            return put(registry, guard, record, raw)
        def event(ledger, guard, build):
            candidate = build(ledger._validate_bytes(ledger._read_raw_locked(guard)))
            selected = ((phase.startswith("event") and observation.ATTEMPT_KEY in candidate.metadata)
                        or (phase.startswith("started") and observation.STARTED_KEY in candidate.metadata))
            if selected:
                if phase.endswith("after"):
                    append(ledger, guard, build)
                raise OSError("actual native T/STARTED event interruption")
            return append(ledger, guard, build)
        with mock.patch.object(resource, "_persist_resource_authority_for", external), \
             mock.patch.object(resource, "_put", artifact), \
             mock.patch.object(EventLedger, "_append_locked", event):
            yield

    def check_burned_attempt_fault(self, phase, events):
        prep = self.prepare()
        original_external = self.case.files()
        with self.attempt_fault(phase):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertEqual(self.case.snapshot()[1].event_count, events)
        self.assertEqual(self.case.files()[:2], original_external)
        self.assertEqual(len(self.case.files()), 3)
        t = self.case.external()[-1]
        self.assertEqual(t["sequence"], 2)
        self.assertEqual(t["state"]["runtime_state"], self.charge.runtime_state.to_dict())
        self.assertIs(t["state"]["attempt_consumed"], True)
        with mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("retry charged")):
            self.assert_refuses_unchanged(lambda: self.run_observation(prep))
            self.assert_refuses_unchanged(self.prepare)

    def test_T_external_before_failure_does_not_consume_attempt(self):
        prep = self.prepare()
        before = self.snapshot()
        with self.attempt_fault("external-before"):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertEqual(self.snapshot(), before)
        result = self.run_observation(prep)
        self.assertEqual(result.attempt.event_index, 4)

    def test_T_external_after_failure_burns_attempt_without_local_record(self):
        self.check_burned_attempt_fault("external-after", 4)

    def test_T_artifact_before_failure_burns_attempt(self):
        self.check_burned_attempt_fault("artifact-before", 4)

    def test_T_artifact_after_failure_burns_record_orphan(self):
        self.check_burned_attempt_fault("artifact-after", 4)

    def test_T_event_before_failure_burns_record_orphan(self):
        self.check_burned_attempt_fault("event-before", 4)

    def test_T_event_after_failure_never_manufactures_started_on_restart(self):
        self.check_burned_attempt_fault("event-after", 5)

    def test_STARTED_before_failure_leaves_external_attempt_consumed(self):
        self.check_burned_attempt_fault("started-before", 5)

    def test_STARTED_after_failure_never_retries_native_release(self):
        self.check_burned_attempt_fault("started-after", 6)

    def test_started_before_release_and_run_tree_rollback_still_burns_attempt(self):
        backup = tempfile.TemporaryDirectory(prefix="simulated-started-rollback-control-")
        self.addCleanup(backup.cleanup)
        saved = Path(backup.name).resolve()
        run_path = self.root / "runs" / self.case.run
        shutil.copytree(run_path, saved / "completed-q-preimage")
        prep = self.prepare()
        with self.journal_fault("RELEASE"):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        self.assertEqual(self.case.snapshot()[1].event_count, 6)
        external = self.case.files()
        raw = self.snapshot()[2]
        self.assertEqual(len(raw.splitlines()), 1)
        run_path.rename(saved / "started-no-release-run")
        shutil.copytree(saved / "completed-q-preimage", run_path)
        self.registry = self.case.registry = ArtifactRegistry(self.root, Path("runs") / self.case.run / "registry")
        self.ledger = self.case.ledger = EventLedger(self.root, Path("runs") / self.case.run / "events.jsonl")
        self.assertEqual(self.case.files(), external)
        self.assertEqual(self.snapshot()[2], raw)
        self.assert_generic_denial(self.ledger.relative_path)
        self.assert_refuses_unchanged(self.prepare)
        self.assertEqual(self.case.external()[-1]["state"]["runtime_state"]["confirmatory_used"], 8)

    def test_owner_first_seal_clock_before_Q_refuses_before_provider_storage(self):
        earlier = (observation._time(self.charge.record.created_at) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        before = self.snapshot()
        with mock.patch.object(observation, "utc_now", return_value=earlier):
            with self.assertRaises(Exception):
                self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_exact_digest_locators_refuse_subclasses_bool_and_nonhex_before_and_after_J(self):
        class EqualText(str):
            def __eq__(self, other):
                return True
            def __ne__(self, other):
                return False
            __hash__ = str.__hash__
        def controls(prep=None, j=None):
            for bad in (EqualText(self.reservation.record.sha256), True, "x" * 64):
                with self.subTest(bad_type=type(bad).__name__, after_j=j is not None):
                    self.assert_refuses_unchanged(lambda: observation.prepare_simulated_reserve_reveal(
                        self.registry, self.ledger, expected_run_id=self.case.run,
                        reservation_artifact_sha256=bad, charge_artifact_sha256=self.charge.record.sha256))
                    self.assert_refuses_unchanged(lambda: observation.prepare_simulated_reserve_reveal(
                        self.registry, self.ledger, expected_run_id=self.case.run,
                        reservation_artifact_sha256=self.reservation.record.sha256, charge_artifact_sha256=bad))
                    self.assert_refuses_unchanged(lambda: reserve.require_simulated_confirmatory_reserve(
                        self.registry, self.ledger, expected_run_id=self.case.run, reservation_artifact_sha256=bad))
                    pair = self.case.snapshot()
                    self.assert_refuses_unchanged(lambda: resource._require_simulated_confirmatory_charge_at_snapshot(
                        self.registry, self.ledger, expected_run_id=self.case.run, charge_artifact_sha256=bad,
                        registry_snapshot=pair[0], ledger_snapshot=pair[1]))
                    self.assert_refuses_unchanged(lambda: observation.run_simulated_reserve_observation(
                        self.registry, self.ledger, expected_run_id=self.case.run, preparation_artifact_sha256=bad))
                    self.assert_refuses_unchanged(lambda: observation.require_simulated_reserve_observation(
                        self.registry, self.ledger, expected_run_id=self.case.run, observation_artifact_sha256=bad))
        controls()
        prep = self.prepare()
        result = self.run_observation(prep)
        controls(prep, result)

    def test_T_correction_is_not_attempt_refund_or_observation_authority(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        self.ledger.append_correction(result.attempt.event.event_id, actor_role=Role.ORCHESTRATOR,
            reason="retained attempt correction", corrected_fields={"attempt_consumed": False})
        self.assert_refuses_unchanged(lambda: self.require(result))
        self.assert_refuses_unchanged(lambda: self.run_observation(prep))

    def test_renamed_T_alias_is_not_passive_permission(self):
        prep = self.prepare()
        result = self.run_observation(prep)
        self.note({"nested": {"schema_version": observation.ATTEMPT_SCHEMA}})
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_J_orphan_completes_at_exact_record_event_caps_after_wall_budget(self):
        prep = self.prepare()
        with self.event_fault(observation.OBSERVATION_KEY):
            with self.assertRaises(Exception):
                self.run_observation(prep)
        pair = self.case.snapshot()
        _prep, _t, _started, orphan, state = observation._history(self.registry, self.ledger, pair, allow_orphan=True)
        self.assertEqual(state, "OBSERVATION_ORPHAN")
        original = ResourceController.from_runtime_state.__func__
        expired = self.charge.runtime_state.wall_started_at_epoch_seconds + self.initialization.config.maximum_wall_clock_seconds + 10
        def expired_controller(cls, config, root, runtime, **kwargs):
            return original(cls, config, root, runtime, wall_clock=lambda: expired, **kwargs)
        control = expired_controller(ResourceController, self.initialization.config, self.root, self.charge.runtime_state)
        decision = control.evaluate()
        self.assertFalse(decision.allowed)
        self.assertIn("WALL_CLOCK_BUDGET_EXHAUSTED", decision.reasons)
        before = self.snapshot()
        event_bytes = len(observation._raw(orphan.event.to_dict()))
        config = self.initialization.config
        total = 10 ** 9
        reserve_bytes = observation.conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
        with mock.patch.object(ResourceController, "from_runtime_state", classmethod(expired_controller)), \
             mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("observation requested a new experiment")), \
             mock.patch.object(ResourceController, "_probe_disk", return_value=(total, reserve_bytes + event_bytes + 1, None)), \
             mock.patch.object(resource, "MAX_REGISTRY_RECORDS", pair[0].count), \
             mock.patch.object(resource, "MAX_LEDGER_EVENTS", pair[1].event_count + 1), \
             mock.patch.object(resource, "MAX_LEDGER_BYTES", pair[1].valid_prefix_bytes + len(observation._raw(orphan.event.to_dict()))):
            result = self.run_observation(prep)
        self.assertEqual(result.record, orphan.record)
        self.assertEqual(self.case.snapshot()[0], pair[0])
        self.assertEqual(self.case.snapshot()[1].event_count, pair[1].event_count + 1)
        self.assertEqual(self.snapshot()[1:], before[1:])

    def test_fresh_J_disk_margin_includes_exact_artifact_metadata(self):
        prep = self.prepare()
        self.native_attempt(prep)
        before = self.snapshot()
        original = observation._publish
        estimates = {}
        def constrained_publish(registry, ledger, pair, q, record, value, event, **kwargs):
            payload_bytes = len(observation._raw(value))
            event_bytes = len(observation._raw(event.to_dict()))
            metadata_bytes = len(observation._raw(record.to_dict()))
            estimates.update(payload=payload_bytes, event=event_bytes, metadata=metadata_bytes)
            self.assertGreater(metadata_bytes, 1)
            config = q.initialization.config
            total = 10 ** 9
            reserve_bytes = observation.conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
            with mock.patch.object(ResourceController, "_probe_disk", return_value=(total, reserve_bytes + payload_bytes + event_bytes + 1, None)):
                return original(registry, ledger, pair, q, record, value, event, **kwargs)
        try:
            with mock.patch.object(observation, "_publish", constrained_publish):
                with self.assertRaisesRegex(observation.SimulatedObservationError, "bookkeeping lacks disk or artifact capacity"):
                    self.run_observation(prep)
        finally:
            after = self.snapshot()
            print("ACTUAL_J_METADATA_MARGIN", {**estimates, "records_before": before[0][0].count,
                  "records_after": after[0][0].count, "events_before": before[0][1].event_count,
                  "events_after": after[0][1].event_count}, flush=True)
        self.assertEqual(self.snapshot(), before)

    def _publication_marker(self, registry, schema, form):
        raw = (b'{"renamed":{"schema_version":' + canonical_json_bytes(schema)) if form == "malformed" else observation._raw({"renamed": {"schema_version": schema}})
        if form == "metadata":
            raw = observation._raw({"inert": True})
        return registry.put_bytes(raw, logical_type="unrelated_marker_note", origin="negative prepublication control",
            creator_role=Role.ORCHESTRATOR, mime_type="application/json", schema_version=schema if form == "metadata" else "1.0")

    def test_preparation_attempt_J_aliases_refuse_before_allocation_only_S_publication(self):
        for schema in (observation.PREPARATION_SCHEMA, observation.ATTEMPT_SCHEMA, observation.OBSERVATION_SCHEMA):
            for form in ("renamed", "malformed", "metadata"):
                with self.subTest(schema=schema, form=form):
                    case = allocation_fixtures.SimulatedReserveTests()
                    case.setUp()
                    self.addCleanup(case.doCleanups)
                    self._publication_marker(case.registry, schema, form)
                    before = case.snapshot()
                    with self.assertRaises(Exception):
                        case.publish()
                    after = case.snapshot()
                    print("ACTUAL_PRE_S_ALIAS", {"resource_backed": False, "schema": schema,
                        "form": form, "records_before": before[0].count, "records_after": after[0].count,
                        "events_before": before[1].event_count, "events_after": after[1].event_count}, flush=True)
                    self.assertEqual(after, before)

    def test_preparation_attempt_J_aliases_before_I_refuse_before_resource_backed_S_publication(self):
        for schema in observation_schemas((observation.PREPARATION_SCHEMA, observation.ATTEMPT_SCHEMA, observation.OBSERVATION_SCHEMA)):
            for form in observation_forms(("renamed", "malformed", "metadata")):
                with self.subTest(schema=schema, form=form):
                    # This variant's one genuine prepare ran in setUp on its
                    # own captured root; cleanup is registered there.
                    case = self.case
                    self._publication_marker(case.registry, schema, form)
                    before, external = case.snapshot(), case.files()
                    with self.assertRaises(Exception):
                        initialization = case.initialize()
                        reserve.register_simulated_confirmatory_reserve(case.registry, case.ledger,
                            expected_run_id=case.run, protocol_artifact_sha256=case.protocol_record.sha256,
                            contract_artifact_sha256=case.contract_record.sha256, population_artifact_sha256=case.population.sha256,
                            window_index=1, initialization_artifact_sha256=initialization.record.sha256)
                    after = case.snapshot()
                    print("ACTUAL_PRE_S_ALIAS", {"resource_backed": True, "schema": schema,
                        "form": form, "records_before": before[0].count, "records_after": after[0].count,
                        "events_before": before[1].event_count, "events_after": after[1].event_count}, flush=True)
                    self.assertEqual(after, before)
                    self.assertEqual(case.files(), external)

    def test_later_schema_words_in_untyped_prose_do_not_select_authority(self):
        case = allocation_fixtures.SimulatedReserveTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.registry.put_json({"note": [observation.PREPARATION_SCHEMA, observation.ATTEMPT_SCHEMA, observation.OBSERVATION_SCHEMA]},
            logical_type="unrelated_prose_note", origin="negative marker scope control", creator_role=Role.ORCHESTRATOR)
        first = case.publish()
        self.assertEqual(case.require(first), first)

    def test_constructor_created_empty_journal_can_finish_one_preparation(self):
        before = self.case.snapshot(), self.case.files()
        original = holdout.SimulatedHoldoutCustody.__init__
        def interrupted(provider, *args, **kwargs):
            original(provider, *args, **kwargs)
            if kwargs.get("journal_root") is not None:
                raise OSError("after actual native constructor created empty journal")
        with mock.patch.object(holdout.SimulatedHoldoutCustody, "__init__", interrupted):
            with self.assertRaises(Exception):
                self.prepare()
        path = self.root / observation._journal_path(self.charge)
        self.assertEqual(path.read_bytes(), b"")
        identity = path.stat().st_ino
        self.assertEqual((self.case.snapshot(), self.case.files()), before)
        prep = self.prepare()
        self.assertEqual(path.stat().st_ino, identity)
        self.assertEqual(prep.custody_journal_bytes, path.read_bytes())
        self.assertEqual(self.case.files(), before[1])

    def test_native_after_SEAL_interruption_can_finish_exact_preparation(self):
        before = self.case.snapshot(), self.case.files()
        with self.journal_fault("SEAL", after=True):
            with self.assertRaises(Exception):
                self.prepare()
        path = self.root / observation._journal_path(self.charge)
        sealed = path.read_bytes()
        self.assertEqual((self.case.snapshot(), self.case.files()), before)
        prep = self.prepare()
        self.assertEqual(prep.custody_journal_bytes, sealed)
        self.assertEqual(path.read_bytes(), sealed)
        self.assertEqual(self.case.files(), before[1])

    def test_native_partial_SEAL_interruption_is_retained_and_refused(self):
        before = self.case.snapshot(), self.case.files()
        original = holdout.os.write
        partial = {}
        def interrupted(descriptor, raw):
            raw = bytes(raw)
            if b'"event_type":"SEAL"' in raw:
                prefix = bytes(raw[:len(raw) // 2])
                written = original(descriptor, prefix)
                os.fsync(descriptor)
                partial["bytes"] = prefix[:written]
                raise OSError("actual partial native SEAL write")
            return original(descriptor, raw)
        with mock.patch.object(holdout.os, "write", interrupted):
            with self.assertRaises(Exception):
                self.prepare()
        path = self.root / observation._journal_path(self.charge)
        self.assertEqual(path.read_bytes(), partial["bytes"])
        self.assertFalse(path.read_bytes().endswith(b"\n"))
        self.assertEqual((self.case.snapshot(), self.case.files()), before)
        self.assert_refuses_unchanged(self.prepare)

    def test_bare_observation_event_prefixes_refuse_before_allocation_only_S_publication(self):
        for prefix in ("sim-reserve-preparation-", "sim-reserve-attempt-", "sim-reserve-started-", "sim-reserve-observation-"):
            with self.subTest(prefix=prefix):
                case = allocation_fixtures.SimulatedReserveTests()
                case.setUp()
                self.addCleanup(case.doCleanups)
                event = case.append_note(event_id=prefix + "bare-negative-control")
                self.assertEqual(event.event_type, "CHECKPOINT")
                self.assertEqual(event.metadata, {})
                self.assertEqual(event.artifact_hashes, ())
                before = case.snapshot()
                with self.assertRaises(Exception) as refusal:
                    case.publish()
                after = case.snapshot()
                print("ACTUAL_BARE_PRE_S_PREFIX", {"prefix": prefix,
                    "reason": str(refusal.exception), "records_before": before[0].count,
                    "records_after": after[0].count, "events_before": before[1].event_count,
                    "events_after": after[1].event_count}, flush=True)
                self.assertEqual(after, before)
