"""Native Q1 accounting with real I/S owners; no release or scientific result."""

from dataclasses import replace
import unittest
from unittest import mock

from scientist_one import orchestrator
from scientist_one import simulated_reserve as reserve
from scientist_one import simulated_resource as resource
from scientist_one.ledger import LedgerEvent
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads
import tests.test_resource_backed_simulated_reserve as reserve_fixtures
from tests.test_resource_prepared_cases import (
    prepared_charge_tests, prepared_charge_setup, charge_phase, charge_variants,
    emit_charge_request, original_charge_result,
)


@prepared_charge_tests
class SimulatedConfirmatoryChargeTests(unittest.TestCase):
    def setUp(self):
        if prepared_charge_setup(self):
            return
        self.fixture = reserve_fixtures.ResourceBackedSimulatedReserveTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.case
        self.registry, self.ledger = self.case.registry, self.case.ledger
        if charge_phase() != "S_orphan":
            self.reservation = self.fixture.publish()

    def charge(self, **changes):
        return resource.charge_simulated_confirmatory_reserve(
            self.registry,
            self.ledger,
            **{
                "expected_run_id": self.case.run,
                "reservation_artifact_sha256": (
                    changes["reservation_artifact_sha256"]
                    if "reservation_artifact_sha256" in changes
                    else self.reservation.record.sha256
                ),
                **changes,
            },
        )

    def require(self, result):
        return resource.require_simulated_confirmatory_charge(
            self.registry,
            self.ledger,
            expected_run_id=self.case.run,
            charge_artifact_sha256=result.record.sha256,
        )

    def snapshot(self):
        return self.case.snapshot(), self.case.files()

    def historical(self, result):
        pair = self.case.snapshot()
        return resource._require_simulated_confirmatory_charge_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=self.case.run,
            charge_artifact_sha256=result.record.sha256,
            registry_snapshot=pair[0],
            ledger_snapshot=pair[1],
        )

    def assert_refuses_unchanged(self, operation):
        before = self.snapshot()
        with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
            operation()
        self.assertEqual(self.snapshot(), before)

    def test_native_first_charge_is_eight_units_and_exact_external_ledger_join(self):
        before = self.snapshot()
        result = self.charge()
        initial = self.fixture.initialization
        self.assertEqual(
            (
                result.runtime_state.validity_total_units,
                result.runtime_state.confirmatory_used,
                result.runtime_state.exploratory_used,
            ),
            (40, 8, 0),
        )
        self.assertEqual(
            result.record.parent_artifacts,
            (initial.record.sha256, self.reservation.record.sha256),
        )
        self.assertEqual(
            result.record.logical_type,
            "resource_runtime_confirmatory_charge." + self.reservation.record.sha256,
        )
        self.assertEqual(len(result.record.logical_type), 101)
        self.assertEqual(result.event_index, 2)
        self.assertEqual(result.registry_snapshot.count, before[0][0].count + 1)
        self.assertEqual(result.ledger_snapshot.event_count, 3)
        self.assertEqual(len(self.case.files()), 2)
        value = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertEqual(value["charged_units"], len(self.reservation.member_ids))
        self.assertEqual(
            value["previous_external_authority_sha256"],
            initial.external_authority_sha256,
        )
        self.assertEqual(
            value["source_ledger_head_hash"], self.reservation.event.event_hash
        )
        self.assertEqual(value["validity_reserve_fraction"], 0.4)
        self.assertNotIn("initialization_artifact_sha256", value)
        self.assertNotIn("initialization_record_hash", value)
        for key in (
            "scientific_authority",
            "release_authority",
            "execution_attestation",
            "host_attestation",
            "freshness_authority",
            "e4_authority",
        ):
            self.assertIs(value[key], False)
        self.assertLessEqual(
            result.runtime_state.wall_started_at_epoch_seconds,
            initial.runtime_state.wall_started_at_epoch_seconds + 1e-6,
        )
        self.assertGreaterEqual(
            result.runtime_state.wall_elapsed_seconds,
            initial.runtime_state.wall_elapsed_seconds,
        )
        orchestrator._validate_resource_authority_ledger_for(
            self.case.external(), result.ledger_snapshot.events
        )

    def test_completed_replay_never_restores_recharges_or_observes_time(self):
        result = self.charge()
        before = self.snapshot()
        with mock.patch.object(
            resource.ResourceController,
            "from_runtime_state",
            side_effect=AssertionError("replay restored a controller"),
        ):
            self.assertEqual(self.charge(), result)
            self.assertEqual(self.require(result), result)
            self.assertEqual(self.historical(result), result)
        self.assertEqual(self.snapshot(), before)
        detached = result.runtime_state
        detached.worker_crashes["caller"] = 1
        self.assertEqual(result.runtime_state.worker_crashes, {})

    def test_public_S_consumes_only_completed_Q_and_private_replay_is_finite(self):
        result = self.charge()
        before = self.snapshot()
        owned = self.fixture.require(self.reservation)
        self.assertEqual(owned.record, self.reservation.record)
        self.assertEqual(owned.registry_snapshot, result.registry_snapshot)
        self.assert_refuses_unchanged(
            lambda: self.case.require(self.fixture.initialization)
        )
        self.assert_refuses_unchanged(self.fixture.publish)
        self.assertEqual(self.snapshot(), before)

    def test_external_failure_before_write_leaves_original_sources(self):
        with mock.patch.object(
            resource,
            "_persist_resource_authority_for",
            side_effect=ValueError("injected before external write"),
        ):
            self.assert_refuses_unchanged(self.charge)
        self.assertEqual(self.charge().runtime_state.confirmatory_used, 8)

    def test_external_only_interruption_recovers_exact_state_without_new_charge(self):
        real = resource._persist_resource_authority_for

        def write_then_fail(*args):
            real(*args)
            raise ValueError("interrupted after external write")

        before = self.case.snapshot()
        with mock.patch.object(
            resource, "_persist_resource_authority_for", new=write_then_fail
        ):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(len(self.case.files()), 2)
        external = self.case.files()
        with mock.patch.object(
            resource.ResourceController,
            "from_runtime_state",
            side_effect=AssertionError("orphan recharge"),
        ):
            result = self.charge()
        self.assertEqual(self.case.files(), external)
        self.assertEqual(result.runtime_state.confirmatory_used, 8)

    def test_artifact_prewrite_interruption_recovers_external_only(self):
        before = self.case.snapshot()
        with mock.patch.object(
            resource, "_put", side_effect=ValueError("before artifact")
        ):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(len(self.case.files()), 2)
        self.assertEqual(self.charge().runtime_state.confirmatory_used, 8)

    def test_record_only_interruption_is_unreadable_then_recovers_exact_suffix(self):
        before = self.case.snapshot()
        with mock.patch.object(
            self.ledger, "_append_locked", side_effect=ValueError("before event")
        ):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        after = self.case.snapshot()
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1], before[1])
        self.assert_refuses_unchanged(lambda: self.fixture.require(self.reservation))
        files = self.case.files()
        with mock.patch.object(
            resource.ResourceController,
            "from_runtime_state",
            side_effect=AssertionError("orphan recharge"),
        ):
            result = self.charge()
        self.assertEqual(result.registry_snapshot, after[0])
        self.assertEqual(self.case.files(), files)

    def test_artifact_postwrite_interruption_retains_exact_orphan(self):
        real = resource._put

        def write_then_fail(*args):
            real(*args)
            raise ValueError("after artifact")

        with mock.patch.object(resource, "_put", new=write_then_fail):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.assertEqual(self.case.snapshot()[1].event_count, 2)
        self.assertEqual(len(self.case.files()), 2)
        self.assertEqual(self.charge().runtime_state.confirmatory_used, 8)

    def test_event_postwrite_interruption_is_completed_idempotency(self):
        real = self.ledger._append_locked

        def write_then_fail(*args):
            real(*args)
            raise ValueError("after event")

        with mock.patch.object(self.ledger, "_append_locked", new=write_then_fail):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        before = self.snapshot()
        with mock.patch.object(
            resource.ResourceController,
            "from_runtime_state",
            side_effect=AssertionError("completed recharge"),
        ):
            self.charge()
        self.assertEqual(self.snapshot(), before)

    def test_actual_S_record_without_event_cannot_be_charged(self):
        # The original default I/S setup completed in its own child.
        # This fresh child prepared only I; the actual S fault is unchanged.
        orphan = self.fixture.orphan()
        self.assert_refuses_unchanged(
            lambda: self.charge(reservation_artifact_sha256=orphan.sha256)
        )

    def test_wrong_identity_run_and_legacy_or_window_two_requests_refuse(self):
        self.assert_refuses_unchanged(
            lambda: self.charge(expected_run_id="caller-reset")
        )
        self.assert_refuses_unchanged(
            lambda: self.charge(
                reservation_artifact_sha256=self.fixture.initialization.record.sha256
            )
        )
        self.assert_refuses_unchanged(lambda: self.fixture.publish(window_index=2))

    def test_live_config_source_and_reservation_correction_refuse(self):
        # Exact config/source writes and finally-restoration belong to the
        # parent between completed captures of this SAME project and ledger.
        phase = charge_phase()
        if phase == "seed":
            emit_charge_request(self)
            return
        if phase in {"config_drift", "source_drift"}:
            relative = {
                "config_drift": "configs/resource_limits.json",
                "source_drift": "src/scientist_one/bookkeeping_fixture.py",
            }[phase]
            with self.subTest(relative=relative):
                self.assert_refuses_unchanged(self.charge)
            return
        if phase != "S_correction":
            raise AssertionError("unexpected charge correction phase")
        self.ledger.append_correction(
            self.reservation.event.event_id,
            actor_role=Role.ORCHESTRATOR,
            reason="disputed S",
            corrected_fields={"reason": "disputed"},
        )
        self.assert_refuses_unchanged(self.charge)

    def test_completed_requires_live_source_but_historical_Q_remains_accounting(self):
        if charge_phase() == "seed":
            result = self.charge()
            emit_charge_request(self, result=result)
            return
        # Recovered by the full historical Q owner on the current actual pair;
        # the parent made the original source append between completed captures.
        result = original_charge_result(self)
        self.assert_refuses_unchanged(self.charge)
        self.assert_refuses_unchanged(lambda: self.require(result))
        self.assertEqual(self.historical(result).record, result.record)

    def test_preflight_capacity_refuses_before_external_advance(self):
        pair = self.case.snapshot()
        for name, limit in (
            ("MAX_REGISTRY_RECORDS", pair[0].count),
            ("MAX_LEDGER_EVENTS", pair[1].event_count),
            ("MAX_LEDGER_BYTES", pair[1].valid_prefix_bytes),
            ("_MAX_BYTES", 1),
        ):
            with self.subTest(name=name), mock.patch.object(resource, name, limit):
                self.assert_refuses_unchanged(self.charge)

    def test_prospective_event_failure_is_before_external_advance(self):
        real = resource._charge_event

        def invalid(*args):
            event = real(*args)
            return replace(event, prior_event_hash="f" * 64, event_hash=None)

        with mock.patch.object(resource, "_charge_event", new=invalid):
            self.assert_refuses_unchanged(self.charge)

    def test_outer_I_S_Q_corrections_are_never_refunds(self):
        for label in charge_variants(("I", "S", "Q")):
            with self.subTest(source=label):
                # This variant's original setUp ran in its fresh captured child.
                result = self.charge()
                event = {
                    "I": self.fixture.initialization.event,
                    "S": self.reservation.event,
                    "Q": result.event,
                }[label]
                self.ledger.append_correction(
                    event.event_id,
                    actor_role=Role.ORCHESTRATOR,
                    reason="disputed source",
                    corrected_fields={"reason": "disputed"},
                )
                self.assert_refuses_unchanged(self.charge)
                self.assert_refuses_unchanged(lambda: self.historical(result))

    def test_renamed_Q_schema_and_shared_profile_aliases_refuse(self):
        for marker in charge_variants((
            {"schema_version": "sim-resource-charge/v1"},
            {"profile": reserve.SIMULATED_RESERVE_PROFILE},
            {"nested": {"initialization_artifact_sha256": None}},
        )):
            with self.subTest(marker=marker):
                # This variant's original setUp ran in its fresh captured child.
                result = self.charge()
                self.registry.put_json(
                    marker,
                    logical_type="inert_charge_alias",
                    origin="adversarial inert marker",
                    creator_role=Role.ORCHESTRATOR,
                )
                self.assert_refuses_unchanged(self.charge)
                self.assert_refuses_unchanged(
                    lambda: self.fixture.require(self.reservation)
                )
                self.assert_refuses_unchanged(lambda: self.historical(result))

    def test_malformed_Q_marker_refuses(self):
        self.registry.put_bytes(
            b'{"schema_version":"sim-resource-charge/v1",',
            logical_type="inert_malformed_charge_alias",
            origin="inert malformed marker",
            creator_role=Role.ORCHESTRATOR,
            mime_type="application/json",
        )
        self.assert_refuses_unchanged(self.charge)

    def test_copied_Q_event_does_not_consume_another_slot(self):
        result = self.charge()
        copied = result.event.to_dict()
        copied.update(
            event_id="copied-charge",
            prior_event_hash=self.ledger.assert_valid().head_hash,
            event_hash=None,
        )
        self.ledger.append(LedgerEvent.from_dict(copied))
        self.assert_refuses_unchanged(lambda: self.historical(result))
        self.assert_refuses_unchanged(lambda: self.fixture.require(self.reservation))

    def test_substituted_Q_metadata_is_not_full_owned_exemption(self):
        result = self.charge()
        changed = replace(
            result.record, logical_type="inert_renamed_charge", record_hash=None
        )
        (self.case.root / result.record.metadata_path).write_bytes(
            canonical_json_bytes(changed.to_dict()) + b"\n"
        )
        self.assert_refuses_unchanged(self.charge)
        self.assert_refuses_unchanged(lambda: self.fixture.require(self.reservation))

    def test_external_Q_deleted_or_later_head_cannot_be_recharged(self):
        result = self.charge()
        base = (
            self.case.root / ".scientist-one-build/resource-authority" / self.case.run
        )
        newest = sorted(base.glob("*.json"))[-1]
        raw = newest.read_bytes()
        newest.unlink()
        self.assert_refuses_unchanged(self.charge)
        newest.write_bytes(raw)
        self.fixture.advance_external()
        self.assert_refuses_unchanged(self.charge)
        self.assert_refuses_unchanged(lambda: self.require(result))
        self.assertEqual(self.historical(result).record, result.record)

    def test_external_Q_noncanonical_bytes_fail_native_reader_without_local_delta(self):
        self.charge()
        base = (
            self.case.root / ".scientist-one-build/resource-authority" / self.case.run
        )
        newest = sorted(base.glob("*.json"))[-1]
        value = safe_json_loads(newest.read_bytes())
        raw = canonical_json_bytes(value) + b" \n"
        from scientist_one.security import sha256_bytes

        alternate = newest.with_name("0001-" + sha256_bytes(raw) + ".json")
        newest.unlink()
        alternate.write_bytes(raw)
        self.assert_refuses_unchanged(self.charge)

    def test_orphan_recovery_refuses_after_extra_source(self):
        with mock.patch.object(
            resource, "_put", side_effect=ValueError("after external")
        ):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.registry.put_json(
            {"kind": "INERT_LATER_SOURCE"},
            logical_type="later_note",
            origin="inert later source",
            creator_role=Role.ORCHESTRATOR,
        )
        self.assert_refuses_unchanged(self.charge)

    def test_event_only_Q_alias_refuses_before_external_advance(self):
        self.case.note(
            {"nested": {resource.SIMULATED_CONFIRMATORY_CHARGE_EVENT_KEY: None}}
        )
        self.assert_refuses_unchanged(self.charge)
        self.assert_refuses_unchanged(lambda: self.fixture.require(self.reservation))

    def test_oversized_renamed_Q_schema_aliases_are_unresolved(self):
        for malformed in charge_variants((False, True)):
            with self.subTest(malformed=malformed):
                # This variant's original setUp ran in its fresh captured child.
                result = self.charge()
                raw = (
                    canonical_json_bytes(
                        {
                            "schema_version": "sim-resource-charge/v1",
                            "padding": "x" * (1024 * 1024),
                        }
                    )
                    + b"\n"
                )
                if malformed:
                    raw = raw[:-2]
                self.registry.put_bytes(
                    raw,
                    logical_type="inert_oversized_q_alias",
                    origin="actual renamed bounded alias",
                    creator_role=Role.ORCHESTRATOR,
                    mime_type="application/json",
                )
                self.assert_refuses_unchanged(lambda: self.historical(result))
                self.assert_refuses_unchanged(
                    lambda: self.fixture.require(self.reservation)
                )

    def test_oversized_renamed_I_schema_aliases_are_unresolved(self):
        for malformed in charge_variants((False, True)):
            with self.subTest(malformed=malformed):
                # This variant's original setUp ran in its fresh captured child.
                result = self.charge()
                raw = (
                    canonical_json_bytes(
                        {
                            "schema_version": "sim-resource-initial/v1",
                            "padding": "x" * (1024 * 1024),
                        }
                    )
                    + b"\n"
                )
                if malformed:
                    raw = raw[:-2]
                self.registry.put_bytes(
                    raw,
                    logical_type="inert_oversized_i_alias",
                    origin="actual renamed bounded I alias",
                    creator_role=Role.ORCHESTRATOR,
                    mime_type="application/json",
                )
                for name, read in (
                    ("Q", lambda: self.historical(result)),
                    ("S", lambda: self.fixture.require(self.reservation)),
                ):
                    with self.subTest(owner=name):
                        self.assert_refuses_unchanged(read)

    def test_actual_contract_successor_refuses_new_charge(self):
        from scientist_one.evaluation_contract_amendment import (
            register_evaluation_contract_amendment,
        )

        child = replace(
            self.case.contract,
            version=2,
            success_criteria=("Changed criteria before any release.",),
        )
        successor = register_evaluation_contract_amendment(
            self.registry,
            self.ledger,
            run_id=self.case.run,
            amendment_id="pre-Q-contract-successor",
            parent_contract_artifact_sha256=self.case.contract_record.sha256,
            child_contract=child,
            author_id=self.case.contract.frozen_by,
            reason="Actual pre-observation contract revision fixture.",
            child_evidence_parent_artifact_sha256s=self.case.contract_record.parent_artifacts,
        )
        self.assertEqual(successor.child_contract, child)
        self.assert_refuses_unchanged(self.charge)

    def test_direct_historical_I_census_is_bounded_and_allows_small_unrelated_notes(
        self,
    ):
        for kind in charge_variants(("inert-above", "alias-above", "inert-at-bound")):
            with self.subTest(kind=kind):
                # This variant's original setUp ran in its fresh captured child.
                result = self.charge()
                value = {
                    "schema_version": "sim-resource-initial/v1"
                    if kind == "alias-above"
                    else "inert-note",
                    "padding": "",
                }
                target_size = reserve.MAX_SIMULATED_RESERVE_BYTES + int(
                    kind != "inert-at-bound"
                )
                overhead = len(canonical_json_bytes(value)) + 1
                value["padding"] = "x" * (target_size - overhead)
                raw = canonical_json_bytes(value) + b"\n"
                self.assertEqual(len(raw), target_size)
                self.registry.put_bytes(
                    raw,
                    logical_type="bounded_outer_i_note",
                    origin="actual bounded native I census control",
                    creator_role=Role.ORCHESTRATOR,
                    mime_type="application/json",
                )
                pair = self.case.snapshot()

                def historical_I():
                    return resource._require_simulated_resource_initialization_at_snapshot(
                        self.registry,
                        self.ledger,
                        expected_run_id=self.case.run,
                        initialization_artifact_sha256=self.fixture.initialization.record.sha256,
                        registry_snapshot=pair[0],
                        ledger_snapshot=pair[1],
                    )

                if kind == "inert-at-bound":
                    self.assertEqual(
                        historical_I().record, self.fixture.initialization.record
                    )
                    self.assertEqual(self.historical(result).record, result.record)
                else:
                    self.assert_refuses_unchanged(historical_I)

    def test_complete_Q_historical_reader_is_not_permission_after_later_note(self):
        result = self.charge()
        self.case.note({"kind": "INERT_LATER_NOTE"})
        self.assertEqual(self.historical(result).record, result.record)
        self.assertEqual(
            self.fixture.require(self.reservation).record, self.reservation.record
        )
        self.assert_refuses_unchanged(self.charge)
        self.assert_refuses_unchanged(lambda: self.require(result))

    def test_invalid_membership_debit_is_refused_before_external_advance(self):
        real = resource.ResourceController.charge_validity

        def wrong_charge(controller, stage, units):
            # Adverse native controller output, not a successful authority stub.
            return real(controller, stage, units - 1)

        with mock.patch.object(
            resource.ResourceController, "charge_validity", new=wrong_charge
        ):
            self.assert_refuses_unchanged(self.charge)

    def test_external_read_after_final_live_inventory_detects_late_external_advance(
        self,
    ):
        result = self.charge()
        real = resource._charge_live_sources
        calls = 0

        def read_then_advance(*args):
            nonlocal calls
            real(*args)
            calls += 1
            self.fixture.advance_external()

        before = self.case.snapshot()
        with mock.patch.object(resource, "_charge_live_sources", new=read_then_advance):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.require(result)
        self.assertEqual(calls, 1)
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(len(self.case.files()), 3)

    def test_paired_source_drift_after_current_contract_read_refuses(self):
        real = resource._charge_current_contract
        calls = 0

        def read_then_note(*args):
            nonlocal calls
            real(*args)
            calls += 1
            self.case.note({"kind": "AFTER_CURRENTNESS_READ"})

        files = self.case.files()
        with mock.patch.object(
            resource, "_charge_current_contract", new=read_then_note
        ):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.assertGreaterEqual(calls, 1)
        self.assertEqual(self.case.files(), files)

    def test_current_Q_external_head_drift_after_event_is_detected_without_refund(self):
        real = self.ledger._append_locked

        def append_then_advance(*args):
            result = real(*args)
            self.fixture.advance_external()
            return result

        with mock.patch.object(self.ledger, "_append_locked", new=append_then_advance):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.charge()
        self.assertEqual(self.case.snapshot()[1].event_count, 3)
        self.assertEqual(len(self.case.files()), 3)
        self.assert_refuses_unchanged(self.charge)

    def test_final_live_inventory_read_detects_source_drift_after_read(self):
        result = self.charge()
        real = resource._charge_live_sources
        path = self.case.root / self.ledger.relative_path
        original = path.read_bytes()
        body = result.event.to_dict()
        body.update(
            event_id="late-inert-event",
            artifact_hashes=[],
            metadata={},
            prior_event_hash=result.event.event_hash,
            event_hash=None,
        )
        extra = LedgerEvent.from_dict(body)
        calls = 0

        def read_then_change(*args):
            nonlocal calls
            real(*args)
            calls += 1
            if calls == 1:
                # Actual native event bytes appended by an adversarial writer;
                # no public append or mutation-lock reentry inside the read.
                path.write_bytes(
                    original + canonical_json_bytes(extra.to_dict()) + b"\n"
                )

        external = self.case.files()
        with mock.patch.object(resource, "_charge_live_sources", new=read_then_change):
            with self.assertRaises((ValueError, orchestrator.OrchestrationError)):
                self.require(result)
        self.assertEqual(calls, 1)
        self.assertEqual(self.ledger.assert_valid().event_count, 4)
        self.assertEqual(self.case.files(), external)


if __name__ == "__main__":
    unittest.main()
