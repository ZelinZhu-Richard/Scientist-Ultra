"""Real I0 -> S1 allocation bookkeeping, never Q/J, release or science."""

from dataclasses import replace
import os
import unittest
from unittest import mock

from scientist_one import simulated_reserve as reserve
from scientist_one import simulated_resource as resource
from scientist_one import orchestrator
from scientist_one.ledger import LedgerEvent
from scientist_one.models import thaw_json
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.scientific_design import register_frozen_evaluation_contract
import tests.test_simulated_resource as initialization_fixtures
from tests.test_resource_prepared_cases import prepared_reserve_tests


@prepared_reserve_tests
class ResourceBackedSimulatedReserveTests(unittest.TestCase):
    def setUp(self):
        self.case = initialization_fixtures.SimulatedResourceTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.registry, self.ledger = self.case.registry, self.case.ledger
        self.initialization = self.case.initialize()

    def publish(self, **changes):
        values = {
            "expected_run_id": self.case.run,
            "protocol_artifact_sha256": self.case.protocol_record.sha256,
            "contract_artifact_sha256": self.case.contract_record.sha256,
            "population_artifact_sha256": self.case.population.sha256,
            "window_index": 1,
            "initialization_artifact_sha256": self.initialization.record.sha256,
        }
        values.update(changes)
        return reserve.register_simulated_confirmatory_reserve(
            self.registry, self.ledger, **values
        )

    def require(self, publication):
        return reserve.require_simulated_confirmatory_reserve(
            self.registry,
            self.ledger,
            expected_run_id=self.case.run,
            reservation_artifact_sha256=publication.record.sha256,
        )

    def snapshot(self):
        return self.case.snapshot()

    def advance_external(self):
        return orchestrator._persist_resource_authority_for(
            self.root,
            self.case.run,
            "resource_runtime_unprojected_stage",
            self.initialization.runtime_state.to_dict(),
        )

    def remove_external(self):
        path = next(
            (
                self.root / ".scientist-one-build/resource-authority" / self.case.run
            ).glob("*.json")
        )
        path.unlink()

    def orphan(self):
        with mock.patch.object(
            self.ledger, "_append_locked", side_effect=OSError("actual S append fault")
        ):
            with self.assertRaises(orchestrator.OrchestrationError):
                self.publish()
        return next(
            record
            for record in self.snapshot()[0].records
            if record.logical_type == "frozen_confirmatory_split"
        )

    def test_real_initialization_then_first_reservation_has_exact_parent_and_seal(self):
        before, external = self.snapshot(), self.case.files()
        result = self.publish()
        body = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertEqual(result.record.schema_version, "sim-reserve/v2")
        self.assertEqual(body["schema_version"], "sim-reserve/v2")
        self.assertEqual(
            result.record.parent_artifacts,
            (
                self.case.population.sha256,
                self.case.protocol_record.sha256,
                self.case.contract_record.sha256,
                self.initialization.record.sha256,
            ),
        )
        self.assertEqual(result.event_index, 1)
        self.assertEqual(body["source_ledger_event_count"], 1)
        self.assertEqual(
            body["source_ledger_head_hash"], self.initialization.event.event_hash
        )
        self.assertIn(
            [self.initialization.record.sha256, self.initialization.record.record_hash],
            body["source_registry_identities"],
        )
        self.assertNotIn("initialization_artifact_sha256", body)
        self.assertNotIn("initialization_record_hash", body)
        self.assertEqual(
            thaw_json(result.event.metadata)[reserve.SIMULATED_RESERVE_EVENT_KEY][
                "schema_version"
            ],
            "sim-reserve-event/v2",
        )
        self.assertEqual(
            result.member_ids, ("c01", "c02", "c03", "c04", "t01", "t02", "t03", "t04")
        )
        self.assertEqual(body["reservation_units"], 8)
        self.assertEqual(result.registry_snapshot.count, before[0].count + 1)
        self.assertEqual(result.ledger_snapshot.event_count, before[1].event_count + 1)
        self.assertEqual(self.case.files(), external)
        self.assertEqual(self.initialization.runtime_state.confirmatory_used, 0)
        self.assertEqual(self.require(result), result)

    def test_completed_replay_is_zero_delta_and_native_I_lower_replay_is_finite(self):
        result = self.publish()
        before, external = self.snapshot(), self.case.files()
        self.assertEqual(self.publish(), result)
        self.assertEqual(self.require(result), result)
        owned = resource._require_simulated_resource_initialization_at_snapshot(
            self.registry,
            self.ledger,
            expected_run_id=self.case.run,
            initialization_artifact_sha256=self.initialization.record.sha256,
            registry_snapshot=before[0],
            ledger_snapshot=before[1],
        )
        self.assertEqual(owned.record, self.initialization.record)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_explicit_none_does_not_upgrade_or_discover_I(self):
        before, external = self.snapshot(), self.case.files()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish(initialization_artifact_sha256=None)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_window_two_refuses_before_new_or_existing_orphan_return(self):
        for phase in ("new", "orphan", "completed"):
            with self.subTest(phase=phase):
                if phase == "orphan":
                    self.orphan()
                elif phase == "completed":
                    self.publish()
                before, external = self.snapshot(), self.case.files()
                with self.assertRaises(reserve.SimulatedReserveError):
                    self.publish(window_index=2)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.case.files(), external)

    def test_wrong_initialization_identity_and_run_refuse(self):
        for changes in (
            {"initialization_artifact_sha256": self.case.protocol_record.sha256},
            {"expected_run_id": "wrong-run"},
        ):
            with self.subTest(changes=changes):
                before, external = self.snapshot(), self.case.files()
                with self.assertRaises(ValueError):
                    self.publish(**changes)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.case.files(), external)

    def test_deleted_external_initialization_does_not_reinitialize(self):
        self.remove_external()
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), ())

    def test_advanced_external_without_local_projection_refuses(self):
        self.advance_external()
        before, external = self.snapshot(), self.case.files()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_exact_S_orphan_recovers_no_new_external_head_or_artifact(self):
        orphan = self.orphan()
        before, external = self.snapshot(), self.case.files()
        result = self.publish()
        self.assertEqual(result.record, orphan)
        self.assertEqual(result.registry_snapshot, before[0])
        self.assertEqual(result.ledger_snapshot.event_count, 2)
        self.assertEqual(self.case.files(), external)

    def test_orphan_with_deleted_external_head_remains_unresolved(self):
        self.orphan()
        self.remove_external()
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), ())

    def test_orphan_with_advanced_external_head_remains_unresolved(self):
        self.orphan()
        self.advance_external()
        before, external = self.snapshot(), self.case.files()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_historical_S_read_is_not_external_currentness_or_new_allocation(self):
        result = self.publish()
        self.advance_external()
        before, external = self.snapshot(), self.case.files()
        self.assertEqual(self.require(result), result)
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_I_correction_is_not_ignored_by_later_S_read(self):
        result = self.publish()
        self.ledger.append_correction(
            self.initialization.event.event_id,
            actor_role=Role.ORCHESTRATOR,
            reason="native I correction fixture",
            corrected_fields={"reason": "disputed"},
        )
        before, external = self.snapshot(), self.case.files()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.require(result)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_outer_I_aliases_do_not_receive_native_I_exemption(self):
        result = self.publish()
        self.case.note(
            {"nested": {resource.SIMULATED_RESOURCE_INITIAL_EVENT_KEY: None}}
        )
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.require(result)
        self.assertEqual(self.snapshot(), before)

    def test_v2_schema_only_alias_and_copied_event_refuse(self):
        result = self.publish()
        self.registry.put_json(
            {"schema_version": "sim-reserve/v2"},
            logical_type="inert_v2_alias",
            origin="unresolved v2 marker",
            creator_role=Role.ORCHESTRATOR,
        )
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.require(result)
        self.assertEqual(self.snapshot(), before)

    def test_substituted_fourth_parent_does_not_rebind_initialization(self):
        result = self.publish()
        changed = replace(
            result.record,
            parent_artifacts=(
                *result.record.parent_artifacts[:3],
                self.case.source.sha256,
            ),
            record_hash=None,
        )
        (self.root / result.record.metadata_path).write_bytes(
            canonical_json_bytes(changed.to_dict()) + b"\n"
        )
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.require(result)
        self.assertEqual(self.snapshot(), before)

    def test_postpublication_external_advance_is_detected_and_evidence_retained(self):
        real = self.ledger._append_locked

        def append_then_advance(guard, build):
            event = real(guard, build)
            self.advance_external()
            return event

        with mock.patch.object(self.ledger, "_append_locked", new=append_then_advance):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        self.assertEqual(self.snapshot()[1].event_count, 2)
        self.assertEqual(len(self.case.files()), 2)

    def test_native_v2_event_copy_cannot_consume_another_slot(self):
        result = self.publish()
        value = result.event.to_dict()
        value.update(
            event_id="inert-copied-S",
            prior_event_hash=self.ledger.assert_valid().head_hash,
            event_hash=None,
        )
        self.ledger.append(LedgerEvent.from_dict(value))
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.require(result)
        self.assertEqual(self.snapshot(), before)

    def test_malformed_external_chain_has_public_reservation_refusal_type(self):
        path = next(
            (
                self.root / ".scientist-one-build/resource-authority" / self.case.run
            ).glob("*.json")
        )
        path.write_bytes(b"{")
        before, external = self.snapshot(), self.case.files()
        with self.assertRaises(reserve.SimulatedReserveError):
            self.publish()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.case.files(), external)

    def test_owned_protocol_and_contract_cannot_be_substituted(self):
        changed_protocol = replace(self.case.protocol, study_id="other-native-study")
        protocol_body = safe_json_loads(
            self.registry.get_bytes(self.case.protocol_record.sha256)
        )
        protocol_body["protocol"] = changed_protocol.canonical_dict
        protocol_body["protocol_sha256"] = changed_protocol.sha256
        other_protocol = self.registry.put_json(
            protocol_body,
            logical_type="frozen_protocol",
            origin="native alternate component protocol",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        other_contract = register_frozen_evaluation_contract(
            self.registry,
            contract=replace(self.case.contract, contract_id="other-contract"),
            parent_artifact_sha256s=self.case.contract_record.parent_artifacts,
        )
        for changes in (
            {"protocol_artifact_sha256": other_protocol.sha256},
            {"contract_artifact_sha256": other_contract.sha256},
        ):
            with self.subTest(changes=changes):
                before, external = self.snapshot(), self.case.files()
                with self.assertRaises(reserve.SimulatedReserveError):
                    self.publish(**changes)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.case.files(), external)

    def test_v2_aliases_still_trigger_negative_scientific_guard(self):
        record = self.registry.put_json(
            {"schema_version": ["sim-reserve/v2"]},
            logical_type="inert_v2_schema_marker",
            origin="negative-only marker",
            creator_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(reserve.SimulatedReserveError):
            reserve.reject_simulated_reserve_exposure(
                self.registry, (record,), (), complete_registry_population=True
            )
        event = self.case.note(
            {"renamed": {"schema_version": {"sim-reserve-event/v2": None}}}
        )
        with self.assertRaises(reserve.SimulatedReserveError):
            reserve.reject_simulated_reserve_exposure(
                self.registry, (), (event,), complete_registry_population=False
            )

    def test_completed_existing_return_rechecks_late_external_advance(self):
        self.publish()
        external_identity = next(
            (
                self.root / ".scientist-one-build/resource-authority" / self.case.run
            ).glob("*.json")
        ).stat()
        real_close, real_fstat = os.close, os.fstat
        injected = False

        def close_then_advance(descriptor):
            nonlocal injected
            try:
                metadata = real_fstat(descriptor)
                selected = (metadata.st_dev, metadata.st_ino) == (
                    external_identity.st_dev,
                    external_identity.st_ino,
                )
            except OSError:
                selected = False
            returned = real_close(descriptor)
            if selected and not injected:
                injected = True
                self.advance_external()
            return returned

        before = self.snapshot()
        with mock.patch.object(os, "close", new=close_then_advance):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        self.assertTrue(injected)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(len(self.case.files()), 2)
