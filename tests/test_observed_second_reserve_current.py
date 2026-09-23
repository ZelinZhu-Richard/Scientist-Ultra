"""Current26 successor: 23 mapped bodies and three NEW_REGRESSION_TEST controls.

Original missing-I-S and captured-original rewrite coverage is unreproduced.
All native authorities are real; no scientific authority follows.
"""
from dataclasses import replace
from contextlib import contextmanager, ExitStack
import hashlib
from pathlib import Path
from unittest import mock
import unittest

from scientist_one import simulated_reserve as reserve
from scientist_one import simulated_resource as accounting
from scientist_one import simulated_observation as observation
from scientist_one import scientific_protocol_revision as protocols
from scientist_one import evaluation_contract_amendment as amendments
from scientist_one.holdout import HoldoutCustodyError
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.orchestrator import OrchestrationError
from scientist_one.models import utc_now
from scientist_one.resources import ResourceController, conservative_disk_reserve
from scientist_one.roles import Role
from scientist_one.scientific_design import ReportingRegime
from scientist_one.security import canonical_json_bytes, safe_json_loads
import tests.test_observed_contract_v2 as fixtures
import tests.test_simulated_reserve as allocation_fixtures
import tests.test_simulated_resource as initialization_fixtures
import tests.test_resource_backed_simulated_reserve as resource_reserve_fixtures


import tests.test_resource_prepared_cases as prepared


@prepared.prepared_second_tests
class ObservedSecondReserveTests(unittest.TestCase):
    def setUp(self):
        if prepared.second_setup(self):
            return
        self.a = fixtures.ObservedContractV2Tests()
        self.addCleanup(self.a.doCleanups)
        self.a.setUp()
        self.case = self.a.case
        self.registry, self.ledger, self.root = self.case.registry, self.case.ledger, self.case.root
        self.j = self.a.j
        if self._testMethodName == "test_actual_best_of_n_A2_P2_is_not_supported_S2":
            seed_plan = self.a.child.seed_reporting
            self.a.child = replace(self.a.child, seed_reporting=replace(
                seed_plan, regime=ReportingRegime.BEST_OF_N, best_of_n=len(seed_plan.seeds)))
        self.amendment = self.a.publish()
        parent_p = self.case.reservation.protocol
        child_p = replace(parent_p, study_version=parent_p.study_version + 1,
            parent_protocol_hash=parent_p.sha256, revision_reason=self.amendment.authority.amendment.reason,
            stopping_rules=self.a.child.stopping_criteria)
        self.revision = protocols.register_scientific_protocol_revision(
            self.registry, self.ledger, expected_run_id=self.case.case.run,
            amendment_artifact_sha256=self.amendment.amendment_record.sha256,
            parent_protocol_artifact_sha256=self.case.reservation.protocol_record.sha256,
            protocol=child_p,
        )

    def request(self, **changes):
        return dict(expected_run_id=self.case.case.run,
            protocol_artifact_sha256=self.revision.protocol_record.sha256,
            contract_artifact_sha256=self.amendment.contract_record.sha256,
            population_artifact_sha256=self.case.reservation.population_record.sha256,
            window_index=2, initialization_artifact_sha256=self.case.initialization.record.sha256,
            prior_reservation_artifact_sha256=self.case.reservation.record.sha256,
            prior_observation_artifact_sha256=self.j.record.sha256, **changes)

    def publish(self, **changes):
        args = self.request()
        args.update(changes)
        return reserve.register_simulated_confirmatory_reserve(self.registry, self.ledger, **args)

    def require(self, result):
        return reserve.require_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.case.run, reservation_artifact_sha256=result.record.sha256)

    def historical(self, result):
        return reserve._require_simulated_confirmatory_reserve_at_snapshot(
            self.registry, self.ledger, expected_run_id=self.case.case.run,
            reservation_artifact_sha256=result.record.sha256,
            registry_snapshot=result.registry_snapshot, ledger_snapshot=result.ledger_snapshot)

    def snapshot(self):
        return self.case.snapshot()

    def assert_refuses_unchanged(self, operation):
        before = self.snapshot()
        with self.assertRaises(reserve.SimulatedReserveError):
            operation()
        self.assertEqual(self.snapshot(), before)

    def planned(self):
        pair = self.case.case.snapshot()
        sources = reserve._observed_second_sources(self.registry, self.ledger, pair,
            run_id=self.case.case.run, protocol_sha=self.revision.protocol_record.sha256,
            contract_sha=self.amendment.contract_record.sha256,
            population_sha=self.case.reservation.population_record.sha256,
            initialization_sha=self.case.initialization.record.sha256,
            prior_reservation_sha=self.case.reservation.record.sha256,
            prior_observation_sha=self.j.record.sha256)
        at = utc_now()
        return at, reserve._observed_second_plan(self.registry, self.ledger, pair, *sources, at)

    @contextmanager
    def event_fault(self, *, after=False):
        original = self.ledger._append_locked
        def interrupted(*args, **kwargs):
            if after:
                original(*args, **kwargs)
            raise OSError("actual S2 event interruption")
        with mock.patch.object(self.ledger, "_append_locked", interrupted):
            yield

    def test_actual_J_A_P_S2_disjoint_members_with_no_new_debit_or_release(self):
        before = self.snapshot()
        with mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("new experiment")), \
             mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("new debit")):
            result = self.publish()
        self.assertEqual(result.window_index, 2)
        self.assertEqual(result.member_ids, ("c05", "c06", "c07", "c08", "t05", "t06", "t07", "t08"))
        self.assertFalse(set(result.member_ids) & set(self.case.reservation.member_ids))
        self.assertEqual(result.record.schema_version, "sim-reserve/v3")
        self.assertEqual(result.event.metadata[reserve.SIMULATED_RESERVE_EVENT_KEY]["schema_version"], "sim-reserve-event/v3")
        self.assertEqual(result.event.artifact_hashes, (result.record.sha256,))
        self.assertNotIn("resource_authority_checkpoint", result.event.metadata)
        self.assertEqual(result.record.parent_artifacts, (
            self.case.reservation.population_record.sha256, self.revision.protocol_record.sha256,
            self.amendment.contract_record.sha256, self.case.initialization.record.sha256,
            self.case.reservation.record.sha256, self.j.record.sha256, self.amendment.amendment_record.sha256))
        payload = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertTrue(payload["allocation_consumed_on_record_publication"])
        self.assertEqual(payload["additional_validity_units"], 0)
        for claim in ("scientific_evidence", "scientific_freshness_authorized", "release_authorized",
                      "e4_authorized", "resource_charge_authorized", "execution_attestation_authorized", "host_attestation_authorized"):
            self.assertIs(payload[claim], False)
        self.assertEqual(result.registry_snapshot.count, before[0][0].count + 1)
        self.assertEqual(result.ledger_snapshot.event_count, before[0][1].event_count + 1)
        self.assertEqual(self.snapshot()[1:], before[1:])
        self.assertEqual(self.j.preparation.charge.runtime_state.confirmatory_used, 8)
        self.assertEqual(self.require(result), result)
        first = self.require(self.case.reservation)
        self.assertEqual(first.record, self.case.reservation.record)
        self.assertEqual((first.registry_snapshot, first.ledger_snapshot), (result.registry_snapshot, result.ledger_snapshot))
        self.assertEqual(amendments.require_evaluation_contract_amendment(self.registry, self.ledger,
            amendment_artifact_sha256=self.amendment.amendment_record.sha256,
            expected_run_id=self.case.case.run), self.amendment)
        self.assertEqual(protocols.require_scientific_protocol_revision(self.registry, self.ledger,
            expected_run_id=self.case.case.run, protocol_artifact_sha256=self.revision.protocol_record.sha256), self.revision)
        before_charge = self.snapshot()
        charged = accounting.charge_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.case.run, reservation_artifact_sha256=result.record.sha256)
        self.assertEqual(charged.record.schema_version, "sim-resource-charge/v2")
        self.assertEqual(charged.record.parent_artifacts, (self.j.attempt.record.sha256, result.record.sha256))
        self.assertEqual(charged.runtime_state.confirmatory_used, 16)
        self.assertEqual(charged.runtime_state.exploratory_used, 0)
        external = accounting._read_resource_authority_records(self.root, self.case.case.run)
        self.assertEqual(tuple(item["sequence"] for item in external), (0, 1, 2, 3))
        self.assertEqual(tuple(item["state"]["runtime_state"]["confirmatory_used"] for item in external), (0, 8, 8, 16))
        after_charge = self.snapshot()
        self.assertEqual(after_charge[0][0].count, before_charge[0][0].count + 1)
        self.assertEqual(after_charge[0][1].event_count, before_charge[0][1].event_count + 1)
        self.assertEqual(after_charge[1][:-1], before_charge[1])
        self.assertEqual(after_charge[2], before_charge[2])

    def test_completed_replay_and_retry_are_pure_historical(self):
        result = self.publish()
        before = self.snapshot()
        with mock.patch.object(accounting, "_read_resource_authority_records", side_effect=AssertionError("external read")), \
             mock.patch.object(accounting, "_charge_live_sources", side_effect=AssertionError("live sources")), \
             mock.patch.object(observation, "_provider", side_effect=AssertionError("custody")), \
             mock.patch.object(ResourceController, "from_runtime_state", side_effect=AssertionError("controller")):
            self.assertEqual(self.require(result), result)
            self.assertEqual(self.historical(result), result)
            self.assertEqual(self.publish(), result)
        self.assertEqual(self.snapshot(), before)

    def test_exact_selectors_wrong_ancestors_and_third_window_refuse(self):
        class EqualText(str):
            def __eq__(self, other): return True
            def __ne__(self, other): return False
            __hash__ = str.__hash__
        for changes in (
            {"window_index": True}, {"window_index": 1}, {"window_index": 3},
            {"initialization_artifact_sha256": None}, {"prior_reservation_artifact_sha256": None},
            {"prior_observation_artifact_sha256": None}, {"prior_observation_artifact_sha256": True},
            {"prior_observation_artifact_sha256": EqualText(self.j.record.sha256)},
            {"prior_observation_artifact_sha256": "g" * 64},
            {"prior_observation_artifact_sha256": self.case.charge.record.sha256},
            {"initialization_artifact_sha256": self.case.charge.record.sha256},
            {"prior_reservation_artifact_sha256": self.j.record.sha256},
            {"protocol_artifact_sha256": self.case.reservation.protocol_record.sha256},
            {"contract_artifact_sha256": self.case.reservation.contract_record.sha256},
        ):
            with self.subTest(changes=changes):
                self.assert_refuses_unchanged(lambda: self.publish(**changes))

    def test_actual_best_of_n_A2_P2_is_not_supported_S2(self):
        self.assertIs(self.amendment.child_contract.seed_reporting.regime, ReportingRegime.BEST_OF_N)
        self.assertEqual(self.revision.protocol.seed_policy.seeds, self.amendment.child_contract.seed_reporting.seeds)
        self.assert_refuses_unchanged(self.publish)

    def test_interruption_before_artifact_has_no_allocation_delta(self):
        with mock.patch.object(reserve, "_put_locked", side_effect=OSError("before actual S2 artifact")):
            self.assert_refuses_unchanged(self.publish)
        self.require(self.publish())

    def test_interruption_after_actual_artifact_recovers_exact_orphan(self):
        before = self.snapshot()
        original = reserve._put_locked
        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("after actual S2 artifact")
        with mock.patch.object(reserve, "_put_locked", interrupted):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        orphan = self.snapshot()
        self.assertEqual(orphan[0][0].count, before[0][0].count + 1)
        self.assertEqual(orphan[0][1], before[0][1])
        self.assertEqual(orphan[1:], before[1:])
        self.assert_refuses_unchanged(lambda: self.publish(initialization_artifact_sha256=self.case.charge.record.sha256))
        result = self.publish()
        self.assertEqual(result.registry_snapshot, orphan[0][0])
        self.assertEqual(result.ledger_snapshot.event_count, orphan[0][1].event_count + 1)
        self.assertEqual(self.snapshot()[1:], before[1:])

    def test_interruption_before_event_retains_record_and_can_finish_once(self):
        with self.event_fault():
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        pair = self.case.case.snapshot()
        records = [record for record in pair[0].records if record.schema_version == reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA]
        self.assertEqual(len(records), 1)
        for digest in (records[0].sha256, self.case.reservation.record.sha256):
            self.assert_refuses_unchanged(lambda: reserve.require_simulated_confirmatory_reserve(
                self.registry, self.ledger, expected_run_id=self.case.case.run, reservation_artifact_sha256=digest))
        result = self.publish()
        self.assertEqual(result.record, records[0])
        self.assertEqual(self.publish(), result)

    def test_fresh_native_readers_complete_exact_record_only_orphan_once(self):
        before = self.snapshot()
        with self.event_fault():
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        orphan = self.snapshot()
        record, = [record for record in orphan[0][0].records
                   if record.schema_version == reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA]
        registry = ArtifactRegistry(self.root, Path("runs") / self.case.case.run / "registry")
        ledger = EventLedger(self.root, Path("runs") / self.case.case.run / "events.jsonl")
        self.assertIsNot(registry, self.registry)
        self.assertIsNot(ledger, self.ledger)
        result = reserve.register_simulated_confirmatory_reserve(registry, ledger, **self.request())
        complete = self.snapshot()
        self.assertEqual(result.record, record)
        self.assertEqual(complete[0][0], orphan[0][0])
        self.assertEqual(complete[0][1].event_count, orphan[0][1].event_count + 1)
        self.assertEqual(complete[1:], before[1:])
        self.assertEqual(reserve.register_simulated_confirmatory_reserve(
            registry, ledger, **self.request()), result)
        self.assertEqual(reserve.require_simulated_confirmatory_reserve(registry, ledger,
            expected_run_id=self.case.case.run, reservation_artifact_sha256=record.sha256), result)
        self.assertEqual(self.snapshot(), complete)

    def test_interruption_after_actual_event_is_completed_historical_retry(self):
        before = self.snapshot()
        with self.event_fault(after=True):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        complete = self.snapshot()
        self.assertEqual(complete[0][0].count, before[0][0].count + 1)
        self.assertEqual(complete[0][1].event_count, before[0][1].event_count + 1)
        result = self.publish()
        self.assertEqual(self.snapshot(), complete)
        self.assertEqual(result.record.schema_version, reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA)

    def test_orphan_refuses_unknown_source_delta_without_reassignment(self):
        with self.event_fault():
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        self.case.note({"unknown": "actual post-orphan source delta"})
        self.assert_refuses_unchanged(self.publish)

    def test_event_only_slot_refuses_before_publication_and_lower_public_S_read(self):
        _at, (_value, record, event) = self.planned()
        self.ledger.append(event)
        self.assertNotIn(record, self.case.case.snapshot()[0].records)
        self.assert_refuses_unchanged(self.publish)
        self.assert_refuses_unchanged(lambda: self.require(self.case.reservation))
        self.assert_refuses_unchanged(lambda: reserve.require_simulated_confirmatory_reserve(
            self.registry, self.ledger, expected_run_id=self.case.case.run, reservation_artifact_sha256=record.sha256))

    def test_global_count_and_ledger_byte_caps_refuse_before_artifact(self):
        pair = self.case.case.snapshot()
        for name, value in (("MAX_REGISTRY_RECORDS", pair[0].count),
                            ("MAX_LEDGER_EVENTS", pair[1].event_count),
                            ("MAX_LEDGER_BYTES", pair[1].valid_prefix_bytes)):
            with self.subTest(limit=name), mock.patch.object(reserve, name, value):
                self.assert_refuses_unchanged(self.publish)
        with mock.patch.object(reserve, "utc_now", return_value=self.case.initialization.record.created_at):
            self.assert_refuses_unchanged(self.publish)

    def test_real_disk_scalar_margin_includes_new_native_metadata(self):
        at, (value, record, event) = self.planned()
        config = self.case.initialization.config
        total = 10**9
        margin = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
        body_bytes = len(canonical_json_bytes(value)) + 1
        event_bytes = len(canonical_json_bytes(event.to_dict())) + 1
        metadata_bytes = len(canonical_json_bytes(record.to_dict())) + 1
        free = margin + body_bytes + event_bytes + metadata_bytes // 2
        with mock.patch.object(reserve, "utc_now", return_value=at), \
             mock.patch.object(ResourceController, "_probe_disk", return_value=(total, free, None)):
            self.assert_refuses_unchanged(self.publish)

    def test_orphan_event_only_capacity_needs_no_new_metadata_or_experiment(self):
        with self.event_fault():
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        pair = self.case.case.snapshot()
        record, = [record for record in pair[0].records if record.schema_version == reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA]
        value = safe_json_loads(self.registry.get_bytes(record.sha256))
        source = reserve._source_pair(pair, value)
        sources = reserve._observed_second_sources(self.registry, self.ledger, source,
            run_id=self.case.case.run, protocol_sha=self.revision.protocol_record.sha256,
            contract_sha=self.amendment.contract_record.sha256, population_sha=self.case.reservation.population_record.sha256,
            initialization_sha=self.case.initialization.record.sha256, prior_reservation_sha=self.case.reservation.record.sha256,
            prior_observation_sha=self.j.record.sha256)
        _value, _record, event = reserve._observed_second_plan(self.registry, self.ledger, source, *sources, value["recorded_at"])
        event_bytes = len(canonical_json_bytes(event.to_dict())) + 1
        config, total = self.case.initialization.config, 10**9
        margin = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
        with mock.patch.object(reserve, "MAX_REGISTRY_RECORDS", pair[0].count), \
             mock.patch.object(reserve, "MAX_LEDGER_EVENTS", pair[1].event_count + 1), \
             mock.patch.object(reserve, "MAX_LEDGER_BYTES", pair[1].valid_prefix_bytes + event_bytes), \
             mock.patch.object(ResourceController, "_probe_disk", return_value=(total, margin + event_bytes + 1, None)), \
             mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("new experiment")):
            result = self.publish()
        self.assertEqual(result.record, record)

    def test_renamed_v3_alias_before_publication_refuses_closed_source(self):
        self.case.note({"renamed": {"schema_version": "sim-reserve/v3", "window_index": 2}})
        self.assert_refuses_unchanged(self.publish)
        self.assert_refuses_unchanged(lambda: self.require(self.case.reservation))

    def test_unknown_or_renamed_outer_after_S2_refuses_both_public_readers(self):
        result = self.publish()
        self.case.note({"renamed": {"schema_version": "sim-reserve/v999", "prior_observation_artifact_sha256": self.j.record.sha256}})
        for item in (result, self.case.reservation):
            self.assert_refuses_unchanged(lambda: self.require(item))
        self.assertEqual(self.historical(result), result)

    def test_later_dependency_correction_refuses_outer_not_sealed_history(self):
        result = self.publish()
        self.ledger.append_correction(self.j.event.event_id, actor_role=Role.ORCHESTRATOR,
            reason="Retained negative dependency correction", corrected_fields={"status": "RETRACTED"})
        for item in (result, self.case.reservation):
            self.assert_refuses_unchanged(lambda: self.require(item))
        self.assertEqual(self.historical(result), result)

    def test_live_configuration_source_external_and_custody_drift_refuse_new_S2(self):
        if prepared.second_phase() == 'seed':
            prepared.emit_second_seed(self)
            return
        path = prepared.second_drift_path(self)
        with self.subTest(path=path.name):
            self.assert_refuses_unchanged(self.publish)

    def test_real_late_registry_CAS_drift_refuses_before_S2_artifact(self):
        before = self.snapshot()
        original = reserve._observed_second_capacity
        calls = []
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            if not calls:
                calls.append(True)
                self.case.note({"actual": "late prewrite CAS drift"})
            return result
        with mock.patch.object(reserve, "_observed_second_capacity", drift):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        after = self.snapshot()
        self.assertEqual(len(calls), 1)
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1], before[0][1])
        self.assertFalse(any(record.schema_version == reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA for record in after[0][0].records))
        self.assertEqual(after[1:], before[1:])

    def test_actual_replaced_native_journal_inode_refuses_new_S2(self):
        path = self.root / observation._journal_path(self.case.charge)
        raw, inode = path.read_bytes(), path.stat().st_ino
        path.rename(path.with_suffix(".retained-original"))
        path.write_bytes(raw)
        self.assertNotEqual(path.stat().st_ino, inode)
        self.assert_refuses_unchanged(self.publish)

    def test_postwrite_custody_drift_refuses_return_but_preserves_allocation(self):
        before = self.snapshot()
        original = reserve._require_observed_second_at_snapshot
        calls = []
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            path = self.root / observation._journal_path(self.case.charge)
            path.write_bytes(path.read_bytes() + b" ")
            return result
        with mock.patch.object(reserve, "_require_observed_second_at_snapshot", drift):
            with self.assertRaises(reserve.SimulatedReserveError):
                self.publish()
        self.assertEqual(len(calls), 1)
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(after[1], before[1])
        self.assertNotEqual(after[2], before[2])
        record, = [record for record in after[0][0].records if record.schema_version == reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA]
        result = reserve.require_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.case.case.run, reservation_artifact_sha256=record.sha256)
        self.assertEqual(result.record, record)



    def test_post_static_registry_append_fails_final_paired_CAS_with_allocation_retained(self):
        before = self.snapshot()
        original = reserve._require_observed_second_at_snapshot
        completed = []
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            completed.append(result[0])
            self.case.note({"actual": "registry append after complete static S2 readback"})
            return result
        with mock.patch.object(reserve, "_require_observed_second_at_snapshot", drift):
            with self.assertRaises(reserve.SimulatedReserveError) as raised:
                self.publish()
        self.assertEqual(len(completed), 1)
        chain, error = [], raised.exception
        while error is not None:
            chain.append(str(error))
            error = error.__cause__
        self.assertIn("charge paired or external source changed during final readback", chain)
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 2)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(self.historical(completed[0]), completed[0])
        for selected in (completed[0], self.case.reservation):
            self.assert_refuses_unchanged(lambda: self.require(selected))


    def _pre_I_snapshot(self):
        pair = self.pre_i.snapshot()
        self.assertFalse(any(r.logical_type in {'frozen_source_inventory', 'frozen_configuration_inventory',
                                                accounting.SIMULATED_RESOURCE_INITIAL_LOGICAL_TYPE}
                             for r in pair[0].records))
        self.assertFalse((self.root / '.scientist-one-build/resource-authority').exists())
        self.assertFalse(hasattr(self.pre_i, 'args'))
        return pair, self.pre_i.files(), prepared.second_inputs(self.root), prepared.second_state(self.root, self.pre_i.run)

    def test_new_regression_S_binding_consumer_rejects_invalid_entries(self):
        from scientist_one.recovery import RecoveryManager, ConfirmatoryRerunError
        raw = (self.root / 'src/scientist_one/simulated_reserve.py').read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        entry = {'path': 'src/scientist_one/simulated_reserve.py', 'sha256': digest, 'size': len(raw)}
        wrong = ('0' if digest[0] != '0' else '1') + digest[1:]
        self.assertNotEqual(wrong, digest)
        variants = (('non-list', (), 'simulated evaluator source inventory is invalid'),
                    ('missing', [], 'frozen source inventory does not uniquely bind observed second reserve owner'),
                    ('duplicate', [entry, dict(entry)], 'frozen source inventory does not uniquely bind observed second reserve owner'),
                    ('digest', [{**entry, 'sha256': wrong}], 'observed second reserve owner implementation differs from the frozen inventory'),
                    ('size', [{**entry, 'size': len(raw) + 1}], 'observed second reserve owner implementation differs from the frozen inventory'))
        for variant, entries, reason in variants:
            with self.subTest(variant=variant):
                before = self._pre_I_snapshot()
                with self.assertRaises(ConfirmatoryRerunError) as raised:
                    RecoveryManager._validated_live_source_implementation(RecoveryManager(self.root),
                        {'entries': entries}, path=entry['path'], label='observed second reserve owner')
                self.assertEqual(str(raised.exception), reason)
                self.assertEqual(self._pre_I_snapshot(), before)
                prepared.second_evidence('consumer', {'variant': variant, 'cause': [str(raised.exception)],
                    'state_unchanged': True, 'pair': prepared._second_pair(before[0]), 'state_files': before[3]})

    def test_new_regression_pre_I_extra_source_refuses_without_publication(self):
        before = self._pre_I_snapshot()
        with prepared.second_added_input(self.root, 'pre_I') as fault:
            with self.assertRaises(OrchestrationError) as raised:
                accounting.register_simulated_resource_initial_inventories(self.registry)
            cause = str(raised.exception)
            self.assertEqual(cause, 'captured source attestation does not cover the source inventory')
            measured = prepared.second_fault_measurement(self.root, fault)
            self.assertEqual(self.pre_i.snapshot(), before[0])
            self.assertEqual(self.pre_i.files(), before[1])
            self.assertEqual(prepared.second_state(self.root, self.pre_i.run), before[3])
            self.assertFalse((self.root / '.scientist-one-build/resource-authority').exists())
        self.assertEqual(self._pre_I_snapshot(), before)
        prepared.second_evidence('producer', {'cause': [cause], 'fault': measured, 'state_unchanged': True,
            'cleanup_verified': True, 'pair': prepared._second_pair(before[0]), 'state_files': before[3]})

    def test_new_regression_late_S2_added_input_refuses_with_allocation_retained(self):
        before = self.snapshot()
        journal_path = Path(observation._journal_path(self.case.charge)).as_posix()
        journal_before = prepared._observation_file(self.root, journal_path)
        original_inputs = prepared.second_inputs(self.root)
        original = reserve._require_observed_second_at_snapshot
        calls, results, order, faults = [], [], [], []
        with ExitStack() as cleanup:
            def drift(*args, **kwargs):
                result = original(*args, **kwargs)
                results.append(result)
                order.append('static-readback')
                with self.assertRaises(OrchestrationError):
                    with accounting._project_resource_execution_lock(self.root, nonblocking=True):
                        pass
                order.append('resource-contention')
                with self.assertRaises(HoldoutCustodyError):
                    observation._provider(self.registry, self.case.charge, existing=True)
                order.append('custody-contention')
                calls.append(True)
                fault = cleanup.enter_context(prepared.second_added_input(self.root, prepared.second_phase()))
                faults.append(fault)
                order.append('fault-created')
                return result
            with mock.patch.object(reserve, '_require_observed_second_at_snapshot', drift):
                with self.assertRaises(reserve.SimulatedReserveError) as raised:
                    self.publish()
            order.append('public-refusal')
            self.assertEqual(len(calls), 1)
            after = self.snapshot()
            self.assertEqual(after[0][0].count, before[0][0].count + 1)
            self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
            self.assertEqual(after[1:], before[1:])
            cause, error = [], raised.exception
            while error is not None:
                cause.append(str(error))
                error = error.__cause__
            reason = ('captured source attestation does not cover the source inventory'
                      if prepared.second_phase() == 'source_addition'
                      else 'live source/configuration inventory differs from frozen bytes')
            self.assertIn(reason, cause)
            publication = results[0][0]
            self.assertEqual(after[0], (publication.registry_snapshot, publication.ledger_snapshot))
            self.assertEqual(set(after[0][0].records), set(before[0][0].records) | {publication.record})
            self.assertEqual(after[0][1].events, (*before[0][1].events, publication.event))
            self.assertEqual(publication.record.schema_version, reserve.OBSERVED_SECOND_SIMULATED_RESERVE_SCHEMA)
            self.assertEqual(publication.event.artifact_hashes, (publication.record.sha256,))
            self.assertEqual(self.case.charge.runtime_state, self.j.preparation.charge.runtime_state)
            external = accounting._read_resource_authority_records(self.root, self.case.case.run)
            self.assertEqual(external[-1]['state']['runtime_state']['confirmatory_used'], self.case.charge.runtime_state.confirmatory_used)
            self.assertEqual(prepared._observation_file(self.root, journal_path), journal_before)
            measured = prepared.second_fault_measurement(self.root, faults[0])
            pair = prepared._second_pair(after[0])
            state_files = prepared.second_state(self.root, self.case.case.run, journal_path)
        self.assertEqual(prepared.second_inputs(self.root), original_inputs)
        self.assertEqual(self.snapshot(), after)
        self.assertEqual(prepared.second_state(self.root, self.case.case.run, journal_path), state_files)
        prepared.second_evidence('late', {'cause': cause, 'fault': measured, 'order': order, 'pair': pair,
            'record': publication.record.record_hash, 'event': publication.event.event_hash,
            'external': [{'name': name, 'bytes_hex': raw.hex(), 'inode': inode, 'mtime_ns': mtime}
                         for name, raw, inode, mtime in after[1]],
            'journal': journal_before, 'journal_path': journal_path, 'state_files': state_files, 'cleanup_verified': True})


@prepared.prepared_second_tests
class ObservedSecondReserveMarkerTests(unittest.TestCase):
    def test_v3_metadata_only_markers_refuse_before_legacy_I_or_S_publication(self):
        for schema in prepared.second_marker_schemas(("sim-reserve/v3", "sim-reserve-event/v3")):
            for kind, fixture_type in prepared.second_marker_kinds((("allocation-only-S1", allocation_fixtures.SimulatedReserveTests),
                                       ("I", initialization_fixtures.SimulatedResourceTests),
                                       ("resource-S1", resource_reserve_fixtures.ResourceBackedSimulatedReserveTests))):
                with self.subTest(schema=schema, kind=kind):
                    fixture = fixture_type()
                    self.addCleanup(fixture.doCleanups)
                    fixture.setUp()
                    prepared.second_marker_fixture(fixture, kind)
                    fixture.registry.put_json({"ordinary_body": "metadata is the sole v3 marker"},
                        logical_type="renamed_metadata_marker", schema_version=schema,
                        origin="negative bounded selection fixture", creator_role=Role.ORCHESTRATOR)
                    before = fixture.snapshot()
                    error = None
                    try:
                        fixture.initialize() if kind == "I" else fixture.publish()
                    except Exception as caught:
                        error = caught
                    after = fixture.snapshot()
                    print("V3_METADATA_MARKER", dict(schema=schema, kind=kind, error=type(error).__name__ if error else None,
                          records=(before[0].count, after[0].count), events=(before[1].event_count, after[1].event_count)), flush=True)
                    self.assertIsNotNone(error)
                    self.assertEqual(after, before)
