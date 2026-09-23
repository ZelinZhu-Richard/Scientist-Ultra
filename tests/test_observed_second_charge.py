"""Native cumulative Q2 controls in independent temporary roots."""
from dataclasses import replace
from pathlib import Path
import os
import select
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import simulated_resource as resource
from scientist_one import simulated_reserve as reserve
from scientist_one import simulated_observation as observation
from scientist_one import holdout
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.resources import ResourceController
from scientist_one.resources import conservative_disk_reserve
from scientist_one.ledger import LedgerEvent
from scientist_one.models import MacroState, utc_now
from scientist_one.orchestrator import OrchestrationError
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads
import tests.test_simulated_resource as initial_fixtures
import tests.test_observed_second_reserve as second_reserve_fixtures


class ObservedSecondChargeTests(unittest.TestCase):
    def setUp(self):
        self.s = second_reserve_fixtures.ObservedSecondReserveTests()
        self.addCleanup(self.s.doCleanups)
        self.s.setUp()
        self.second = self.s.publish()
        self.case, self.j = self.s.case, self.s.j
        self.registry, self.ledger, self.root = self.s.registry, self.s.ledger, self.s.root
        self.run = self.case.case.run

    def snapshot(self):
        pair = self.registry.verify_all(raise_on_error=True), self.ledger.assert_valid()
        path = self.root / observation._journal_path(self.case.charge)
        return pair, self.case.case.files(), path.read_bytes() if path.exists() else None

    def charge(self):
        return resource.charge_simulated_confirmatory_reserve(self.registry, self.ledger,
            expected_run_id=self.run, reservation_artifact_sha256=self.second.record.sha256)

    def require(self, result):
        return resource.require_simulated_confirmatory_charge(self.registry, self.ledger,
            expected_run_id=self.run, charge_artifact_sha256=result.record.sha256)

    def history(self, result):
        return resource._require_simulated_confirmatory_charge_at_snapshot(self.registry, self.ledger,
            expected_run_id=self.run, charge_artifact_sha256=result.record.sha256,
            registry_snapshot=result.registry_snapshot, ledger_snapshot=result.ledger_snapshot)

    def assert_refuses_unchanged(self, operation):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            operation()
        self.assertEqual(self.snapshot(), before)

    def forbid_accounting(self):
        return mock.patch.multiple(ResourceController,
            evaluate=mock.Mock(side_effect=AssertionError("recovery admission")),
            charge_validity=mock.Mock(side_effect=AssertionError("recovery debit")),
            observe_wall_time=mock.Mock(side_effect=AssertionError("recovery clock")))

    def interrupt_event(self, *, after=False):
        native = self.ledger._append_locked
        def interrupted(*args, **kwargs):
            if after:
                native(*args, **kwargs)
            raise OSError("after native Q2 event" if after else "before native Q2 event")
        return mock.patch.object(self.ledger, "_append_locked", interrupted)

    def test_actual_T1_then_S2_Q2_charges_eight_to_sixteen_without_release(self):
        before = self.snapshot()
        calls = []
        charge = ResourceController.charge_validity
        def actual_charge(controller, stage, units):
            calls.append((stage, units, controller.validity_budget.snapshot().confirmatory_used))
            return charge(controller, stage, units)
        with mock.patch.object(ResourceController, "charge_validity", actual_charge):
            result = self.charge()
        self.assertEqual(calls, [("CONFIRMATORY", 8, 8)])
        self.assertEqual(result.record.schema_version, "sim-resource-charge/v2")
        self.assertEqual(result.record.parent_artifacts, (self.j.attempt.record.sha256, self.second.record.sha256))
        self.assertNotEqual(result.record.parent_artifacts[0], self.case.charge.record.sha256)
        self.assertEqual(result.initialization.record, self.case.initialization.record)
        self.assertEqual(result.initialization.runtime_state, self.case.initialization.runtime_state)
        self.assertEqual(result.initialization.config, self.case.initialization.config)
        self.assertEqual(result.runtime_state.confirmatory_used, 16)
        self.assertEqual(result.runtime_state.exploratory_used, 0)
        previous = self.case.charge.runtime_state  # T1 repeats this exact native state.
        self.assertLessEqual(result.runtime_state.wall_started_at_epoch_seconds,
                             previous.wall_started_at_epoch_seconds)
        self.assertLessEqual(previous.wall_started_at_epoch_seconds,
                             self.case.initialization.runtime_state.wall_started_at_epoch_seconds)
        self.assertEqual(result.runtime_state.run_id, self.case.initialization.runtime_state.run_id)
        self.assertGreaterEqual(result.runtime_state.wall_elapsed_seconds, previous.wall_elapsed_seconds)
        self.assertGreaterEqual(result.runtime_state.wall_observed_at_epoch_seconds, previous.wall_observed_at_epoch_seconds)
        self.assertEqual(result.runtime_state.checkpoint_elapsed_seconds, previous.checkpoint_elapsed_seconds)
        self.assertEqual(result.runtime_state.progress_elapsed_seconds, previous.progress_elapsed_seconds)
        self.assertEqual(result.runtime_state.worker_crashes, previous.worker_crashes)
        external = resource._read_resource_authority_records(self.root, self.run)
        self.assertEqual(tuple(item["sequence"] for item in external), (0, 1, 2, 3))
        self.assertEqual(tuple(item["state"]["runtime_state"]["confirmatory_used"] for item in external), (0, 8, 8, 16))
        value = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        self.assertEqual(value["previous_external_authority_sha256"], self.j.attempt.external_authority_sha256)
        self.assertEqual((value["previous_external_sequence"], value["confirmatory_used_before"], value["charged_units"]), (2, 8, 8))
        self.assertFalse(value["release_authority"])
        self.assertFalse(value["scientific_authority"])
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(after[1][:-1], before[1])
        self.assertEqual(after[2], before[2])
        self.assertEqual(self.require(result), result)
        self.assertEqual(self.history(result), result)

    def test_completed_retry_does_not_admit_charge_or_refresh_runtime(self):
        result = self.charge()
        before = self.snapshot()
        with mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("new admission")), \
             mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("second debit")), \
             mock.patch.object(ResourceController, "observe_wall_time", side_effect=AssertionError("runtime refresh")):
            self.assertEqual(self.charge(), result)
        self.assertEqual(self.snapshot(), before)

    def test_external_only_native_interruption_recovers_without_another_debit(self):
        before = self.snapshot()
        native = resource._persist_resource_authority_for
        def interrupted(*args, **kwargs):
            native(*args, **kwargs)
            raise OSError("after actual external Q2")
        with mock.patch.object(resource, "_persist_resource_authority_for", interrupted):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        orphan = self.snapshot()
        self.assertEqual(orphan[0], before[0])
        self.assertEqual(len(orphan[1]), len(before[1]) + 1)
        self.assertEqual(orphan[2], before[2])
        with mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("recovery admission")), \
             mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("recovery charge")), \
             mock.patch.object(ResourceController, "observe_wall_time", side_effect=AssertionError("recovery time")):
            result = self.charge()
        self.assertEqual(result.runtime_state.confirmatory_used, 16)
        self.assertEqual(self.snapshot()[1:], orphan[1:])

    def test_complete_Q2_owns_public_S1_S2_and_historical_Q1_not_current_Q1(self):
        result = self.charge()
        for selected in (self.second, self.case.reservation):
            owned = reserve.require_simulated_confirmatory_reserve(self.registry, self.ledger,
                expected_run_id=self.run, reservation_artifact_sha256=selected.record.sha256)
            self.assertEqual(owned.record, selected.record)
            self.assertEqual(owned.registry_snapshot, result.registry_snapshot)
        prior = resource._require_simulated_confirmatory_charge_at_snapshot(self.registry, self.ledger,
            expected_run_id=self.run, charge_artifact_sha256=self.case.charge.record.sha256,
            registry_snapshot=result.registry_snapshot, ledger_snapshot=result.ledger_snapshot)
        self.assertEqual(prior.record, self.case.charge.record)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.require(self.case.charge)
        self.assertEqual(self.snapshot(), before)

    def test_before_external_failure_leaves_no_durable_debit(self):
        before = self.snapshot()
        with mock.patch.object(resource, "_persist_resource_authority_for", side_effect=OSError("before external Q2")):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.charge().runtime_state.confirmatory_used, 16)

    def test_after_real_artifact_failure_recovers_identical_record_and_external(self):
        before = self.snapshot()
        native = resource._put
        def interrupted(*args, **kwargs):
            native(*args, **kwargs)
            raise OSError("after actual Q2 artifact")
        with mock.patch.object(resource, "_put", interrupted):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        orphan = self.snapshot()
        self.assertEqual(orphan[0][0].count, before[0][0].count + 1)
        self.assertEqual(orphan[0][1], before[0][1])
        self.assertEqual(len(orphan[1]), len(before[1]) + 1)
        with self.forbid_accounting():
            result = self.charge()
        self.assertEqual(result.registry_snapshot, orphan[0][0])
        self.assertEqual(self.snapshot()[1:], orphan[1:])

    def test_before_artifact_failure_is_exact_external_only_suffix(self):
        before = self.snapshot()
        with mock.patch.object(resource, "_put", side_effect=OSError("before actual Q2 artifact")):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        orphan = self.snapshot()
        self.assertEqual(orphan[0], before[0])
        with self.forbid_accounting():
            result = self.charge()
        self.assertEqual(self.snapshot()[1:], orphan[1:])
        self.assertEqual(result.runtime_state.confirmatory_used, 16)

    def test_before_event_record_orphan_refuses_public_S_but_fresh_readers_can_finish(self):
        with self.interrupt_event():
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        orphan = self.snapshot()
        for item in (self.second, self.case.reservation):
            self.assert_refuses_unchanged(lambda: reserve.require_simulated_confirmatory_reserve(
                self.registry, self.ledger, expected_run_id=self.run, reservation_artifact_sha256=item.record.sha256))
        self.registry = ArtifactRegistry(self.root, self.registry.base_path)
        self.ledger = EventLedger(self.root, self.ledger.relative_path)
        with self.forbid_accounting():
            result = self.charge()
        self.assertEqual(result.registry_snapshot, orphan[0][0])
        self.assertEqual(self.snapshot()[1:], orphan[1:])

    def test_after_event_failure_completed_suffix_has_no_accounting_retry(self):
        before = self.snapshot()
        with self.interrupt_event(after=True):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        complete = self.snapshot()
        self.assertEqual(complete[0][0].count, before[0][0].count + 1)
        self.assertEqual(complete[0][1].event_count, before[0][1].event_count + 1)
        with self.forbid_accounting():
            result = self.charge()
            self.assertEqual(self.require(result), result)
        self.assertEqual(self.snapshot(), complete)

    def test_actual_run_tree_rollback_recovers_same_external_debit_without_reset(self):
        with tempfile.TemporaryDirectory(prefix="q2-retained-run-preimage-") as directory:
            run = self.root / "runs" / self.run
            backup = Path(directory) / "pre-Q2"
            shutil.copytree(run, backup)
            result = self.charge()
            complete = self.snapshot()
            shutil.move(str(run), str(Path(directory) / "retained-complete-Q2"))
            shutil.copytree(backup, run)
            self.registry = ArtifactRegistry(self.root, Path("runs") / self.run / "registry")
            self.ledger = EventLedger(self.root, Path("runs") / self.run / "events.jsonl")
            with self.forbid_accounting():
                recovered = self.charge()
            self.assertEqual(recovered.record, result.record)
            self.assertEqual(recovered.runtime_state_bytes, result.runtime_state_bytes)
            self.assertEqual(self.snapshot(), complete)

    def test_original_runtime_identity_cannot_be_replaced_by_equal_counter_Q1(self):
        result = self.charge()
        value = safe_json_loads(self.registry.get_bytes(result.record.sha256))
        value["previous_runtime_artifact_sha256"] = self.case.charge.record.sha256
        value["previous_runtime_record_hash"] = self.case.charge.record.record_hash
        before = self.snapshot()
        with self.assertRaises(resource.SimulatedResourceError):
            resource._reconstruct_second_charge(self.registry, self.ledger,
                (result.registry_snapshot, result.ledger_snapshot), value)
        self.assertEqual(self.snapshot(), before)

    def test_selectors_and_unsupported_third_window_refuse_without_debit(self):
        class EqualText(str):
            def __eq__(self, other):
                return True
            __hash__ = str.__hash__
        for digest in (True, "not-hex", EqualText(self.second.record.sha256), self.case.charge.record.sha256):
            with self.subTest(digest=repr(digest)):
                self.assert_refuses_unchanged(lambda: resource.charge_simulated_confirmatory_reserve(
                    self.registry, self.ledger, expected_run_id=self.run, reservation_artifact_sha256=digest))
        self.assert_refuses_unchanged(lambda: self.s.publish(window_index=3))

    def test_native_deadline_and_stall_faults_refuse_before_second_charge(self):
        native = ResourceController.from_runtime_state.__func__
        config = self.case.initialization.config
        for delta, reason in ((config.maximum_wall_clock_seconds + 1, "WALL_CLOCK_BUDGET_EXHAUSTED"),
                              (config.stall_timeout_seconds + 1, "WORK_STALLED")):
            with self.subTest(reason=reason):
                def fault(cls, config, root, state, **kwargs):
                    return native(cls, config, root, state,
                        wall_clock=lambda: state.wall_observed_at_epoch_seconds + delta, **kwargs)
                before = self.snapshot()
                with mock.patch.object(ResourceController, "from_runtime_state", classmethod(fault)), \
                     mock.patch.object(ResourceController, "charge_validity", side_effect=AssertionError("debit after deadline")):
                    with self.assertRaisesRegex(resource.SimulatedResourceError, reason):
                        self.charge()
                self.assertEqual(self.snapshot(), before)

    def test_live_source_configuration_native_tail_and_terminal_bytes_refuse(self):
        paths = [self.root / "configs/resource_limits.json", self.root / "src/scientist_one/simulated_resource.py",
                 self.root / observation._journal_path(self.case.charge)]
        paths.append(sorted((self.root / ".scientist-one-build/resource-authority" / self.run).glob("*.json"))[-1])
        for path in paths:
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                try:
                    path.write_bytes(raw + b" ")
                    self.assert_refuses_unchanged(self.charge)
                finally:
                    path.write_bytes(raw)

    def test_actual_C2_lineage_correction_refuses_new_charge(self):
        self.ledger.append_correction(self.s.amendment.event.event_id, actor_role=Role.ORCHESTRATOR,
            reason="Negative current C2 lineage correction", corrected_fields={"status": "RETRACTED"})
        self.assert_refuses_unchanged(self.charge)

    def test_registry_ledger_count_and_clock_refuse_before_external_advance(self):
        pair = self.snapshot()[0]
        for name, limit in (("MAX_REGISTRY_RECORDS", pair[0].count), ("MAX_LEDGER_EVENTS", pair[1].event_count),
                            ("MAX_LEDGER_BYTES", pair[1].valid_prefix_bytes)):
            with self.subTest(limit=name), mock.patch.object(resource, name, limit):
                self.assert_refuses_unchanged(self.charge)
        with mock.patch.object(resource, "utc_now", return_value=self.case.initialization.record.created_at):
            self.assert_refuses_unchanged(self.charge)

    def test_exact_new_disk_capacity_includes_external_payload_and_native_metadata(self):
        native = resource._second_charge_capacity
        calls = []
        def constrained(registry, pair, result, external, **kwargs):
            config, total = result.initialization.config, 10**9
            margin = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
            metadata = len(resource._raw(result.record.to_dict()))
            free = margin + result.record.size + len(resource._raw(external[-1])) + len(resource._raw(result.event.to_dict())) + metadata // 2
            calls.append(True)
            with mock.patch.object(ResourceController, "_probe_disk", return_value=(total, free, None)):
                return native(registry, pair, result, external, **kwargs)
        with mock.patch.object(resource, "_second_charge_capacity", constrained):
            self.assert_refuses_unchanged(self.charge)
        self.assertEqual(calls, [True])

    def test_orphan_event_capacity_after_deadline_has_no_new_admission_or_metadata(self):
        with self.interrupt_event():
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        orphan = self.snapshot()
        external = resource._read_resource_authority_records(self.root, self.run)
        _source, _reservation, _revision, _observed, _record, event, _external = resource._reconstruct_second_charge(
            self.registry, self.ledger, orphan[0], external[-1]["state"])
        event_bytes = len(resource._raw(event.to_dict()))
        config, total = self.case.initialization.config, 10**9
        margin = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
        native = ResourceController.from_runtime_state.__func__
        def late(cls, config, root, state, **kwargs):
            return native(cls, config, root, state,
                wall_clock=lambda: state.wall_observed_at_epoch_seconds + config.maximum_wall_clock_seconds + 1, **kwargs)
        with self.forbid_accounting(), \
             mock.patch.object(ResourceController, "from_runtime_state", classmethod(late)), \
             mock.patch.object(ResourceController, "_probe_disk", return_value=(total, margin + event_bytes + 1, None)), \
             mock.patch.object(resource, "MAX_REGISTRY_RECORDS", orphan[0][0].count), \
             mock.patch.object(resource, "MAX_LEDGER_EVENTS", orphan[0][1].event_count + 1), \
             mock.patch.object(resource, "MAX_LEDGER_BYTES", orphan[0][1].valid_prefix_bytes + event_bytes):
            result = self.charge()
        self.assertEqual(result.external_authority_bytes, resource._raw(external[-1]))
        self.assertEqual(self.snapshot()[1:], orphan[1:])

    def test_static_readback_retains_native_guards_and_final_source_refuses_return(self):
        before = self.snapshot()
        native = resource._require_second_charge_at_snapshot
        completed = []
        def drift(*args, **kwargs):
            result = native(*args, **kwargs)
            completed.append(result[0])
            with self.assertRaises(OrchestrationError):
                with resource._project_resource_execution_lock(self.root, nonblocking=True):
                    pass
            with self.assertRaises(holdout.HoldoutCustodyError):
                observation._provider(self.registry, self.case.charge, existing=True)
            source = self.root / "src/scientist_one/simulated_resource.py"
            source.write_bytes(source.read_bytes() + b"# actual late Q2 readback drift\n")
            return result
        with mock.patch.object(resource, "_require_second_charge_at_snapshot", drift):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        self.assertEqual(len(completed), 1)
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(len(after[1]), len(before[1]) + 1)
        self.assertEqual(after[2], before[2])
        self.assertEqual(self.history(completed[0]), completed[0])
        self.assert_refuses_unchanged(self.charge)

    def test_post_static_registry_append_refuses_final_CAS_with_Q2_retained(self):
        before = self.snapshot()
        native = resource._require_second_charge_at_snapshot
        completed = []
        def drift(*args, **kwargs):
            result = native(*args, **kwargs)
            completed.append(result[0])
            self.case.note({"actual": "registry append after complete static Q2 readback"})
            return result
        with mock.patch.object(resource, "_require_second_charge_at_snapshot", drift):
            with self.assertRaises(resource.SimulatedResourceError) as raised:
                self.charge()
        self.assertEqual(len(completed), 1)
        errors, error = [], raised.exception
        while error is not None:
            errors.append(str(error))
            error = error.__cause__
        self.assertIn("charge paired or external source changed during final readback", errors)
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 2)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(len(after[1]), len(before[1]) + 1)
        self.assertEqual(after[2], before[2])
        self.assertEqual(self.history(completed[0]), completed[0])
        self.assert_refuses_unchanged(lambda: self.require(completed[0]))

    def test_terminal_bytes_change_after_static_Q2_readback_refuses_return(self):
        before = self.snapshot()
        native = resource._require_second_charge_at_snapshot
        completed = []
        path = self.root / observation._journal_path(self.case.charge)
        inode = path.stat().st_ino
        def drift(*args, **kwargs):
            result = native(*args, **kwargs)
            completed.append(result[0])
            path.write_bytes(path.read_bytes() + b" ")
            self.assertEqual(path.stat().st_ino, inode)
            return result
        with mock.patch.object(resource, "_require_second_charge_at_snapshot", drift):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        self.assertEqual(len(completed), 1)
        after = self.snapshot()
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
        self.assertEqual(len(after[1]), len(before[1]) + 1)
        self.assertNotEqual(after[2], before[2])
        self.assertEqual(self.history(completed[0]), completed[0])
        self.assert_refuses_unchanged(self.charge)

    def test_replaced_terminal_inode_refuses_before_external_Q2(self):
        path = self.root / observation._journal_path(self.case.charge)
        before_inode = path.stat().st_ino
        path.rename(path.with_suffix(".retained-native-terminal"))
        path.write_bytes(self.j.custody_journal_bytes)
        self.assertNotEqual(path.stat().st_ino, before_inode)
        self.assert_refuses_unchanged(self.charge)

    def test_late_pair_change_before_external_does_not_debit(self):
        before = self.snapshot()
        native = resource._second_charge_capacity
        calls = []
        def drift(*args, **kwargs):
            result = native(*args, **kwargs)
            if not calls:
                self.case.note({"actual": "registry append after prospective capacity before Q2 CAS"})
            calls.append(True)
            return result
        with mock.patch.object(resource, "_second_charge_capacity", drift):
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        after = self.snapshot()
        self.assertEqual(len(calls), 2)
        self.assertEqual(after[0][0].count, before[0][0].count + 1)
        self.assertEqual(after[0][1], before[0][1])
        self.assertEqual(after[1:], before[1:])

    def test_full_historical_Q2_does_not_consult_current_permission(self):
        result = self.charge()
        before = self.snapshot()
        with self.forbid_accounting(), \
             mock.patch.object(ResourceController, "from_runtime_state", side_effect=AssertionError("historical controller")), \
             mock.patch.object(resource, "_pair", side_effect=AssertionError("current pair")), \
             mock.patch.object(resource, "_read_resource_authority_records", side_effect=AssertionError("current external")), \
             mock.patch.object(resource, "_charge_live_sources", side_effect=AssertionError("current sources")), \
             mock.patch.object(resource, "_charge_current_contract", side_effect=AssertionError("current C")), \
             mock.patch.object(observation, "_provider", side_effect=AssertionError("current custody")):
            self.assertEqual(self.history(result), result)
        self.assertEqual(self.snapshot(), before)

    def test_local_Q2_without_external_head_refuses_recharge_or_current_use(self):
        result = self.charge()
        tail = sorted((self.root / ".scientist-one-build/resource-authority" / self.run).glob("*.json"))[-1]
        tail.rename(self.root / "retained-external-Q2.json")
        with self.forbid_accounting():
            self.assert_refuses_unchanged(self.charge)
            self.assert_refuses_unchanged(lambda: self.require(result))
        self.assertEqual(self.history(result), result)

    def test_terminal_custody_closure_refuses_foreign_thread_child_and_expired_IO(self):
        before = self.snapshot()
        errors = []
        with resource._project_resource_execution_lock(self.root, nonblocking=True):
            with observation._observed_terminal_custody_guard(self.registry, self.ledger,
                    expected_run_id=self.run, observation_artifact_sha256=self.j.record.sha256,
                    registry_snapshot=self.j.registry_snapshot, ledger_snapshot=self.j.ledger_snapshot) as (owned, recheck):
                self.assertEqual(owned, self.j)
                with mock.patch.object(holdout.SimulatedHoldoutCustody, "_open_journal", side_effect=AssertionError("foreign IO")):
                    def foreign():
                        try:
                            recheck()
                        except Exception as exc:
                            errors.append(exc)
                    thread = threading.Thread(target=foreign)
                    thread.start()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(len(errors), 1)
                    self.assertIsInstance(errors[0], observation.SimulatedObservationError)
                    self.assertIn("process/thread", str(errors[0]))
                    reader, writer = os.pipe()
                    child = os.fork()
                    if child == 0:
                        os.close(reader)
                        try:
                            try:
                                recheck()
                            except observation.SimulatedObservationError as exc:
                                os.write(writer, b"refused" if "process/thread" in str(exc) else b"wrong-error")
                            except Exception:
                                os.write(writer, b"wrong-error")
                            else:
                                os.write(writer, b"accepted")
                        finally:
                            os.close(writer)
                            os._exit(0)
                    os.close(writer)
                    ready, _, _ = select.select([reader], [], [], 2)
                    if not ready:
                        os.kill(child, 9)
                    response = os.read(reader, 32)
                    os.close(reader)
                    _, status = os.waitpid(child, 0)
                    self.assertTrue(ready)
                    self.assertEqual(status, 0)
                    self.assertEqual(response, b"refused")
                recheck()
            with mock.patch.object(holdout.SimulatedHoldoutCustody, "_open_journal", side_effect=AssertionError("expired IO")):
                with self.assertRaisesRegex(observation.SimulatedObservationError, "expired"):
                    recheck()
        self.assertEqual(self.snapshot(), before)

    def assert_outer_Q2_and_S_refuse(self, result):
        self.assert_refuses_unchanged(lambda: self.require(result))
        for reservation in (self.second, self.case.reservation):
            self.assert_refuses_unchanged(lambda: reserve.require_simulated_confirmatory_reserve(
                self.registry, self.ledger, expected_run_id=self.run,
                reservation_artifact_sha256=reservation.record.sha256))
        self.assertEqual(self.history(result), result)

    def test_renamed_complete_Q2_body_alias_refuses_all_current_outer_reads(self):
        result = self.charge()
        self.case.note({"renamed": safe_json_loads(self.registry.get_bytes(result.record.sha256))})
        self.assert_outer_Q2_and_S_refuse(result)

    def test_unknown_charge_schema_metadata_refuses_all_current_outer_reads(self):
        result = self.charge()
        self.registry.put_json({"ordinary": "unknown schema metadata only"},
            logical_type="renamed_unknown_q", schema_version="sim-resource-charge/v999",
            origin="negative higher Q2 schema control", creator_role=Role.ORCHESTRATOR)
        self.assert_outer_Q2_and_S_refuse(result)

    def test_unknown_charge_event_only_refuses_all_current_outer_reads(self):
        result = self.charge()
        self.ledger.append(LedgerEvent.create(run_id=self.run, event_id="negative-higher-Q-event",
            timestamp=utc_now(), actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CALIBRATE, event_type="CHECKPOINT", artifact_hashes=(),
            code_version="negative-higher-Q-event", configuration_hash=self.s.amendment.contract_record.sha256,
            prior_event_hash=self.ledger.assert_valid().head_hash, reason="Negative higher unknown charge event",
            metadata={"renamed": {"schema_version": "sim-resource-charge-event/v999"}}))
        self.assert_outer_Q2_and_S_refuse(result)

    def test_actual_Q2_event_correction_refuses_all_current_outer_reads(self):
        result = self.charge()
        self.ledger.append_correction(result.event.event_id, actor_role=Role.ORCHESTRATOR,
            reason="Negative Q2 current-authority correction", corrected_fields={"status": "RETRACTED"})
        self.assert_outer_Q2_and_S_refuse(result)

    def test_record_orphan_with_extra_registry_delta_refuses_reconciliation(self):
        with self.interrupt_event():
            with self.assertRaises(resource.SimulatedResourceError):
                self.charge()
        self.case.note({"actual": "extra registry delta after orphan Q2"})
        with self.forbid_accounting():
            self.assert_refuses_unchanged(self.charge)


class SecondChargeMarkerTests(unittest.TestCase):
    def test_malformed_bare_reserved_prefix_refuses_before_I_and_default_A(self):
        for target in ("I", "A"):
            with self.subTest(target=target):
                case = initial_fixtures.SimulatedResourceTests()
                self.addCleanup(case.doCleanups)
                case.setUp()
                self.add_marker(case, "sim-resource-charge/", "malformed")
                before = case.snapshot(), case.files()
                error, publication = None, None
                try:
                    if target == "I":
                        publication = case.initialize()
                    else:
                        publication = amendments.register_evaluation_contract_amendment(
                            case.registry, case.ledger, run_id=case.run, amendment_id="negative-bare-charge-prefix",
                            parent_contract_artifact_sha256=case.contract_record.sha256,
                            child_contract=replace(case.contract, version=case.contract.version + 1,
                                success_criteria=("Changed criteria with malformed bare reserved schema.",)),
                            author_id=case.contract.frozen_by, reason="Negative malformed bare-prefix boundary")
                except ValueError as exc:
                    error = exc
                after = case.snapshot(), case.files()
                print("ACTUAL_MALFORMED_BARE_CHARGE_PREFIX", dict(target=target,
                    records_before=before[0][0].count, records_after=after[0][0].count,
                    events_before=before[0][1].event_count, events_after=after[0][1].event_count,
                    external_before=len(before[1]), external_after=len(after[1]),
                    refused=error is not None, published=publication is not None), flush=True)
                self.assertIsInstance(error, ValueError)
                self.assertEqual(after, before)

    def post_commitment_A_markers(self, stage):
        for schema in ("sim-resource-charge/v2", "sim-resource-charge-event/v999"):
            for form in ("metadata", "unknown-payload", "event-only"):
                with self.subTest(stage=stage, schema=schema, form=form):
                    case = initial_fixtures.SimulatedResourceTests()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    initial = case.initialize()
                    if stage == "Q1":
                        first = self.first_reservation(case, initial)
                        resource.charge_simulated_confirmatory_reserve(case.registry, case.ledger,
                            expected_run_id=case.run, reservation_artifact_sha256=first.record.sha256)
                    self.add_marker(case, schema, form)
                    before = case.snapshot(), case.files()
                    error, publication = None, None
                    try:
                        publication = amendments.register_evaluation_contract_amendment(
                            case.registry, case.ledger, run_id=case.run, amendment_id="negative-q2-after-commitment",
                            parent_contract_artifact_sha256=case.contract_record.sha256,
                            child_contract=replace(case.contract, version=case.contract.version + 1,
                                success_criteria=("Changed criteria after actual native commitment.",)),
                            author_id=case.contract.frozen_by, reason="Negative post-commitment Q2 marker boundary")
                    except amendments.EvaluationContractAmendmentError as exc:
                        error = exc
                    after = case.snapshot(), case.files()
                    print("ACTUAL_POST_COMMITMENT_Q2_A_MARKER", dict(stage=stage, schema=schema, form=form,
                        records_before=before[0][0].count, records_after=after[0][0].count,
                        events_before=before[0][1].event_count, events_after=after[0][1].event_count,
                        refused=error is not None, published=publication is not None,
                        results_seen=None if publication is None else publication.authority.amendment.results_already_seen,
                        fresh_reserve_required=None if publication is None else publication.authority.amendment.requires_new_confirmatory_reserve), flush=True)
                    self.assertIsInstance(error, amendments.EvaluationContractAmendmentError)
                    self.assertEqual(after, before)

    def test_post_I_default_A_refuses_nonlegacy_charge_schema_markers(self):
        self.post_commitment_A_markers("I")

    def test_post_Q1_default_A_refuses_nonlegacy_charge_schema_markers(self):
        self.post_commitment_A_markers("Q1")

    def test_actual_I_and_Q1_preserve_default_pre_attempt_A(self):
        for stage in ("I", "Q1"):
            with self.subTest(stage=stage):
                case = initial_fixtures.SimulatedResourceTests()
                self.addCleanup(case.doCleanups)
                case.setUp()
                initial = case.initialize()
                if stage == "Q1":
                    first = self.first_reservation(case, initial)
                    resource.charge_simulated_confirmatory_reserve(case.registry, case.ledger,
                        expected_run_id=case.run, reservation_artifact_sha256=first.record.sha256)
                before = case.snapshot(), case.files()
                result = amendments.register_evaluation_contract_amendment(case.registry, case.ledger,
                    run_id=case.run, amendment_id="actual-pre-attempt-amendment",
                    parent_contract_artifact_sha256=case.contract_record.sha256,
                    child_contract=replace(case.contract, version=case.contract.version + 1,
                        success_criteria=("Actual unseen amendment before a native attempt.",)),
                    author_id=case.contract.frozen_by, reason="Preserve native pre-attempt amendment")
                self.assertEqual(result.authority.schema_version, "evaluation-contract-amendment/v1")
                self.assertFalse(result.authority.amendment.results_already_seen)
                self.assertFalse(result.authority.amendment.requires_new_confirmatory_reserve)
                after = case.snapshot(), case.files()
                self.assertEqual(after[0][0].count, before[0][0].count + 2)
                self.assertEqual(after[0][1].event_count, before[0][1].event_count + 1)
                self.assertEqual(after[1], before[1])

    def add_marker(self, case, schema, form):
        value = {"renamed": {"schema_version": schema, "unknown": "not an owned charge"}}
        if form == "event-only":
            case.ledger.append(LedgerEvent.create(run_id=case.run, event_id="negative-q2-marker",
                timestamp=utc_now(), actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CALIBRATE, event_type="CHECKPOINT", artifact_hashes=(),
                code_version="negative-q2-marker-control", configuration_hash=case.contract.sha256,
                prior_event_hash=case.ledger.assert_valid().head_hash, reason="Negative Q2 marker", metadata=value))
        else:
            raw = canonical_json_bytes(value)
            case.registry.put_bytes(b"{}" if form == "metadata" else raw[:-1] if form == "malformed" else raw,
                logical_type="inert_q2_marker", origin="negative Q2 schema boundary", creator_role=Role.ORCHESTRATOR,
                schema_version=schema if form == "metadata" else "1.0")

    def first_reservation(self, case, initial):
        return reserve.register_simulated_confirmatory_reserve(case.registry, case.ledger,
            expected_run_id=case.run, protocol_artifact_sha256=case.protocol_record.sha256,
            contract_artifact_sha256=case.contract_record.sha256, population_artifact_sha256=case.population.sha256,
            window_index=1, initialization_artifact_sha256=initial.record.sha256)

    def before_legacy_stage(self, stage):
        for schema in ("sim-resource-charge/v2", "sim-resource-charge-event/v2",
                       "sim-resource-charge/v999", "sim-resource-charge-event/v999"):
            for form in ("metadata", "unknown-payload", "malformed", "event-only"):
                with self.subTest(stage=stage, schema=schema, form=form):
                    case = initial_fixtures.SimulatedResourceTests()
                    self.addCleanup(case.doCleanups)
                    case.setUp()
                    if stage == "I":
                        operation = case.initialize
                    else:
                        initial = case.initialize()
                        if stage == "S":
                            def operation():
                                return self.first_reservation(case, initial)
                        else:
                            first = self.first_reservation(case, initial)
                            def operation():
                                return resource.charge_simulated_confirmatory_reserve(
                                    case.registry, case.ledger, expected_run_id=case.run,
                                    reservation_artifact_sha256=first.record.sha256)
                    self.add_marker(case, schema, form)
                    before = case.snapshot(), case.files()
                    with self.assertRaises(ValueError):
                        operation()
                    self.assertEqual((case.snapshot(), case.files()), before)

    def test_known_and_unknown_Q2_markers_refuse_before_old_I(self):
        self.before_legacy_stage("I")

    def test_known_and_unknown_Q2_markers_refuse_before_old_S(self):
        self.before_legacy_stage("S")

    def test_known_and_unknown_Q2_markers_refuse_before_old_Q(self):
        self.before_legacy_stage("Q")

    def test_valid_prose_and_unreserved_schema_preserve_actual_old_I_S_Q(self):
        for value in ({"note": "sim-resource-charge/v999"}, {"schema_version": "unreserved/v2"},
                      {"note": "The sim-resource-charge/v2 namespace is documented, not invoked here."}):
            with self.subTest(value=value):
                case = initial_fixtures.SimulatedResourceTests()
                self.addCleanup(case.doCleanups)
                case.setUp()
                case.registry.put_json(value, logical_type="ordinary_note", origin="negative selection control",
                                       creator_role=Role.ORCHESTRATOR)
                first = self.first_reservation(case, case.initialize())
                result = resource.charge_simulated_confirmatory_reserve(case.registry, case.ledger,
                    expected_run_id=case.run, reservation_artifact_sha256=first.record.sha256)
                self.assertEqual(result.record.schema_version, "sim-resource-charge/v1")
                self.assertEqual(result.runtime_state.confirmatory_used, 8)

    def test_valid_prose_and_unreserved_schema_preserve_default_A(self):
        for value in ({"note": "sim-resource-charge/v999"}, {"schema_version": "unreserved/v2"},
                      {"note": "The sim-resource-charge/v2 namespace is documented, not invoked here."}):
            with self.subTest(value=value):
                case = initial_fixtures.SimulatedResourceTests()
                self.addCleanup(case.doCleanups)
                case.prepare(freeze=False)
                case.registry.put_json(value, logical_type="ordinary_note", origin="negative selection control",
                                       creator_role=Role.ORCHESTRATOR)
                result = amendments.register_evaluation_contract_amendment(case.registry, case.ledger,
                    run_id=case.run, amendment_id="ordinary-prose-preserved", parent_contract_artifact_sha256=case.contract_record.sha256,
                    child_contract=replace(case.contract, version=case.contract.version + 1,
                                           success_criteria=("Actual legacy amendment with unselected prose.",)),
                    author_id=case.contract.frozen_by, reason="Actual negative selection boundary")
                self.assertEqual(result.authority.schema_version, "evaluation-contract-amendment/v1")
                self.assertFalse(result.authority.amendment.results_already_seen)

    def test_pre_I_default_A_refuses_known_Q2_metadata_malformed_and_event_markers(self):
        for schema in ("sim-resource-charge/v2", "sim-resource-charge-event/v2",
                       "sim-resource-charge/v999", "sim-resource-charge-event/v999"):
            for form in ("metadata", "unknown-payload", "malformed", "event-only"):
                with self.subTest(schema=schema, form=form):
                    case = initial_fixtures.SimulatedResourceTests()
                    self.addCleanup(case.doCleanups)
                    case.prepare(freeze=False)
                    value = {"renamed": {"schema_version": schema, "unknown": "not an owned charge"}}
                    raw = canonical_json_bytes(value)
                    if form == "event-only":
                        case.ledger.append(LedgerEvent.create(
                            run_id=case.run, event_id="inert-q2-marker-probe", timestamp=utc_now(),
                            actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
                            requested_state_after=MacroState.CALIBRATE, event_type="CHECKPOINT",
                            artifact_hashes=(), code_version="negative-q2-marker-control",
                            configuration_hash=case.contract.sha256, prior_event_hash=None,
                            reason="Negative marker control", metadata=value))
                    else:
                        case.registry.put_bytes(raw[:-1] if form == "malformed" else b"{}" if form == "metadata" else raw,
                            logical_type="inert_q2_marker_probe", origin="negative Q2 marker control",
                            creator_role=Role.ORCHESTRATOR,
                            schema_version=schema if form == "metadata" else "1.0")
                    before = case.snapshot(), case.files()
                    error, publication = None, None
                    try:
                        publication = amendments.register_evaluation_contract_amendment(
                            case.registry, case.ledger, run_id=case.run, amendment_id="negative-q2-pre-I",
                            parent_contract_artifact_sha256=case.contract_record.sha256,
                            child_contract=replace(case.contract, version=case.contract.version + 1,
                                success_criteria=("Changed stopping criteria in the negative Q2 probe.",)),
                            author_id=case.contract.frozen_by, reason="Negative pre-I Q2 marker boundary")
                    except amendments.EvaluationContractAmendmentError as exc:
                        error = exc
                    after = case.snapshot(), case.files()
                    print("ACTUAL_PRE_I_Q2_A_MARKER", dict(schema=schema, form=form,
                        records_before=before[0][0].count, records_after=after[0][0].count,
                        events_before=before[0][1].event_count, events_after=after[0][1].event_count,
                        refused=error is not None, published=publication is not None,
                        results_seen=None if publication is None else publication.authority.amendment.results_already_seen,
                        fresh_reserve_required=None if publication is None else publication.authority.amendment.requires_new_confirmatory_reserve), flush=True)
                    self.assertIsInstance(error, amendments.EvaluationContractAmendmentError)
                    self.assertEqual(after, before)
