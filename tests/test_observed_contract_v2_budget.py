"""Exact A/C bookkeeping bytes, expired work budget, and typed refusals."""
import unittest
from unittest import mock

from scientist_one import evaluation_contract_amendment as amendments
from scientist_one import simulated_resource as accounting
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.resources import ResourceController, ResourceConfigError, ResourceLimitError, conservative_disk_reserve
from scientist_one.security import canonical_json_bytes
import tests.test_observed_contract_v2 as fixtures


from tests.test_resource_prepared_cases import (
    prepared_observed_tests,
)


@prepared_observed_tests
class ObservedContractV2BudgetTests(unittest.TestCase):
    def setUp(self):
        self.owner = fixtures.ObservedContractV2Tests()
        self.addCleanup(self.owner.doCleanups)
        self.owner.setUp()

    def test_metadata_bytes_are_reserved_before_first_A_write(self):
        planned = {}
        events = []
        estimates = []
        original_plan = amendments._planned_record
        original_event = amendments._build_event
        original_capacity = amendments._observed_amendment_bookkeeping_capacity
        def plan(registry, raw, **kwargs):
            record = original_plan(registry, raw, **kwargs)
            planned[record.logical_type] = (raw, record)
            return record
        def event(*args, **kwargs):
            result = original_event(*args, **kwargs)
            events.append(canonical_json_bytes(result.to_dict()) + b"\n")
            return result
        def capacity(registry, observed, needed):
            payloads = sum(len(raw) for raw, _record in planned.values())
            metadata = sum(len(canonical_json_bytes(record.to_dict()) + b"\n") for _raw, record in planned.values())
            expected = payloads + metadata + len(events[-1])
            estimates.append((needed, expected, metadata))
            config = observed.preparation.charge.initialization.config
            total = 10**9
            reserve = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
            # Enough for payloads/event, insufficient for real metadata files.
            with mock.patch.object(ResourceController, "_probe_disk", return_value=(total, reserve + payloads + len(events[-1]) + 1, None)):
                return original_capacity(registry, observed, needed)
        with mock.patch.object(amendments, "_planned_record", side_effect=plan), \
             mock.patch.object(amendments, "_build_event", side_effect=event), \
             mock.patch.object(amendments, "_observed_amendment_bookkeeping_capacity", side_effect=capacity):
            self.owner.assert_refuses_unchanged(self.owner.publish)
        self.assertEqual(len(estimates), 1)
        self.assertEqual(estimates[0][0], estimates[0][1])
        self.assertGreater(estimates[0][2], 0)
        self.assertEqual(set(planned), {"evaluation_contract_amendment", "evaluation_contract"})

    def test_budget_loss_before_locked_publication_is_rechecked_without_writes(self):
        calls = []
        original = amendments._observed_amendment_bookkeeping_capacity
        def capacity(*args):
            calls.append(args[2])
            if len(calls) == 2:
                with mock.patch.object(ResourceController, "_probe_disk", return_value=(10**9, 0, None)):
                    return original(*args)
            return original(*args)
        with mock.patch.object(amendments, "_observed_amendment_bookkeeping_capacity", side_effect=capacity):
            self.owner.assert_refuses_unchanged(self.owner.publish)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])

    def test_A_C_orphan_completes_only_event_after_work_wall_budget_expired(self):
        original_state = self.owner.case.snapshot()
        original_put = ArtifactRegistry._put_bytes_locked
        def after_child(registry, guard, data, **kwargs):
            result = original_put(registry, guard, data, **kwargs)
            if kwargs["logical_type"] == "evaluation_contract":
                raise OSError("actual A+C publication interrupted before its event")
            return result
        with mock.patch.object(ArtifactRegistry, "_put_bytes_locked", new=after_child):
            with self.assertRaises(amendments.EvaluationContractAmendmentError) as caught:
                self.owner.publish()
        # The native resource-lock context wraps write OSError on unwinding;
        # require the actual injected failure beneath the typed public refusal.
        write_error = caught.exception.__cause__.__cause__
        self.assertIs(type(write_error), OSError)
        self.assertEqual(str(write_error), "actual A+C publication interrupted before its event")
        case = self.owner.case
        before = case.snapshot()
        self.assertEqual(len(before[0][0].records), len(original_state[0][0].records) + 2)
        self.assertEqual(before[0][1], original_state[0][1])
        self.assertEqual(before[1:], original_state[1:])
        a_record, = [record for record in before[0][0].records if record.logical_type == "evaluation_contract_amendment"]
        c_record, = [record for record in before[0][0].records if record.parent_artifacts[:1] == (a_record.sha256,)]
        authority = amendments._read_amendment_record(case.registry, a_record)
        event = amendments._build_event(authority, a_record, c_record, before[0][1])
        event_size = len(canonical_json_bytes(event.to_dict()) + b"\n")
        config = case.initialization.config
        total = 10**9
        reserve = conservative_disk_reserve(total, config.minimum_free_disk_bytes, config.minimum_free_disk_fraction)
        future = case.charge.runtime_state.wall_observed_at_epoch_seconds + config.maximum_wall_clock_seconds + 100
        original_rebuild = ResourceController.from_runtime_state
        original_capacity = amendments._observed_amendment_bookkeeping_capacity
        elapsed, estimates = [], []
        def rebuild(*args, **kwargs):
            # Exercise the real native controller with an expired clock fixture;
            # this is not a successful-authority or resource-decision mock.
            result = original_rebuild(*args, **{**kwargs, "wall_clock": lambda: future})
            elapsed.append(result.export_state().wall_elapsed_seconds)
            return result
        def capacity(*args):
            estimates.append(args[2])
            return original_capacity(*args)
        with mock.patch.object(ResourceController, "from_runtime_state", side_effect=rebuild), \
             mock.patch.object(ResourceController, "evaluate", side_effect=AssertionError("bookkeeping requested a new experiment")), \
             mock.patch.object(ResourceController, "_probe_disk", return_value=(total, reserve + event_size + 1, None)), \
             mock.patch.object(amendments, "_observed_amendment_bookkeeping_capacity", side_effect=capacity):
            result = self.owner.publish()
        self.assertEqual(estimates, [event_size, event_size])
        self.assertTrue(elapsed)
        self.assertTrue(all(value > config.maximum_wall_clock_seconds for value in elapsed))
        after = case.snapshot()
        self.assertEqual(after[0][0], before[0][0])
        self.assertEqual(after[0][1].events, (*before[0][1].events, event))
        self.assertEqual(after[1:], before[1:])
        with mock.patch.object(ResourceController, "from_runtime_state", side_effect=AssertionError("completed history sought new capacity")):
            self.assertEqual(self.owner.publish(), result)
            self.assertEqual(self.owner.require(result), result)

    def test_native_resource_contention_and_capacity_errors_are_typed_A_refusals(self):
        with accounting._project_resource_execution_lock(self.owner.case.root, nonblocking=True):
            self.owner.assert_refuses_unchanged(self.owner.publish)
        for error in (ResourceConfigError("injected invalid resource configuration"), ResourceLimitError("injected unsafe artifact scan")):
            with self.subTest(error=type(error).__name__), mock.patch.object(ResourceController, "_probe_disk", side_effect=error):
                self.owner.assert_refuses_unchanged(self.owner.publish)
