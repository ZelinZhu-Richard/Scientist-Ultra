"""Real native J1 historical/admission interface in independent temporary roots."""

from dataclasses import replace
import os
import threading
import unittest
from unittest import mock

from scientist_one import simulated_observation as observation
from scientist_one import simulated_resource as resource
from scientist_one import holdout
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.resources import ResourceController
import tests.test_simulated_observation as fixtures


class ObservedAmendmentJInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.SimulatedObservationTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.registry, self.ledger = self.case.registry, self.case.ledger
        self.preparation = self.case.prepare()

    def complete(self):
        return self.case.run_observation(self.preparation)

    def historical(self, j, pair=None, **changes):
        pair = pair or (j.registry_snapshot, j.ledger_snapshot)
        arguments = dict(expected_run_id=self.case.case.run, observation_artifact_sha256=j.record.sha256,
                         registry_snapshot=pair[0], ledger_snapshot=pair[1])
        arguments.update(changes)
        return observation._require_simulated_reserve_observation_at_snapshot(self.registry, self.ledger, **arguments)

    def admission(self, j, current_pair=None):
        return observation._observed_amendment_admission_guard(self.registry, self.ledger,
            expected_run_id=self.case.case.run, observation_artifact_sha256=j.record.sha256,
            registry_snapshot=j.registry_snapshot, ledger_snapshot=j.ledger_snapshot,
            current_pair=current_pair or self.case.case.snapshot())

    def journal_path(self):
        return self.case.root / observation._journal_path(self.case.charge)

    def final_refusal(self, final_check, pair, guards):
        try:
            final_check(pair, *guards)
        except Exception as error:
            return error
        return None

    def test_actual_complete_historical_replay_never_reads_current_authority(self):
        j = self.complete()
        before = self.case.snapshot()
        with mock.patch.object(observation, "_pair", create=True, side_effect=AssertionError("current pair")), \
             mock.patch.object(resource, "_pair", side_effect=AssertionError("current pair")), \
             mock.patch.object(observation, "_live", side_effect=AssertionError("current live admission")), \
             mock.patch.object(observation, "_provider", side_effect=AssertionError("durable custody")), \
             mock.patch.object(resource, "_read_resource_authority_records", side_effect=AssertionError("current external")), \
             mock.patch.object(resource, "_charge_live_sources", side_effect=AssertionError("current source")), \
             mock.patch.object(resource, "_charge_current_contract", side_effect=AssertionError("current C")), \
             mock.patch.object(ResourceController, "from_runtime_state", side_effect=AssertionError("controller")):
            self.assertEqual(self.historical(j), j)
        self.assertEqual(self.case.snapshot(), before)

    def test_historical_prefix_survives_unowned_current_drift_but_is_not_permission(self):
        j = self.complete()
        self.case.note({"note": "later unowned source, not an amendment"})
        config = self.case.root / "configs/resource_limits.json"
        config.write_bytes(config.read_bytes() + b" ")
        self.journal_path().rename(self.journal_path().with_suffix(".retained-native-journal"))
        external = self.case.root / ".scientist-one-build/resource-authority" / self.case.case.run
        tail = sorted(external.glob("*.json"))[-1]
        tail.rename(tail.with_suffix(".retained-native-external"))
        self.assertEqual(self.historical(j), j)
        with self.assertRaises(Exception):
            self.case.require(j)
        with self.assertRaises(Exception):
            with self.admission(j):
                pass

    def test_exact_selector_and_native_snapshot_controls(self):
        j = self.complete()
        class EqualText(str):
            def __eq__(self, other): return True
            def __ne__(self, other): return False
            __hash__ = str.__hash__
        for bad in (True, "x" * 64, EqualText(j.record.sha256), self.case.charge.record.sha256):
            with self.subTest(selector=type(bad).__name__), self.assertRaises(Exception):
                self.historical(j, observation_artifact_sha256=bad)
        for bad in (replace(j.registry_snapshot, valid=1), replace(j.registry_snapshot, records=list(j.registry_snapshot.records)),
                    replace(j.registry_snapshot, orphan_paths=("unowned",))):
            with self.assertRaises(Exception):
                self.historical(j, registry_snapshot=bad)
        for bad in (replace(j.ledger_snapshot, valid=1), replace(j.ledger_snapshot, events=list(j.ledger_snapshot.events)),
                    replace(j.ledger_snapshot, valid_prefix_bytes=j.ledger_snapshot.valid_prefix_bytes + 1),
                    replace(j.ledger_snapshot, head_hash="0" * 64), replace(j.ledger_snapshot, recoverable_truncated_tail=True)):
            with self.assertRaises(Exception):
                self.historical(j, ledger_snapshot=bad)
        with self.assertRaises(Exception):
            observation._require_simulated_reserve_observation_at_snapshot(ArtifactRegistry(self.case.root), self.ledger,
                expected_run_id=self.case.case.run, observation_artifact_sha256=j.record.sha256,
                registry_snapshot=j.registry_snapshot, ledger_snapshot=j.ledger_snapshot)
        with self.assertRaises(Exception):
            observation._require_simulated_reserve_observation_at_snapshot(self.registry, EventLedger(self.case.root, "alternate.jsonl"),
                expected_run_id=self.case.case.run, observation_artifact_sha256=j.record.sha256,
                registry_snapshot=j.registry_snapshot, ledger_snapshot=j.ledger_snapshot)

    def test_selected_orphan_alias_and_correction_are_not_complete_history(self):
        with self.case.event_fault(observation.OBSERVATION_KEY):
            with self.assertRaises(Exception):
                self.complete()
        pair = self.case.case.snapshot()
        orphan = observation._history(self.registry, self.ledger, pair, allow_orphan=True)[3]
        with self.assertRaises(Exception):
            self.historical(orphan, pair)
        j = self.complete()
        self.case.note({"renamed": {"schema_version": observation.OBSERVATION_SCHEMA}})
        with self.assertRaises(Exception):
            self.historical(j, self.case.case.snapshot())
        self.ledger.append_correction(j.event.event_id, actor_role=j.event.actor_role,
            reason="negative observation correction", corrected_fields={"reason": "retained correction"})
        with self.assertRaises(Exception):
            self.historical(j, self.case.case.snapshot())
        self.assertEqual(self.historical(j), j)

    def test_current_guard_rederives_J_and_final_checks_without_current_C_recursion(self):
        j = self.complete()
        before = self.case.snapshot()
        with mock.patch.object(resource, "_charge_current_contract", side_effect=AssertionError("public current C1 recursion")), \
             mock.patch.object(observation, "require_simulated_reserve_observation", side_effect=AssertionError("public current J recursion")), \
             mock.patch.object(ResourceController, "from_runtime_state", side_effect=AssertionError("new experiment admission")):
            with self.admission(j) as (owned, final_check):
                self.assertEqual(owned, j)
                pair = self.case.case.snapshot()
                with observation._locks(self.registry, self.ledger) as guards:
                    final_check(pair, *guards)
        self.assertEqual(self.case.snapshot(), before)

    def test_current_pair_CAS_and_live_source_drift_refuse(self):
        j = self.complete()
        pair = self.case.case.snapshot()
        self.case.note({"note": "actual late current-pair delta"})
        with self.assertRaises(Exception):
            with self.admission(j, pair):
                pass
        source = self.case.root / "src/scientist_one/simulated_observation.py"
        source.write_bytes(source.read_bytes() + b"# actual late source drift\n")
        with self.assertRaises(Exception):
            with self.admission(j):
                pass

    def test_same_inode_native_journal_mutation_is_detected_before_write(self):
        j = self.complete()
        pair, external = self.case.case.snapshot(), self.case.case.files()
        path = self.journal_path()
        inode = path.stat().st_ino
        refusal = None
        with self.assertRaises(Exception):
            with self.admission(j) as (_owned, final_check):
                path.write_bytes(path.read_bytes() + b" ")
                self.assertEqual(path.stat().st_ino, inode)
                with observation._locks(self.registry, self.ledger) as guards:
                    refusal = self.final_refusal(final_check, pair, guards)
        self.assertIsInstance(refusal, Exception)
        self.assertEqual(self.case.case.snapshot(), pair)
        self.assertEqual(self.case.case.files(), external)

    def test_replaced_native_journal_path_is_detected_before_write(self):
        j = self.complete()
        pair, external = self.case.case.snapshot(), self.case.case.files()
        path = self.journal_path()
        inode = path.stat().st_ino
        refusal = None
        with self.assertRaises(Exception):
            with self.admission(j) as (_owned, final_check):
                path.rename(path.with_suffix(".retained-original"))
                path.write_bytes(j.custody_journal_bytes)
                self.assertNotEqual(path.stat().st_ino, inode)
                with observation._locks(self.registry, self.ledger) as guards:
                    refusal = self.final_refusal(final_check, pair, guards)
        self.assertIsInstance(refusal, Exception)
        self.assertEqual(self.case.case.snapshot(), pair)
        self.assertEqual(self.case.case.files(), external)

    def test_foreign_thread_and_expired_final_check_refuse_before_IO(self):
        j = self.complete()
        before = self.case.snapshot()
        errors = []
        with self.admission(j) as (_owned, final_check):
            def foreign():
                try:
                    final_check(None, None, None)
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], observation.SimulatedObservationError)
            self.assertIn("process/thread", str(errors[0]))
            pair = self.case.case.snapshot()
            with observation._locks(self.registry, self.ledger) as guards:
                final_check(pair, *guards)
        with mock.patch.object(holdout.SimulatedHoldoutCustody, "_open_journal", side_effect=AssertionError("expired IO")):
            with self.assertRaisesRegex(observation.SimulatedObservationError, "expired"):
                final_check(None, None, None)
        self.assertEqual(self.case.snapshot(), before)

    def test_replaced_project_namespace_is_detected_before_write(self):
        j = self.complete()
        before = self.case.snapshot()
        pair = self.case.case.snapshot()
        root = self.case.root
        retained = root.with_name(root.name + "-retained-original-namespace")
        replaced = False
        refusal = None
        try:
            with self.assertRaises(Exception):
                with self.admission(j) as (_owned, final_check):
                    with observation._locks(self.registry, self.ledger) as guards:
                        root.rename(retained)
                        replaced = True
                        root.mkdir()
                        refusal = self.final_refusal(final_check, pair, guards)
        finally:
            # These are this test's actual TemporaryDirectory fixtures only.
            # Keep the original tree intact and restore it after all guards exit.
            if replaced:
                root.rmdir()
                retained.rename(root)
        self.assertIsInstance(refusal, observation.SimulatedObservationError)
        self.assertIn("namespace", str(refusal))
        self.assertEqual(self.case.snapshot(), before)

    def test_foreign_child_final_check_refuses_before_IO_without_parent_delta(self):
        j = self.complete()
        before = self.case.snapshot()
        with self.admission(j) as (_owned, final_check):
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                try:
                    try:
                        final_check(None, None, None)
                    except observation.SimulatedObservationError as error:
                        os.write(write_fd, b"refused" if "process/thread" in str(error) else b"wrong")
                    else:
                        os.write(write_fd, b"accepted")
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                result = os.read(read_fd, 32)
            finally:
                os.close(read_fd)
            _pid, status = os.waitpid(child, 0)
            self.assertEqual(status, 0)
            self.assertEqual(result, b"refused")
            pair = self.case.case.snapshot()
            with observation._locks(self.registry, self.ledger) as guards:
                final_check(pair, *guards)
        self.assertEqual(self.case.snapshot(), before)

    def test_actual_native_resource_and_custody_contention_refuse(self):
        j = self.complete()
        before = self.case.snapshot()
        with resource._project_resource_execution_lock(self.case.root, nonblocking=True):
            with self.assertRaises(Exception):
                with self.admission(j):
                    pass
        provider = observation._provider(self.registry, self.case.charge, existing=True)
        with provider.admission_guard(nonblocking=True):
            with self.assertRaises(Exception):
                with self.admission(j):
                    pass
        self.assertEqual(self.case.snapshot(), before)

    def test_actual_custody_drift_after_final_live_source_read_is_detected(self):
        j = self.complete()
        pair, external = self.case.case.snapshot(), self.case.case.files()
        original = resource._charge_live_sources
        refusal = None
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            path = self.journal_path()
            path.write_bytes(path.read_bytes() + b" ")
            return result
        with self.assertRaises(Exception):
            with self.admission(j) as (_owned, final_check):
                with observation._locks(self.registry, self.ledger) as guards:
                    with mock.patch.object(resource, "_charge_live_sources", drift):
                        refusal = self.final_refusal(final_check, pair, guards)
        self.assertIsInstance(refusal, Exception)
        self.assertEqual(self.case.case.snapshot(), pair)
        self.assertEqual(self.case.case.files(), external)
