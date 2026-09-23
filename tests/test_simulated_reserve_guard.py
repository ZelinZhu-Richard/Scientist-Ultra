"""Native guard mechanics only; no scientific or simulated release approval."""

from pathlib import Path
import fcntl
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import scientist_one
from scientist_one import holdout, orchestrator, recovery
from scientist_one import simulated_resource
from scientist_one.calibration import CalibrationError
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
from scientist_one.roles import Role


def _contention_child():
    return '''
import fcntl, importlib.util, os, sys, tempfile, threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
for name, source in zip(("orchestrator", "holdout", "recovery"), sys.argv[2:5]):
    fullname = "scientist_one." + name
    spec = importlib.util.spec_from_file_location(fullname, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = module
    spec.loader.exec_module(module)
h = sys.modules["scientist_one.holdout"]
o = sys.modules["scientist_one.orchestrator"]
action, mode = sys.argv[5].split(":", 1)
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp).resolve() / "Project"
    root.mkdir()
    provider = h.SimulatedHoldoutCustody(("fixed-requester",), journal_root=root,
        journal_path="custody/events.jsonl")
    provider.seal(b"{}", split_manifest_hash="a"*64, protocol_hash="b"*64,
        code_hash="c"*64, configuration_hash="d"*64,
        pre_unblinding_interpretation_hash="e"*64)
    with o._project_resource_execution_lock(root, nonblocking=True):
        pass
    before = {p.relative_to(root).as_posix():p.read_bytes()
              for p in root.rglob("*") if p.is_file()}
    def attempt():
        try:
            if action == "reveal":
                with provider._reveal_admission_guard(simulated_reserve_project_root=root):
                    pass
            elif action == "observe":
                with provider.admission_guard(nonblocking=True):
                    pass
            elif action == "seal":
                provider.seal(b"{}", split_manifest_hash="a"*64, protocol_hash="b"*64,
                    code_hash="c"*64, configuration_hash="d"*64,
                    pre_unblinding_interpretation_hash="e"*64, nonblocking=True)
            else:
                h.SimulatedHoldoutCustody(("fixed-requester",), journal_root=root,
                    journal_path="custody/events.jsonl", require_existing_journal=True,
                    nonblocking=True)
            raise AssertionError("contended custody guard entered")
        except BlockingIOError:
            pass
        except h.HoldoutJournalError as exc:
            if not isinstance(exc.__cause__, BlockingIOError) and str(exc) != "custody process lock unavailable":
                raise
    if mode == "nested":
        with provider.admission_guard():
            attempt()
    elif mode == "process":
        ready, release = threading.Event(), threading.Event()
        def hold():
            with provider._lock:
                ready.set()
                release.wait(8)
        thread = threading.Thread(target=hold, daemon=True)
        thread.start()
        assert ready.wait(1)
        try:
            attempt()
        finally:
            release.set()
            thread.join(1)
    else:
        target = root if mode == "namespace" else provider.journal_path
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        if mode == "namespace": flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(target, flags)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            attempt()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
    after = {p.relative_to(root).as_posix():p.read_bytes()
             for p in root.rglob("*") if p.is_file()}
    assert before == after
    with o._project_resource_execution_lock(root, nonblocking=True):
        pass
    print("REFUSED_WITHOUT_CONTENT_DELTA_RESOURCE_LOCK_AVAILABLE")
'''


class SimulatedReserveGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "Project"
        self.root.mkdir()
        self.provider = holdout.SimulatedHoldoutCustody(
            ("fixed-requester",), journal_root=self.root,
            journal_path="custody/events.jsonl",
        )
        self.provider.seal(
            b"{}", split_manifest_hash="a"*64, protocol_hash="b"*64,
            code_hash="c"*64, configuration_hash="d"*64,
            pre_unblinding_interpretation_hash="e"*64,
        )

    def guarded(self):
        return self.provider._reveal_admission_guard(
            simulated_reserve_project_root=self.root
        )

    def generic_ledger(self, run_id, event_id="generic-checkpoint"):
        ledger = EventLedger(self.root, "generic/events.jsonl")
        ledger.append(LedgerEvent.create(
            run_id=run_id, event_id=event_id, actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE, requested_state_after=MacroState.CALIBRATE,
            code_version="inert-negative-routing-control", configuration_hash="a"*64,
            reason="Native ledger, not a successful observation or scientific authority.",
            event_type="CHECKPOINT", artifact_hashes=(), prior_event_hash=None,
        ))
        return ledger

    def test_unrelated_generic_recovery_does_not_load_calibration_fixture(self):
        ledger = self.generic_ledger("ordinary-native-run")
        before = (self.root / ledger.relative_path).read_bytes()
        with mock.patch.object(simulated_resource, "_pinned_population",
                               side_effect=CalibrationError("inert missing calibration fixture")) as load:
            report = recovery.RecoveryManager(self.root).recover(
                ledger_path=ledger.relative_path, incomplete_paths=(), repair_truncated_tail=False,
            )
            self.assertIs(report.action, recovery.ResumeAction.RESUME_FROM_LEDGER)
            load.assert_not_called()
        self.assertEqual((self.root / ledger.relative_path).read_bytes(), before)

    def test_negative_namespace_reports_marker_not_success_and_never_loads_fixture(self):
        ledger = self.generic_ledger("sim-reserve-" + "a"*48, "sim-reserve-started-inert-marker")
        before = (self.root / ledger.relative_path).read_bytes()
        with mock.patch.object(simulated_resource, "_pinned_population",
                               side_effect=CalibrationError("inert missing calibration fixture")) as load:
            report = recovery.RecoveryManager(self.root).recover(
                ledger_path=ledger.relative_path, incomplete_paths=(), repair_truncated_tail=False,
            )
            self.assertIs(report.action, recovery.ResumeAction.STOP_SECURITY)
            self.assertTrue(report.confirmatory_touched)
            self.assertFalse(report.confirmatory_completed)
            self.assertFalse(report.resumable)
            self.assertIn("SIMULATED_RESERVE_CUSTODY_UNASSESSED", report.reasons)
            load.assert_not_called()
        self.assertEqual((self.root / ledger.relative_path).read_bytes(), before)

    def test_default_session_has_no_resource_binding(self):
        with self.provider._reveal_admission_guard() as session:
            self.assertFalse(hasattr(session, "_simulated_reserve_resource_binding"))
            with self.assertRaises(holdout.HoldoutAccessViolation):
                holdout._require_simulated_reserve_resource_binding(
                    session, self.provider, self.root
                )

    def test_native_binding_expires_after_complete_guard_exit(self):
        with self.guarded() as session:
            binding = holdout._require_simulated_reserve_resource_binding(
                session, self.provider, self.root
            )
            self.assertTrue(binding.active)
            self.assertEqual(binding.thread_id, threading.get_ident())
        self.assertFalse(binding.active)
        self.assertFalse(session._active)
        with self.assertRaises(holdout.HoldoutAccessViolation):
            holdout._require_simulated_reserve_resource_binding(
                session, self.provider, self.root
            )

    def test_foreign_root_and_non_native_path_refuse(self):
        foreign = self.root.parent / "Foreign"
        foreign.mkdir()
        for supplied in (foreign, str(self.root)):
            with self.subTest(root=repr(supplied)):
                with self.assertRaises(holdout.HoldoutJournalError):
                    with self.provider._reveal_admission_guard(
                        simulated_reserve_project_root=supplied
                    ):
                        self.fail("foreign root selected")
        self.assertFalse((foreign / ".scientist-one-resource-execution.lock").exists())

    def test_transferred_thread_refuses_before_native_access_record(self):
        before = self.provider.journal_path.read_bytes()
        errors = []
        with self.guarded() as session:
            manager = recovery.RecoveryManager(self.root)
            selector = recovery.RegisteredArtifactSelector("a"*64, "b"*64)
            selection = recovery.SimulatedReserveRevealSelection(selector, selector)
            def transferred():
                try:
                    session._release(
                        coordinator=manager, ledger_path="uncreated.jsonl",
                        study_version=None, fresh_custody_evidence=None,
                        reveal_authority=selection, artifact_registry=None,
                        custody_provider=self.provider, validity_snapshot=None,
                        start_event=None, evaluator_spec=holdout.ConfirmatoryEvaluatorSpec(),
                        execution_class=holdout.RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL,
                        requester="unauthorized-requester", reason="inert transfer test",
                    )
                except BaseException as exc:
                    errors.append(exc)
            thread = threading.Thread(target=transferred, daemon=True)
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], holdout.HoldoutAccessViolation)
            self.assertIn("resource-bound session", str(errors[0]))
            self.assertFalse(session._attempted)
        self.assertEqual(self.provider.journal_path.read_bytes(), before)
        self.assertFalse((self.root / "uncreated.jsonl").exists())

    def test_contended_custody_acquisitions_are_bounded_and_release_resource_lock(self):
        modes = [action + ":" + lock for action in ("reveal", "observe", "seal", "construct")
                 for lock in ("nested", "process", "namespace", "journal")
                 if (action, lock) != ("construct", "process")]
        for mode in modes:
            with self.subTest(mode=mode):
                process = subprocess.Popen(
                    [sys.executable, "-I", "-B", "-c", _contention_child(),
                     str(Path(scientist_one.__path__[0]).parent),
                     orchestrator.__file__, holdout.__file__, recovery.__file__, mode],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    try:
                        stdout, stderr = process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate(timeout=2)
                        self.fail(f"native custody acquisition blocked ({mode}): {stdout!r} {stderr!r}")
                    self.assertEqual(process.returncode, 0, stdout + stderr)
                    self.assertIn("REFUSED_WITHOUT_CONTENT_DELTA_RESOURCE_LOCK_AVAILABLE", stdout)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)

    def test_direct_native_primitive_cannot_transfer_bound_session_with_legacy_selector(self):
        before = self.provider.journal_path.read_bytes()
        errors = []
        try:
            with self.guarded() as session:
                def transferred():
                    try:
                        holdout.SimulatedHoldoutCustody._run_confirmatory_locked(
                            self.provider, session._descriptor, session,
                            coordinator=recovery.RecoveryManager(self.root),
                            ledger_path="uncreated.jsonl", study_version=None,
                            fresh_custody_evidence=None, reveal_authority=None,
                            artifact_registry=None, custody_provider=self.provider,
                            validity_snapshot=None, start_event=None,
                            evaluator_spec=holdout.ConfirmatoryEvaluatorSpec(),
                            execution_class=holdout.RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL,
                            requester="unauthorized-requester", reason="inert direct native transfer",
                        )
                    except BaseException as exc:
                        errors.append(exc)
                thread = threading.Thread(target=transferred, daemon=True)
                thread.start()
                thread.join(2)
                self.assertFalse(thread.is_alive())
        except holdout.HoldoutJournalError:
            # A before-repair ACCESS also trips parent exit validation. Keep
            # the actual bytes available for the explicit no-mutation check.
            pass
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], holdout.HoldoutAccessViolation)
        with self.subTest(check="binding refusal before requester policy"):
            self.assertIn("resource-bound session", str(errors[0]))
        self.assertEqual(self.provider.journal_path.read_bytes(), before)

    def test_observation_seal_and_constructor_require_exact_boolean(self):
        before = self.provider.journal_path.read_bytes()
        for value in (0, 1, None, "true", 1.0):
            with self.subTest(value=value):
                with self.assertRaisesRegex(holdout.HoldoutJournalError, "exact boolean"):
                    with self.provider.admission_guard(nonblocking=value):
                        self.fail("invalid observation mode")
                with self.assertRaisesRegex(holdout.HoldoutJournalError, "exact boolean"):
                    self.provider.seal(
                        b"{}", split_manifest_hash="a"*64, protocol_hash="b"*64,
                        code_hash="c"*64, configuration_hash="d"*64,
                        pre_unblinding_interpretation_hash="e"*64, nonblocking=value,
                    )
                with self.assertRaisesRegex(holdout.HoldoutJournalError, "exact boolean"):
                    holdout.SimulatedHoldoutCustody(
                        ("fixed-requester",), journal_root=self.root,
                        journal_path="uncreated/events.jsonl", nonblocking=value,
                    )
                self.assertFalse((self.root / "uncreated").exists())
        self.assertEqual(self.provider.journal_path.read_bytes(), before)
        with self.provider.admission_guard(nonblocking=True) as snapshot:
            self.assertEqual(snapshot.journal_bytes, before)
        self.assertEqual(
            self.provider.seal(
                b"{}", split_manifest_hash="a"*64, protocol_hash="b"*64,
                code_hash="c"*64, configuration_hash="d"*64,
                pre_unblinding_interpretation_hash="e"*64, nonblocking=True,
            ), snapshot.seal,
        )

    def test_journal_exit_failure_expires_binding_and_releases_all_locks(self):
        path = self.provider.journal_path
        original = path.read_bytes()
        try:
            with self.assertRaises(holdout.HoldoutJournalError):
                with self.guarded() as session:
                    binding = session._simulated_reserve_resource_binding
                    path.write_bytes(original + b"invalid journal suffix\n")
            self.assertFalse(binding.active)
            self.assertFalse(session._active)
        finally:
            path.write_bytes(original)
        with self.guarded() as subsequent:
            self.assertEqual(subsequent.snapshot.journal_bytes, original)

    @unittest.skipUnless(hasattr(os, "fork"), "native fork is unavailable")
    def test_fork_normal_unwind_keeps_parent_locks_and_journal_position(self):
        self._assert_fork_unwind()

    @unittest.skipUnless(hasattr(os, "fork"), "native fork is unavailable")
    def test_fork_release_refusal_never_reads_or_mutates_parent_session(self):
        self._assert_fork_unwind(attempt=True)

    @unittest.skipUnless(hasattr(os, "fork"), "native fork is unavailable")
    def test_fork_legacy_selector_cannot_escape_bound_session_lifetime(self):
        self._assert_fork_unwind(attempt=True, legacy_selector=True)

    @unittest.skipUnless(hasattr(os, "fork"), "native fork is unavailable")
    def test_fork_direct_native_primitive_cannot_escape_bound_session_lifetime(self):
        self._assert_fork_unwind(attempt=True, legacy_selector=True, direct_primitive=True)

    def _assert_fork_unwind(self, *, attempt=False, legacy_selector=False, direct_primitive=False):
        """Normal child unwinding must close copies, not unlock shared OFDs."""
        reader, writer = os.pipe()
        child = False
        pid = None
        reaped = False
        before = self.provider.journal_path.read_bytes()
        try:
            try:
                with self.guarded() as session:
                    # An exit-time journal read would change this shared offset.
                    os.lseek(session._descriptor, 1, os.SEEK_SET)
                    pid = os.fork()
                    child = pid == 0
                    if child:
                        os.close(reader)
                        if attempt:
                            selector = recovery.RegisteredArtifactSelector("a"*64, "b"*64)
                            selection = recovery.SimulatedReserveRevealSelection(selector, selector)
                            try:
                                request = dict(
                                    coordinator=recovery.RecoveryManager(self.root),
                                    ledger_path="uncreated.jsonl", study_version=None,
                                    fresh_custody_evidence=None,
                                    reveal_authority=None if legacy_selector else selection,
                                    artifact_registry=None, custody_provider=self.provider,
                                    validity_snapshot=None, start_event=None,
                                    evaluator_spec=holdout.ConfirmatoryEvaluatorSpec(),
                                    execution_class=holdout.RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL,
                                    requester="unauthorized-requester", reason="inert child attempt",
                                )
                                if direct_primitive:
                                    holdout.SimulatedHoldoutCustody._run_confirmatory_locked(
                                        self.provider, session._descriptor, session, **request,
                                    )
                                else:
                                    session._release(**request)
                            except holdout.HoldoutAccessViolation:
                                pass
                        # Leave the actual inherited context normally: no
                        # os._exit until every context manager has unwound.
                    else:
                        os.close(writer)
                        ready, _, _ = select.select([reader], [], [], 3)
                        self.assertTrue(ready, "child context unwind blocked")
                        message = os.read(reader, 1024)
                        with self.subTest(check="fail-closed inherited exit"):
                            self.assertIn(b"inherited", message, message)
                        observed, status = os.waitpid(pid, 0)
                        reaped = observed == pid
                        with self.subTest(check="child completed"):
                            self.assertEqual(status, 0)
                        with self.subTest(check="shared journal offset unchanged"):
                            self.assertEqual(os.lseek(session._descriptor, 0, os.SEEK_CUR), 1)
                        for target in (self.root.parent, self.root,
                                       self.root / ".scientist-one-resource-execution.lock",
                                       self.provider.journal_path):
                            with self.subTest(target=target.name):
                                fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
                                try:
                                    with self.assertRaises(BlockingIOError):
                                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                finally:
                                    os.close(fd)
            except BaseException as exc:
                if child:
                    os.write(writer, (type(exc).__name__ + ":" + str(exc)).encode()[:1000])
                    os._exit(0)
                raise
            if child:
                os.write(writer, b"UNSAFE_NORMAL_CHILD_EXIT")
                os._exit(4)
            self.assertEqual(self.provider.journal_path.read_bytes(), before)
            with self.guarded():
                pass
        finally:
            if not child:
                os.close(reader)
                if pid is None:
                    os.close(writer)
                elif not reaped:
                    observed, _status = os.waitpid(pid, os.WNOHANG)
                    if observed == 0:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)

    @unittest.skipUnless(hasattr(os, "fork"), "native fork is unavailable")
    def test_inherited_fork_binding_is_refused(self):
        with self.guarded() as session:
            reader, writer = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(reader)
                try:
                    holdout._require_simulated_reserve_resource_binding(
                        session, self.provider, self.root
                    )
                except holdout.HoldoutAccessViolation:
                    os.write(writer, b"REFUSED")
                    os._exit(0)
                except BaseException:
                    os._exit(3)
                os._exit(4)
            os.close(writer)
            reaped = False
            try:
                ready, _, _ = select.select([reader], [], [], 2)
                self.assertTrue(ready, "inherited session probe blocked")
                self.assertEqual(os.read(reader, 32), b"REFUSED")
                _pid, status = os.waitpid(pid, 0)
                reaped = True
                self.assertEqual(status, 0)
            finally:
                os.close(reader)
                if not reaped:
                    observed, _status = os.waitpid(pid, os.WNOHANG)
                    if observed == 0:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)


if __name__ == "__main__":
    unittest.main()
