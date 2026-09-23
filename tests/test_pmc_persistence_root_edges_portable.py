"""Portable disposable local-store PMC root edges."""

import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scientist_one import pmc_coordination as subject

BOOT = b"12345678-1234-4234-8234-123456789abc"
COORDINATOR = b"abcdefab-cdef-4abc-8def-abcdefabcdef"

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def envelope(payload):
    return canonical({"payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()})

def identity(path):
    value = path.stat()
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]

def write_fixture(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(envelope(payload))

class RootPmcPersistenceEdges(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pmc-store-root-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state = self.directory / "state.json"
        lock = self.directory / "coordinator.lock"
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        anchor = {
            "schema": "pmc-operational-anchor/v1",
            "trace_anchor": {
                "schema": "pmc-supplied-coordination-trace/v1",
                "coordinator_uuid": COORDINATOR.decode("ascii"),
                "boot_uuid": BOOT.decode("ascii"), "initialized_ns": 0, "initial_sequence": 0,
            },
            "directory_identity": identity(self.directory), "lock_identity": identity(lock),
        }
        write_fixture(self.directory / "anchor.json", anchor)
        write_fixture(self.state, {
            "schema": "pmc-operational-state/v1", "anchor_sha256": hashlib.sha256(canonical(anchor)).hexdigest(),
            "generation": 0, "sequence": 0, "phase": "QUIESCENT", "predecessor": None,
            "pending": None, "terminal": None, "last_cleanup_ns": None, "last_observed_ns": 0,
        })
        self.descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.descriptor)
        self.now = 100
        clock = patch.object(subject, "_pmc_store_clock", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    def owner(self, deadline=10.0):
        return subject._PmcCoordinationStore(self.descriptor, boot_uuid=BOOT, deadline_seconds=deadline)

    def bindings(self):
        return {"request_id": "a" * 64, "prepared_claim_sha256": "b" * 64,
                "policy_claim_sha256": "c" * 64, "attempt_number": 1}

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
                for path in self.directory.iterdir()}

    def payload(self):
        return json.loads(self.state.read_bytes())["payload"]

    def assert_fresh_refused_without_mutation(self):
        before = self.files()
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.owner():
                self.fail("invalid or unresolved state admitted")
        self.assertEqual(self.files(), before)

    def test_independent_canonical_fixture_admits_without_reset(self):
        before = self.files()
        with self.owner() as store:
            state = store.read_snapshot()
            self.assertEqual((state["sequence"], state["generation"], state["phase"]), (0, 0, "QUIESCENT"))
        self.assertEqual(self.files(), before)

    def test_defensive_readback_and_binding_copy(self):
        with self.owner() as store:
            bindings = self.bindings()
            pending = store.begin_pending(bindings)
            before = self.files()
            returned = store.read_snapshot()
            returned["pending"]["request_id"] = "d" * 64
            bindings["request_id"] = "e" * 64
            self.assertEqual(store.read_snapshot()["pending"]["request_id"], "a" * 64)
            self.assertTrue(store.confirm_current_transition(pending))
            self.assertEqual(self.files(), before)
            store.commit_terminal("NOT_SENT")

    def test_stale_terminal_never_clears_new_pending(self):
        with self.owner() as first:
            first.begin_pending(self.bindings())
            terminal = first.commit_terminal("NOT_SENT")
        with self.owner() as second:
            second.begin_pending(self.bindings())
            before = self.files()
            with self.assertRaises(subject._PmcStoreUnavailable):
                second.confirm_current_transition(terminal)
            self.assertEqual(self.files(), before)
            self.assertEqual(self.payload()["sequence"], 2)
        self.assert_fresh_refused_without_mutation()

    def test_valid_digest_does_not_accept_inconsistent_pending_summary(self):
        with self.owner() as store:
            store.begin_pending(self.bindings())
        valid = self.payload()
        variants = []
        for key, value in (("generation", 2), ("sequence", 2), ("phase", "QUIESCENT"),
                           ("last_cleanup_ns", 99), ("last_observed_ns", 99)):
            value_copy = copy.deepcopy(valid)
            value_copy[key] = value
            variants.append((key, value_copy))
        for key, payload in variants:
            with self.subTest(key=key):
                write_fixture(self.state, payload)
                self.assert_fresh_refused_without_mutation()

    def test_valid_digest_does_not_accept_mismatched_terminal_binding_or_floor(self):
        with self.owner() as store:
            store.begin_pending(self.bindings())
            self.now = 200
            store.commit_terminal("LOCAL_CLOSED_ABORTED", cleanup_ns=150)
        valid = self.payload()
        for key, value in (("request_id", "d" * 64), ("attempt_number", 2), ("cleanup_ns", 99)):
            with self.subTest(key=key):
                payload = copy.deepcopy(valid)
                payload["terminal"][key] = value
                write_fixture(self.state, payload)
                self.assert_fresh_refused_without_mutation()

    def test_more_than_128_attempts_is_not_trace_oracle_lifetime_quota(self):
        for sequence in range(1, 131):
            with self.owner() as store:
                pending = store.begin_pending(self.bindings())
                self.assertEqual((pending["sequence"], pending["attempt_number"]), (sequence, 1))
                store.commit_terminal("NOT_SENT")
        with self.owner() as store:
            result = store.read_snapshot()
            self.assertEqual((result["sequence"], result["generation"], result["phase"]), (130, 260, "QUIESCENT"))
            self.assertIsNone(result["last_cleanup_ns"])
        self.assertEqual(set(self.files()), {"anchor.json", "coordinator.lock", "state.json"})
        self.assertLess(self.state.stat().st_size, 16 * 1024)

    def test_failure_before_temporary_creation_leaves_confirmable_old_quiescent(self):
        original = subject._pmc_store_open

        def fail_temporary(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith("state.pending."):
                raise OSError("synthetic precreation failure")
            return original(name, *args, **kwargs)

        before = self.files()
        with self.owner() as store:
            with patch.object(subject, "_pmc_store_open", fail_temporary):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(self.bindings())
        self.assertEqual(self.files(), before)
        with self.owner() as recovered:
            self.assertEqual(recovered.begin_pending(self.bindings())["sequence"], 1)
            recovered.commit_terminal("NOT_SENT")

    def test_pending_replace_effect_then_exception_remains_blocked(self):
        original = subject._pmc_store_replace

        def replace_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("synthetic postreplacement failure")

        with self.owner() as store:
            with patch.object(subject, "_pmc_store_replace", replace_then_fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(self.bindings())
        self.assertEqual(self.payload()["phase"], "PENDING")
        self.assert_fresh_refused_without_mutation()

    def test_terminal_replace_effect_then_exception_allows_only_fresh_confirmed_readback(self):
        original = subject._pmc_store_replace

        def replace_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("synthetic terminal publication ambiguity")

        with self.owner() as store:
            store.begin_pending(self.bindings())
            with patch.object(subject, "_pmc_store_replace", replace_then_fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.commit_terminal("NOT_SENT")
            with self.assertRaises(subject._PmcStoreUnavailable):
                store.begin_pending(self.bindings())
        with self.owner() as recovered:
            self.assertEqual(recovered.read_snapshot()["generation"], 2)
            self.assertEqual(recovered.begin_pending(self.bindings())["sequence"], 2)
            recovered.commit_terminal("NOT_SENT")

    def test_expiry_after_confirmed_pending_allows_only_current_owner_not_sent(self):
        original = subject._pmc_store_replace

        def expire_after_replace(*args, **kwargs):
            original(*args, **kwargs)
            self.now = 10_000_000_000

        with self.owner() as store:
            with patch.object(subject, "_pmc_store_replace", expire_after_replace):
                with self.assertRaises(subject._PmcStoreDeadlineExpired):
                    store.begin_pending(self.bindings())
            self.assertEqual(self.payload()["phase"], "PENDING")
            terminal = store.commit_terminal("NOT_SENT")
            self.assertEqual(terminal["observed_ns"], self.now)
        with self.owner(deadline=11.0) as recovered:
            self.assertIsNone(recovered.read_snapshot()["last_cleanup_ns"])
            self.assertEqual(recovered.begin_pending(self.bindings())["sequence"], 2)
            recovered.commit_terminal("NOT_SENT")

    def test_confirmed_pending_owner_loss_is_not_recovered_as_not_sent(self):
        with self.owner() as store:
            store.begin_pending(self.bindings())
        self.assert_fresh_refused_without_mutation()

    def test_matching_digest_does_not_make_noncanonical_bytes_acceptable(self):
        value = json.loads(self.state.read_bytes())
        # Correct digest and values, but alternate whitespace is not the selected wire.
        self.state.write_bytes((json.dumps(value, indent=2) + "\n").encode("ascii"))
        self.assert_fresh_refused_without_mutation()

    def test_entry_cancellation_survives_secondary_close_error(self):
        primary = KeyboardInterrupt("synthetic cancellation")
        actual_close = subject._pmc_store_close

        def close_then_fail(descriptor):
            actual_close(descriptor)
            raise OSError("synthetic close outcome")

        store = self.owner()
        before = self.files()
        with patch.object(subject, "_pmc_store_flock", side_effect=primary), \
                patch.object(subject, "_pmc_store_close", close_then_fail):
            with self.assertRaises(KeyboardInterrupt) as caught:
                store.__enter__()
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.files(), before)

    def test_write_cancellation_survives_secondary_temporary_close_error(self):
        primary = KeyboardInterrupt("synthetic write cancellation")
        actual_open, actual_close = subject._pmc_store_open, subject._pmc_store_close
        temporary = set()

        def opened(name, *args, **kwargs):
            descriptor = actual_open(name, *args, **kwargs)
            if isinstance(name, str) and name.startswith("state.pending."):
                temporary.add(descriptor)
            return descriptor

        def close_then_fail(descriptor):
            actual_close(descriptor)
            if descriptor in temporary:
                raise OSError("synthetic temporary close outcome")

        with self.owner() as store:
            with patch.object(subject, "_pmc_store_open", opened), \
                    patch.object(subject, "_pmc_store_close", close_then_fail), \
                    patch.object(subject, "_pmc_store_write", side_effect=primary):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    store.begin_pending(self.bindings())
            self.assertIs(caught.exception, primary)
        self.assertEqual(self.payload()["phase"], "QUIESCENT")

    def test_uncertain_temporary_close_is_not_attempted_twice(self):
        actual_open, actual_close = subject._pmc_store_open, subject._pmc_store_close
        temporary = set()
        close_calls = []

        def opened(name, *args, **kwargs):
            descriptor = actual_open(name, *args, **kwargs)
            if isinstance(name, str) and name.startswith("state.pending."):
                temporary.add(descriptor)
            return descriptor

        def close_then_fail(descriptor):
            if descriptor in temporary:
                close_calls.append(descriptor)
                if len(close_calls) == 1:
                    actual_close(descriptor)
                # Deliberately never close a numeric descriptor again after an
                # uncertain outcome. Count an erroneous retry without reuse.
                raise OSError("synthetic uncertain close")
            return actual_close(descriptor)

        with self.owner() as store:
            with patch.object(subject, "_pmc_store_open", opened), \
                    patch.object(subject, "_pmc_store_close", close_then_fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(self.bindings())
        self.assertEqual(len(close_calls), 1)
        self.assertEqual(self.payload()["phase"], "QUIESCENT")

    def test_contender_waits_for_active_writer_temporary_instead_of_calling_it_orphan(self):
        actual_write = subject._pmc_store_write
        answers = queue.Queue()
        entered_waiter = threading.Event()
        worker = None
        launched = False

        def contender():
            entered_waiter.set()
            try:
                with self.owner(deadline=time.monotonic() + 2.0) as store:
                    answers.put(("ACQUIRED", store.read_snapshot()["phase"]))
            except BaseException as error:
                answers.put(("ERROR", type(error).__name__, str(error)))

        def written(descriptor, raw):
            nonlocal worker, launched
            result = actual_write(descriptor, raw)
            if not launched:
                launched = True
                worker = threading.Thread(target=contender)
                worker.start()
                self.assertTrue(entered_waiter.wait(timeout=1))
                # Give the contender time to attempt admission while the
                # current owner's legitimate temporary is visible under lock.
                time.sleep(0.05)
            return result

        try:
            with patch.object(subject, "_pmc_store_clock", time.monotonic_ns):
                with self.owner(deadline=time.monotonic() + 2.0) as store:
                    with patch.object(subject, "_pmc_store_write", written):
                        store.begin_pending(self.bindings())
                    store.commit_terminal("NOT_SENT")
                if worker is not None:
                    worker.join(timeout=3)
                    self.assertFalse(worker.is_alive())
                self.assertEqual(answers.get(timeout=1), ("ACQUIRED", "QUIESCENT"))
        finally:
            if worker is not None:
                worker.join(timeout=3)
