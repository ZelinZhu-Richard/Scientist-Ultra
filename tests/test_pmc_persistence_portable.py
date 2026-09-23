"""Portable disposable local-store PMC controls."""

import hashlib
import json
import os
from pathlib import Path
import queue
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scientist_one import pmc_coordination as subject

BOOT = b"12345678-1234-4234-8234-123456789abc"
COORDINATOR = b"23456789-2345-4345-8345-23456789abcd"
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def write_envelope(path, payload):
    # Fixture setup/corruption only; never the implementation's commit path.
    raw = canonical({"payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()})
    Path(path).write_bytes(raw)
    os.chmod(path, 0o600)
    return raw

def read_envelope(path):
    return json.loads(Path(path).read_bytes())["payload"]

def identity(path):
    value = Path(path).stat()
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]

def provision_fixture(directory, *, initialized_ns=0, boot_uuid=BOOT, coordinator_uuid=COORDINATOR):
    directory = Path(directory)
    os.chmod(directory, 0o700)
    descriptor = os.open(directory / "coordinator.lock", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    anchor = {
        "schema": "pmc-operational-anchor/v1",
        "trace_anchor": {"schema": "pmc-supplied-coordination-trace/v1",
                         "coordinator_uuid": coordinator_uuid.decode("ascii"),
                         "boot_uuid": boot_uuid.decode("ascii"),
                         "initialized_ns": initialized_ns, "initial_sequence": 0},
        "directory_identity": identity(directory),
        "lock_identity": identity(directory / "coordinator.lock"),
    }
    write_envelope(directory / "anchor.json", anchor)
    state = {"schema": "pmc-operational-state/v1",
             "anchor_sha256": hashlib.sha256(canonical(anchor)).hexdigest(),
             "generation": 0, "sequence": 0, "phase": "QUIESCENT",
             "predecessor": None, "pending": None, "terminal": None,
             "last_cleanup_ns": None, "last_observed_ns": initialized_ns}
    write_envelope(directory / "state.json", state)
    return anchor

def bindings(**changes):
    result = {"request_id": "a" * 64, "prepared_claim_sha256": "b" * 64,
              "policy_claim_sha256": "c" * 64, "attempt_number": 1}
    result.update(changes)
    return result

class Clock:
    def __init__(self, now=1_000_000_000):
        self.now = now
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += max(1, int(seconds * 1_000_000_000))

class PmcPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pmc-store-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        provision_fixture(self.directory)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.fd)
        self.clock = Clock()
        self.clock_patch = patch.object(subject, "_pmc_store_clock", self.clock)
        self.sleep_patch = patch.object(subject, "_pmc_store_sleep", self.clock.sleep)
        self.clock_patch.start()
        self.sleep_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.addCleanup(self.sleep_patch.stop)

    def store(self, deadline=10.0, boot=BOOT):
        return subject._PmcCoordinationStore(self.fd, boot_uuid=boot, deadline_seconds=deadline)

    def raw(self):
        return (self.directory / "state.json").read_bytes()

    def test_genesis_and_defensive_snapshot(self):
        original = self.raw()
        with self.store() as store:
            snapshot = store.read_snapshot()
            self.assertEqual((snapshot["phase"], snapshot["generation"]), ("QUIESCENT", 0))
            snapshot["sequence"] = 400
            self.assertEqual(store.read_snapshot()["sequence"], 0)
        self.assertEqual(self.raw(), original)

    def test_complete_abort_and_not_sent_preserve_spacing(self):
        with self.store() as store:
            first = store.begin_pending(bindings())
            self.clock.now += 10
            closed = store.commit_terminal("LOCAL_CLOSED_ABORTED", cleanup_ns=self.clock.now)
            floor = closed["cleanup_ns"]
            second = store.begin_pending(bindings())
            self.assertEqual(second["observed_ns"], floor + subject._PMC_SPACING_NS)
            self.assertTrue(self.clock.sleeps)
            store.commit_terminal("NOT_SENT")
            self.assertEqual(store.read_snapshot()["last_cleanup_ns"], floor)
            store.begin_pending(bindings())
            store.commit_terminal("LOCAL_CLOSED_COMPLETE", cleanup_ns=self.clock.now)
            self.assertEqual(store.read_snapshot()["generation"], 6)
            self.assertEqual(first["sequence"], 1)

    def test_generated_short_histories_match_trace(self):
        records = []
        anchor = {"schema": subject._PMC_TRACE_SCHEMA, "coordinator_uuid": COORDINATOR,
                  "boot_uuid": BOOT, "initialized_ns": 0, "initial_sequence": 0}
        with self.store(deadline=100.0) as store:
            for index in range(18):
                pending = store.begin_pending(bindings(attempt_number=1 + index % 3))
                records.append(pending)
                kind = ("NOT_SENT", "LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED")[index % 3]
                self.clock.now += 1
                records.append(store.commit_terminal(kind, cleanup_ns=None if kind == "NOT_SENT" else self.clock.now))
                projected = subject._project_pmc_coordination_trace(anchor, tuple(records))
                current = store.read_snapshot()
                self.assertEqual(current["last_cleanup_ns"], projected.last_cleanup_ns)
                self.assertEqual(current["last_observed_ns"], projected.last_observed_ns)
                self.assertEqual(current["sequence"], projected.last_sequence)

    def test_pending_restart_refuses_and_never_clears(self):
        with self.store() as store:
            store.begin_pending(bindings())
        before = self.raw()
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
            with self.store():
                self.fail("pending restart entered")
        self.assertEqual(self.raw(), before)

    def test_current_transition_idempotent_readback_not_duplicate_append(self):
        with self.store() as store:
            pending = store.begin_pending(bindings())
            self.assertTrue(store.confirm_current_transition(pending))
            terminal = store.commit_terminal("NOT_SENT")
            before = self.raw()
            self.assertTrue(store.confirm_current_transition(terminal))
            self.assertEqual(self.raw(), before)
        with self.store() as store:
            self.assertTrue(store.confirm_current_transition(terminal))
            store.begin_pending(bindings())
            before = self.raw()
            with self.assertRaises(subject._PmcStoreUnavailable):
                store.confirm_current_transition(terminal)
            self.assertEqual(self.raw(), before)

    def test_deadline_expiry_before_acquisition_changes_nothing(self):
        before = self.raw()
        with self.assertRaises(subject._PmcStoreDeadlineExpired):
            with self.store(deadline=1.0):
                self.fail("expired entered")
        self.assertEqual(self.raw(), before)

    def test_pending_publication_expiry_can_only_record_current_not_sent(self):
        original = subject._pmc_store_replace

        def expire(*args, **kwargs):
            original(*args, **kwargs)
            self.clock.now = 10_000_000_000

        with self.store() as store:
            with patch.object(subject, "_pmc_store_replace", expire):
                with self.assertRaises(subject._PmcStoreDeadlineExpired):
                    store.begin_pending(bindings())
            self.assertEqual(read_envelope(self.directory / "state.json")["phase"], "PENDING")
            terminal = store.commit_terminal("NOT_SENT")
            self.assertEqual(terminal["observed_ns"], self.clock.now)
        with self.store(deadline=20.0) as store:
            self.assertEqual(store.read_snapshot()["phase"], "QUIESCENT")

    def test_late_cleanup_is_persisted_without_new_deadline(self):
        with self.store(deadline=2.0) as store:
            pending = store.begin_pending(bindings())
            self.clock.now = 3_000_000_000
            terminal = store.commit_terminal("LOCAL_CLOSED_ABORTED", cleanup_ns=self.clock.now)
            self.assertEqual(pending["deadline_seconds"], 2.0)
            self.assertEqual(terminal["cleanup_ns"], 3_000_000_000)
        with self.store(deadline=4.0) as store:
            pending = store.begin_pending(bindings())
            self.assertEqual(pending["observed_ns"], 3_333_333_334)
            store.commit_terminal("NOT_SENT")

    def test_spacing_cannot_fit_deadline_keeps_previous_state(self):
        with self.store() as store:
            store.begin_pending(bindings())
            store.commit_terminal("LOCAL_CLOSED_COMPLETE", cleanup_ns=self.clock.now)
        before = self.raw()
        with self.store(deadline=1.2) as store:
            with self.assertRaises(subject._PmcStoreDeadlineExpired):
                store.begin_pending(bindings())
        self.assertEqual(self.raw(), before)

    def test_exact_deadline_hex_and_static_bad_inputs(self):
        for value in (True, 10, float("nan"), float("inf"), -1.0):
            with self.subTest(value=value), self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_INVALID"):
                self.store(deadline=value)
        with self.store(deadline=1.234567891234) as store:
            store.begin_pending(bindings())
            value = read_envelope(self.directory / "state.json")
            self.assertEqual(value["pending"]["deadline_seconds"], (1.234567891234).hex())
            store.commit_terminal("NOT_SENT")

    def test_missing_files_or_orphan_never_bootstrap_or_cleanup(self):
        for name in ("anchor.json", "state.json", "coordinator.lock"):
            with self.subTest(name=name):
                path = self.directory / name
                raw = path.read_bytes()
                path.unlink()
                with self.assertRaises(subject._PmcStoreUnavailable):
                    with self.store():
                        self.fail("missing entered")
                self.assertFalse(path.exists())
                path.write_bytes(raw)
                os.chmod(path, 0o600)
                # A replaced lock is intentionally not repaired for later cases.
        orphan = self.directory / "state.pending.orphan"
        orphan.write_bytes(b"partial")
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.store():
                self.fail("orphan entered")
        self.assertEqual(orphan.read_bytes(), b"partial")

    def test_corruption_duplicate_keys_noncanonical_and_oversize_refuse(self):
        original = self.raw()
        damaged = [original.replace(b'"generation":0', b'"generation":1'),
                   original.rstrip(b"\n"), b" " + original,
                   b'{"payload":{},"payload":{},"sha256":"' + b"a" * 64 + b'"}\n',
                   b"x" * (subject._PMC_STORE_LIMIT + 1)]
        for raw in damaged:
            with self.subTest(size=len(raw)):
                (self.directory / "state.json").write_bytes(raw)
                with self.assertRaises(subject._PmcStoreUnavailable):
                    with self.store():
                        self.fail("corruption entered")
                self.assertEqual(self.raw(), raw)
        (self.directory / "state.json").write_bytes(original)

    def test_matching_checksum_does_not_excuse_semantic_corruption(self):
        original = read_envelope(self.directory / "state.json")
        changes = ({"generation": True}, {"sequence": 1}, {"phase": "PENDING"},
                   {"last_cleanup_ns": 0}, {"last_observed_ns": 1}, {"extra": 1})
        for change in changes:
            with self.subTest(change=change):
                write_envelope(self.directory / "state.json", dict(original, **change))
                with self.assertRaises(subject._PmcStoreUnavailable):
                    with self.store():
                        self.fail("semantic corruption entered")
        write_envelope(self.directory / "state.json", original)

    def test_changed_boot_and_lock_replacement_refuse(self):
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.store(boot=COORDINATOR):
                self.fail("wrong boot entered")
        with self.store() as store:
            path = self.directory / "coordinator.lock"
            path.unlink()
            path.write_bytes(b"")
            os.chmod(path, 0o600)
            with self.assertRaises(subject._PmcStoreUnavailable):
                store.begin_pending(bindings())

    def test_file_links_and_nonprivate_modes_refuse(self):
        state = self.directory / "state.json"
        original = self.raw()
        os.chmod(state, 0o644)
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.store():
                self.fail("public state entered")
        os.chmod(state, 0o600)
        with tempfile.TemporaryDirectory(prefix="pmc-linked-fixture-") as elsewhere:
            link = Path(elsewhere) / "link"
            os.link(state, link)
            with self.assertRaises(subject._PmcStoreUnavailable):
                with self.store():
                    self.fail("linked state entered")
            link.unlink()
            target = Path(elsewhere) / "state"
            target.write_bytes(original)
            state.unlink()
            state.symlink_to(target)
            with self.assertRaises(subject._PmcStoreUnavailable):
                with self.store():
                    self.fail("symlink state entered")

    def test_partial_write_completes_and_zero_write_preserves_orphan(self):
        actual = subject._pmc_store_write
        with self.store() as store:
            with patch.object(subject, "_pmc_store_write", lambda fd, raw: actual(fd, raw[:17])):
                store.begin_pending(bindings())
            store.commit_terminal("NOT_SENT")
            with patch.object(subject, "_pmc_store_write", return_value=0):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
        self.assertEqual(read_envelope(self.directory / "state.json")["phase"], "QUIESCENT")
        self.assertEqual(len(list(self.directory.glob("state.pending.*"))), 1)
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.store():
                self.fail("orphan recovery entered")

    def test_replace_failure_preserves_orphan_and_aborts_owner(self):
        before = self.raw()
        with self.store() as store:
            with patch.object(subject, "_pmc_store_replace", side_effect=OSError("PRIVATE_SENTINEL")):
                with self.assertRaisesRegex(subject._PmcStoreUnavailable, "^PMC_STORE_INVALID$"):
                    store.begin_pending(bindings())
            with self.assertRaises(subject._PmcStoreUnavailable):
                store.begin_pending(bindings())
        self.assertEqual(self.raw(), before)
        self.assertEqual(len(list(self.directory.glob("state.pending.*"))), 1)

    def test_old_quiescent_readback_after_failure_before_temp_creation(self):
        actual = subject._pmc_store_open

        def fail(name, *args, **kwargs):
            if name.startswith("state.pending."):
                raise OSError("fixture")
            return actual(name, *args, **kwargs)

        before = self.raw()
        with self.store() as store:
            with patch.object(subject, "_pmc_store_open", fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
        self.assertEqual(self.raw(), before)
        with self.store() as store:
            store.begin_pending(bindings())
            store.commit_terminal("NOT_SENT")

    def test_uncertain_pending_replace_cannot_be_recovered_as_terminal(self):
        actual = subject._pmc_store_replace

        def replaced_then_fail(*args, **kwargs):
            actual(*args, **kwargs)
            raise OSError("fixture")

        with self.store() as store:
            with patch.object(subject, "_pmc_store_replace", replaced_then_fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
            with self.assertRaises(subject._PmcStoreUnavailable):
                store.commit_terminal("NOT_SENT")
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
            with self.store():
                self.fail("pending recovered")

    def test_uncertain_terminal_replace_can_be_confirmed_by_fresh_owner(self):
        actual = subject._pmc_store_replace

        def replaced_then_fail(*args, **kwargs):
            actual(*args, **kwargs)
            raise OSError("fixture")

        with self.store() as store:
            store.begin_pending(bindings())
            with patch.object(subject, "_pmc_store_replace", replaced_then_fail):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.commit_terminal("LOCAL_CLOSED_ABORTED", cleanup_ns=self.clock.now)
        with self.store() as store:
            self.assertEqual(store.read_snapshot()["last_cleanup_ns"], self.clock.now)
            pending = store.begin_pending(bindings())
            self.assertEqual(pending["observed_ns"], 1_333_333_334)
            store.commit_terminal("NOT_SENT")

    def test_directory_sync_failure_leaves_pending(self):
        actual_sync = subject._pmc_store_fsync
        with self.store() as store:
            def fail_directory(fd):
                if fd == store._directory:
                    raise OSError("fixture")
                return actual_sync(fd)

            with patch.object(subject, "_pmc_store_fsync", fail_directory):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
            with self.store():
                self.fail("pending recovered")

    def test_file_sync_failure_keeps_old_snapshot_and_orphan(self):
        before = self.raw()
        with self.store() as store:
            with patch.object(subject, "_pmc_store_fsync", side_effect=OSError("fixture")):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
        self.assertEqual(self.raw(), before)
        self.assertEqual(len(list(self.directory.glob("state.pending.*"))), 1)

    def test_final_readback_failure_leaves_pending_and_no_repeated_write(self):
        actual_open, actual_replace = subject._pmc_store_open, subject._pmc_store_replace
        replaced = False
        replacements = []

        def replacement(*args, **kwargs):
            nonlocal replaced
            actual_replace(*args, **kwargs)
            replaced = True
            replacements.append(1)

        def opened(name, *args, **kwargs):
            if replaced and name == "state.json":
                raise OSError("fixture")
            return actual_open(name, *args, **kwargs)

        with self.store() as store:
            with patch.object(subject, "_pmc_store_replace", replacement), patch.object(subject, "_pmc_store_open", opened):
                with self.assertRaises(subject._PmcStoreUnavailable):
                    store.begin_pending(bindings())
        self.assertEqual(len(replacements), 1)
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
            with self.store():
                self.fail("pending recovered")

    def test_close_failure_preserves_body_error_or_cancellation_with_static_note(self):
        actual_close = subject._pmc_store_close
        armed = False

        def failed_close(fd):
            actual_close(fd)
            if armed:
                raise OSError("PRIVATE_CLOSE_SENTINEL")

        for primary in (ValueError("primary"), KeyboardInterrupt()):
            with self.subTest(primary=type(primary).__name__):
                armed = False
                with patch.object(subject, "_pmc_store_close", failed_close):
                    with self.assertRaises(type(primary)) as caught:
                        with self.store():
                            armed = True
                            raise primary
                self.assertIs(caught.exception, primary)
                self.assertIn("PMC_STORE_CLOSE_FAILED", primary.__notes__)
        store = self.store()
        store.__enter__()
        with patch.object(subject, "_pmc_store_close", failed_close):
            with self.assertRaisesRegex(subject._PmcStoreUnavailable, "^PMC_STORE_CLOSE_FAILED$"):
                store.close()

    def test_cancellation_is_not_swallowed_and_does_not_clear_pending(self):
        actual = subject._pmc_store_replace

        def interrupt(*args, **kwargs):
            actual(*args, **kwargs)
            raise KeyboardInterrupt()

        with self.store() as store:
            with patch.object(subject, "_pmc_store_replace", interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    store.begin_pending(bindings())
        self.assertEqual(read_envelope(self.directory / "state.json")["phase"], "PENDING")

    def test_constructor_cleanup_preserves_cancellation_and_sanitized_primary_notes(self):
        actual_dup, actual_stat, actual_close = os.dup, os.fstat, subject._pmc_store_close
        for primary in (KeyboardInterrupt(), ValueError("PRIVATE_PRIMARY")):
            with self.subTest(primary=type(primary).__name__):
                owned, closed = [], []

                def duplicate(fd):
                    result = actual_dup(fd)
                    owned.append(result)
                    return result

                def metadata(fd):
                    if fd in owned:
                        raise primary
                    return actual_stat(fd)

                def closing(fd):
                    closed.append(fd)
                    actual_close(fd)
                    raise OSError("PRIVATE_SECONDARY")

                expected = KeyboardInterrupt if isinstance(primary, KeyboardInterrupt) else subject._PmcStoreUnavailable
                with patch.object(os, "dup", duplicate), patch.object(os, "fstat", metadata), patch.object(subject, "_pmc_store_close", closing):
                    with self.assertRaises(expected) as caught:
                        self.store()
                if isinstance(primary, KeyboardInterrupt):
                    self.assertIs(caught.exception, primary)
                else:
                    self.assertEqual(str(caught.exception), "PMC_STORE_INVALID")
                self.assertIn("PMC_STORE_CLOSE_FAILED", caught.exception.__notes__)
                self.assertEqual(closed, owned)

    def test_file_validation_cleanup_preserves_primary_and_closes_once(self):
        actual_stat, actual_close = os.stat, subject._pmc_store_close
        for primary in (KeyboardInterrupt(), ValueError("PRIVATE_PRIMARY")):
            with self.subTest(primary=type(primary).__name__), self.store() as store:
                closed = []

                def metadata(name, *args, **kwargs):
                    if name == "anchor.json":
                        raise primary
                    return actual_stat(name, *args, **kwargs)

                def closing(fd):
                    closed.append(fd)
                    actual_close(fd)
                    raise OSError("PRIVATE_SECONDARY")

                with patch.object(os, "stat", metadata), patch.object(subject, "_pmc_store_close", closing):
                    with self.assertRaises(type(primary)) as caught:
                        store._file("anchor.json")
                self.assertIs(caught.exception, primary)
                self.assertIn("PMC_STORE_CLOSE_FAILED", primary.__notes__)
                self.assertEqual(len(closed), 1)

    def test_read_cleanup_preserves_cancellation_and_public_static_evidence(self):
        actual_close = subject._pmc_store_close
        for primary in (KeyboardInterrupt(), ValueError("PRIVATE_PRIMARY")):
            with self.subTest(primary=type(primary).__name__), self.store() as store:
                closed = []

                def closing(fd):
                    closed.append(fd)
                    actual_close(fd)
                    raise OSError("PRIVATE_SECONDARY")

                expected = KeyboardInterrupt if isinstance(primary, KeyboardInterrupt) else subject._PmcStoreUnavailable
                with patch.object(subject, "_pmc_store_read", side_effect=primary), patch.object(subject, "_pmc_store_close", closing):
                    with self.assertRaises(expected) as caught:
                        store.read_snapshot()
                if isinstance(primary, KeyboardInterrupt):
                    self.assertIs(caught.exception, primary)
                else:
                    self.assertEqual(str(caught.exception), "PMC_STORE_INVALID")
                self.assertIn("PMC_STORE_CLOSE_FAILED", caught.exception.__notes__)
                self.assertEqual(len(closed), 1)

    def test_entry_cleanup_attempts_other_owned_descriptors_without_masking_cancellation(self):
        actual_close = subject._pmc_store_close
        primary, closed = KeyboardInterrupt(), []

        def closing(fd):
            closed.append(fd)
            actual_close(fd)
            raise OSError("PRIVATE_SECONDARY")

        store = self.store()
        # Reach post-lock sync without making earlier successful read closes fail.
        armed = False

        def sync(fd):
            nonlocal armed
            armed = True
            raise primary

        def conditional_close(fd):
            if armed:
                closing(fd)
            else:
                actual_close(fd)

        with patch.object(subject, "_pmc_store_fsync", sync), patch.object(subject, "_pmc_store_close", conditional_close):
            with self.assertRaises(KeyboardInterrupt) as caught:
                store.__enter__()
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(closed), 3)
        self.assertEqual(len(set(closed)), 3)
        self.assertIn("PMC_STORE_CLOSE_FAILED", primary.__notes__)
        self.assertIsNone(store._directory)
        self.assertIsNone(store._lock)

    def test_temporary_close_is_once_on_write_cancellation_and_close_then_raise(self):
        actual_open, actual_close = subject._pmc_store_open, subject._pmc_store_close
        for cancel_write in (True, False):
            with self.subTest(cancel_write=cancel_write):
                # Each uncertain close leaves an orphan; use a separate fixture.
                with tempfile.TemporaryDirectory(prefix="pmc-close-fixture-") as directory:
                    provision_fixture(directory)
                    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with subject._PmcCoordinationStore(directory_fd, boot_uuid=BOOT, deadline_seconds=10.0) as store:
                            temporary_fd, closes = None, []
                            primary = KeyboardInterrupt()

                            def opened(name, *args, **kwargs):
                                nonlocal temporary_fd
                                result = actual_open(name, *args, **kwargs)
                                if name.startswith("state.pending."):
                                    temporary_fd = result
                                return result

                            def closing(fd):
                                if temporary_fd is not None and fd == temporary_fd:
                                    closes.append(fd)
                                    # Never close twice, even if the implementation regresses.
                                    if len(closes) == 1:
                                        actual_close(fd)
                                    raise OSError("PRIVATE_CLOSE")
                                return actual_close(fd)

                            with patch.object(subject, "_pmc_store_open", opened), patch.object(subject, "_pmc_store_close", closing):
                                if cancel_write:
                                    with patch.object(subject, "_pmc_store_write", side_effect=primary):
                                        with self.assertRaises(KeyboardInterrupt) as caught:
                                            store.begin_pending(bindings())
                                    self.assertIs(caught.exception, primary)
                                    self.assertIn("PMC_STORE_CLOSE_FAILED", primary.__notes__)
                                else:
                                    with self.assertRaises(subject._PmcStoreUnavailable):
                                        store.begin_pending(bindings())
                            self.assertEqual(closes, [temporary_fd])
                    finally:
                        os.close(directory_fd)

    def test_real_thread_separate_open_exclusion_and_foreign_owner_refusal(self):
        # Restore genuine native clock/sleep for this contention control.
        self.clock_patch.stop()
        self.sleep_patch.stop()
        answers = queue.Queue()
        with self.store(deadline=time.monotonic() + 3.0) as owner:
            def attempt():
                try:
                    owner.read_snapshot()
                except subject._PmcStoreUnavailable as error:
                    answers.put(str(error))
                fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with subject._PmcCoordinationStore(fd, boot_uuid=BOOT, deadline_seconds=time.monotonic() + 0.1):
                        answers.put("UNEXPECTED")
                except subject._PmcStoreDeadlineExpired:
                    answers.put("CONTENDED")
                finally:
                    os.close(fd)

            worker = threading.Thread(target=attempt)
            worker.start()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(answers.get(timeout=1), "PMC_STORE_OWNER_MISMATCH")
            self.assertEqual(answers.get(timeout=1), "CONTENDED")
            self.assertEqual(owner.read_snapshot()["sequence"], 0)
        with self.store(deadline=time.monotonic() + 1.0):
            pass

    def child(self, phase, operation="pending", directory=None):
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c",
             "import runpy, sys; sys.path.insert(0, sys.argv[1]); sys.argv = sys.argv[2:]; runpy.run_path(sys.argv[0], run_name='__main__')",
             str(Path(subject.__file__).resolve().parents[1]), str(Path(__file__).resolve()),
             "--child", str(self.directory if directory is None else directory), phase, operation],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(self.directory.parent),
        )
        self.addCleanup(self.finish_child, process)
        self.assertTrue(select.select([process.stdout], [], [], 5)[0], "child did not reach phase")
        message = process.stdout.readline()
        self.assertEqual(message, "AT_PHASE\n", message + process.stderr.read() if process.poll() is not None else message)
        return process

    @staticmethod
    def finish_child(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    def test_real_process_contends_across_working_directories(self):
        self.clock_patch.stop()
        self.sleep_patch.stop()
        process = self.child("locked")
        before = self.raw()
        with self.assertRaises(subject._PmcStoreDeadlineExpired):
            with self.store(deadline=time.monotonic() + 0.1):
                self.fail("concurrent owner")
        self.assertEqual(self.raw(), before)
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        with self.store(deadline=time.monotonic() + 1.0):
            pass

    def test_active_writer_temporary_is_not_an_orphan_until_lock_acquired(self):
        self.clock_patch.stop()
        self.sleep_patch.stop()
        process = self.child("after_create")
        self.assertEqual(len(list(self.directory.glob("state.pending.*"))), 1)
        with self.assertRaises(subject._PmcStoreDeadlineExpired):
            with self.store(deadline=time.monotonic() + 0.1):
                self.fail("concurrent temporary accepted")
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "^PMC_STORE_INVALID$"):
            with self.store(deadline=time.monotonic() + 1.0):
                self.fail("real orphan accepted")

    def test_actual_process_crash_before_pending_create_is_old_quiescent(self):
        process = self.child("before_create")
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        self.assertEqual(read_envelope(self.directory / "state.json")["phase"], "QUIESCENT")
        with self.store() as store:
            self.assertEqual(store.read_snapshot()["sequence"], 0)

    def test_actual_process_crash_after_temp_write_leaves_refused_orphan(self):
        process = self.child("after_write")
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        self.assertEqual(read_envelope(self.directory / "state.json")["phase"], "QUIESCENT")
        self.assertEqual(len(list(self.directory.glob("state.pending.*"))), 1)
        with self.assertRaises(subject._PmcStoreUnavailable):
            with self.store():
                self.fail("orphan recovered")

    def test_actual_process_crash_after_pending_replace_remains_pending(self):
        process = self.child("after_replace")
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
            with self.store():
                self.fail("pending recovered")

    def test_actual_process_crash_after_terminal_replace_is_fresh_readback(self):
        process = self.child("after_replace", "terminal")
        process.terminate()
        self.assertLess(process.wait(timeout=3), 0)
        with self.store() as store:
            self.assertEqual(store.read_snapshot()["phase"], "QUIESCENT")
            self.assertEqual(store.read_snapshot()["sequence"], 1)

    def test_process_crash_matrix_at_remaining_publication_boundaries(self):
        phases = ("after_create", "after_file_sync", "before_replace", "after_directory_sync",
                  "before_readback", "after_readback", "confirmed")
        for operation in ("pending", "terminal"):
            for phase in phases:
                with self.subTest(operation=operation, phase=phase):
                    with tempfile.TemporaryDirectory(prefix="pmc-crash-fixture-") as directory:
                        provision_fixture(directory)
                        process = self.child(phase, operation, directory)
                        process.terminate()
                        self.assertLess(process.wait(timeout=3), 0)
                        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            store = subject._PmcCoordinationStore(fd, boot_uuid=BOOT, deadline_seconds=10.0)
                            if phase in {"after_create", "after_file_sync", "before_replace"}:
                                self.assertEqual(len(list(Path(directory).glob("state.pending.*"))), 1)
                                with self.assertRaises(subject._PmcStoreUnavailable):
                                    with store:
                                        self.fail("orphan accepted")
                            elif operation == "pending":
                                with self.assertRaisesRegex(subject._PmcStoreUnavailable, "PMC_STORE_PENDING"):
                                    with store:
                                        self.fail("pending accepted")
                            else:
                                with store:
                                    self.assertEqual(store.read_snapshot()["phase"], "QUIESCENT")
                                    self.assertEqual(store.read_snapshot()["generation"], 2)
                        finally:
                            os.close(fd)


def child_main(directory, phase, operation):
    def stop():
        print("AT_PHASE", flush=True)
        sys.stdin.readline()

    clock = Clock()
    subject._pmc_store_clock, subject._pmc_store_sleep = clock, clock.sleep
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with subject._PmcCoordinationStore(fd, boot_uuid=BOOT, deadline_seconds=100.0) as store:
            if phase == "locked":
                stop()
                return
            if operation == "terminal":
                store.begin_pending(bindings())
            actual_open, actual_write, actual_replace = subject._pmc_store_open, subject._pmc_store_write, subject._pmc_store_replace
            actual_sync, actual_read = subject._pmc_store_fsync, subject._pmc_store_read
            did_replace = False

            def opened(name, *args, **kwargs):
                if phase == "before_create" and name.startswith("state.pending."):
                    stop()
                if phase == "before_readback" and did_replace and name == "state.json":
                    stop()
                result = actual_open(name, *args, **kwargs)
                if phase == "after_create" and name.startswith("state.pending."):
                    stop()
                return result

            def written(*args, **kwargs):
                result = actual_write(*args, **kwargs)
                if phase == "after_write":
                    stop()
                return result

            def replaced(*args, **kwargs):
                nonlocal did_replace
                if phase == "before_replace":
                    stop()
                result = actual_replace(*args, **kwargs)
                did_replace = True
                if phase == "after_replace":
                    stop()
                return result

            def synced(descriptor):
                result = actual_sync(descriptor)
                if ((phase == "after_file_sync" and descriptor != store._directory)
                        or (phase == "after_directory_sync" and descriptor == store._directory)):
                    stop()
                return result

            def read(*args, **kwargs):
                result = actual_read(*args, **kwargs)
                if phase == "after_readback" and did_replace and result == b"":
                    stop()
                return result

            subject._pmc_store_open, subject._pmc_store_write, subject._pmc_store_replace = opened, written, replaced
            subject._pmc_store_fsync, subject._pmc_store_read = synced, read
            if operation == "terminal":
                store.commit_terminal("NOT_SENT")
            else:
                store.begin_pending(bindings())
            if phase == "confirmed":
                stop()
    finally:
        os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        child_main(*sys.argv[2:])
    else:
        unittest.main()
