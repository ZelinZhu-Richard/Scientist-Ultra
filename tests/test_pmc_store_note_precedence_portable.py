"""Portable synthetic PMC store-note precedence root edges."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
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

class StoreNotePrecedence(unittest.TestCase):
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

    def check_primary(self, primary):
        primary.__notes__ = ()  # add_note cannot append to this malformed diagnostic field.
        store = self.owner()
        close = store.close
        closes = []

        def failed_after_close():
            closes.append(1)
            if len(closes) != 1:
                raise AssertionError("unexpected second close intercepted")
            close()  # One valid owned cleanup, never a numeric descriptor retry.
            raise OSError("fixture post-close failure")

        observed = None
        with patch.object(store, "close", failed_after_close):
            try:
                with store:
                    store.begin_pending(self.bindings())
                    pending_files = self.files()
                    raise primary
            except BaseException as error:
                observed = error
        self.assertIs(observed, primary)
        self.assertEqual(closes, [1])
        self.assertEqual(self.files(), pending_files)
        self.assertEqual(self.payload()["phase"], "PENDING")
        self.assert_fresh_refused_without_mutation()

    def test_store_exit_diagnostic_failure_does_not_replace_keyboard_interrupt(self):
        self.check_primary(KeyboardInterrupt("primary cancellation"))

    def test_store_exit_diagnostic_failure_does_not_replace_system_exit(self):
        self.check_primary(SystemExit(71))

    def test_diagnostic_failure_cannot_skip_remaining_detached_cleanup(self):
        primary = KeyboardInterrupt("primary retained")
        primary.__notes__ = ()
        attempts = []

        def inert_close(token):
            attempts.append(token)
            raise OSError("inert close failure; no descriptor operation")

        observed = None
        # These sentinel integers never reach an OS close; only helper sequencing
        # is under test. They are not native handles or resource authority.
        with patch.object(subject, "_pmc_store_close", inert_close):
            try:
                subject._pmc_store_cleanup((111, 222), primary=primary)
            except BaseException as error:
                observed = error
        self.assertIsNone(observed)
        self.assertEqual(attempts, [111, 222])

    def test_malformed_optional_notes_do_not_prevent_static_store_refusal(self):
        original = RuntimeError("fixture ordinary error")
        original.__notes__ = None
        sanitized = subject._pmc_store_sanitized(original)
        self.assertIsInstance(sanitized, subject._PmcStoreUnavailable)
        self.assertEqual(str(sanitized), "PMC_STORE_INVALID")
