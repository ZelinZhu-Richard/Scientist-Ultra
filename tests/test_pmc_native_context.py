"""Pure-rule and temporary synthetic native-primitive fixtures, never authority."""
import _thread
import ctypes
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import pickle
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one import pmc_coordination as subject


def instant(value):
    delta = datetime.fromisoformat(value).replace(tzinfo=timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000


def rules(footer=b"EST5EDT,M3.2.0,M11.1.0", *, offset=-18000):
    header = b"TZif2" + b"\x00" * 15 + struct.pack(">6I", 0, 0, 0, 0, 2, 8)
    block = struct.pack(">iBBiBB", offset, 0, 0, offset + 3600, 1, 4) + b"EST\x00EDT\x00"
    return header + block + header + block + b"\n" + footer + b"\n"


def bounded_raw_thread(target):
    """Real low-level thread; wait for body and native TLS teardown, no ID mocks."""
    ready, done, teardown = threading.Event(), threading.Event(), threading.Event()
    holder = {}
    local_storage = _thread._local()

    class ExitNotice:
        def __del__(self):
            teardown.set()

    def invoke():
        # Native TLS, not threading._active, owns this sole instance reference.
        # CPython3.14 no longer exposes the former _thread._set_sentinel API.
        local_storage.exit_notice = ExitNotice()
        ready.set()
        try:
            target()
        except BaseException as error:
            holder["error"] = error
        finally:
            done.set()

    _thread.start_new_thread(invoke, ())
    if not ready.wait(3) or not done.wait(3):
        raise AssertionError("raw thread target did not finish")
    if not teardown.wait(3):
        raise AssertionError("raw native TLS teardown did not occur")
    if "error" in holder:
        raise holder["error"]


class _Call:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class NativeFixture:
    """Real read-only fd operations inside an owned temporary synthetic tree.

    Root ownership, passwd, mount flags, boot and clocks are emulated at module
    import. These fixtures do not demonstrate production native identity trust.
    No production API receives a test path, factory, native context or clock.
    """
    def __init__(self, root):
        self.root = root
        self.home = root / "Users" / "fixture-principal"
        self.namespace = self.home / "Library/Application Support/Scientist-Ultra/pmc-oai-coordinator"
        self.zone = root / "private/var/db/timezone/tz/fixture/zoneinfo/America/New_York"
        self.namespace.mkdir(parents=True, mode=0o700)
        self.namespace.parent.chmod(0o700)
        self.zone.parent.mkdir(parents=True)
        (root / "usr/share").mkdir(parents=True)
        (root / "usr/share/zoneinfo").symlink_to("/var/db/timezone/zoneinfo")
        (root / "var").symlink_to("private/var")
        (root / "private/var/db/timezone/zoneinfo").symlink_to("/var/db/timezone/tz/fixture/zoneinfo")
        self.zone.write_bytes(rules())
        self.uid, self.euid, self.gid, self.egid = 501, 501, 20, 20
        self.mount_flags = 0x1000
        self.boots = [b"12345678-1234-4234-8234-123456789abc\x00"]
        self.boot_reads = 0
        self.boot_error = None
        self.monotonic_values = [100, 200]
        self.monotonic_index = 0
        self.wall = instant("2026-09-14T08:59:59")
        self.fd_paths = {}
        self.open_flags = []
        self.owner_overrides = {}
        self.fail_open = None
        self.read_error = None
        self.final_stat_error = None
        self.fstat_error = None
        self.real_open, self.real_close, self.real_read = os.open, os.close, os.read
        self.real_stat, self.real_fstat, self.real_readlink = os.stat, os.fstat, os.readlink
        self.module = None

    def metadata(self, value, path):
        names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns")
        result = {name: getattr(value, name) for name in names}
        result["st_uid"] = self.owner_overrides.get(str(path), self.euid if path == self.home or self.home in path.parents else 0)
        return SimpleNamespace(**result)

    def opened(self, path, flags, mode=0o777, *, dir_fd=None):
        if self.fail_open is not None and path == self.fail_open[0]:
            raise self.fail_open[1]
        self.open_flags.append(flags)
        if path == "/":
            target = self.root
            fd = self.real_open(target, flags)
        else:
            target = self.fd_paths[dir_fd] / path
            fd = self.real_open(path, flags, mode, dir_fd=dir_fd)
        self.fd_paths[fd] = target
        return fd

    def closed(self, fd):
        try:
            return self.real_close(fd)
        finally:
            self.fd_paths.pop(fd, None)

    def stated(self, path, *, dir_fd, follow_symlinks=False):
        if self.final_stat_error is not None and self.boot_reads >= 2:
            raise self.final_stat_error
        target = self.fd_paths[dir_fd] / path
        return self.metadata(self.real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks), target)

    def fstated(self, fd):
        if self.fstat_error is not None:
            raise self.fstat_error
        return self.metadata(self.real_fstat(fd), self.fd_paths[fd])

    def read(self, fd, count):
        if self.read_error is not None:
            raise self.read_error
        return self.real_read(fd, count)

    def sysctl(self, name, output, size, new, new_size):
        assert name == b"kern.bootsessionuuid" and new is None and new_size == 0
        if self.boot_error is not None:
            raise self.boot_error
        raw = self.boots[min(self.boot_reads, len(self.boots) - 1)]
        size._obj.value = len(raw)
        if output is not None:
            ctypes.memmove(output, raw, len(raw))
            self.boot_reads += 1
        return 0

    def fstatfs(self, fd, output):
        assert fd in self.fd_paths
        output._obj.f_flags = self.mount_flags
        return 0

    def monotonic(self):
        result = self.monotonic_values[min(self.monotonic_index, len(self.monotonic_values) - 1)]
        self.monotonic_index += 1
        return result

    def load(self):
        path = Path(subject.__file__)
        name = f"_pmc_fixture_{id(self)}"
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        library = SimpleNamespace(sysctlbyname=_Call(self.sysctl), fstatfs64=_Call(self.fstatfs))
        import pwd
        import time
        with patch.object(os, "open", self.opened), patch.object(os, "close", self.closed), patch.object(os, "read", self.read), \
             patch.object(os, "stat", self.stated), patch.object(os, "fstat", self.fstated), \
             patch.object(os, "getuid", lambda: self.uid), patch.object(os, "geteuid", lambda: self.euid), \
             patch.object(os, "getgid", lambda: self.gid), patch.object(os, "getegid", lambda: self.egid), \
             patch.object(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_uid=uid, pw_dir="/Users/fixture-principal")), \
             patch.object(time, "monotonic_ns", self.monotonic), patch.object(time, "time_ns", lambda: self.wall), \
             patch.object(ctypes, "CDLL", return_value=library), patch.object(sys, "platform", "darwin"):
            spec.loader.exec_module(module)
        self.module = module
        return module


class ScheduleTests(unittest.TestCase):
    def test_exact_subsecond_weekday_boundaries_and_weekend(self):
        for utc, expected in (("2026-09-14T09:00:00", True), ("2026-09-15T01:00:00", False)):
            boundary = instant(utc)
            for delta in (-1, 0, 1):
                projected = subject.project_pmc_schedule(rules(), utc_unix_ns=boundary + delta)
                self.assertEqual(projected.weekday_0500_2100_window, expected if delta >= 0 else not expected)
                self.assertEqual(projected.local_nanosecond, (boundary + delta) % 1_000_000_000)
                self.assertEqual(projected.rule_identity_status, "UNVERIFIED_SUPPLIED_TZIF_BYTES")
        weekend = subject.project_pmc_schedule(rules(), utc_unix_ns=instant("2026-09-13T16:00:00"))
        self.assertEqual(weekend.local_iso_weekday, 7)
        self.assertFalse(weekend.weekday_0500_2100_window)

    def test_dst_gap_fold_and_historical_supplied_rules(self):
        before = subject.project_pmc_schedule(rules(), utc_unix_ns=instant("2026-03-08T06:59:59"))
        after = subject.project_pmc_schedule(rules(), utc_unix_ns=instant("2026-03-08T07:00:00"))
        self.assertEqual((before.local_hour, after.local_hour), (1, 3))
        folded = subject.project_pmc_schedule(rules(), utc_unix_ns=instant("2026-11-01T06:00:00"))
        self.assertEqual((folded.local_hour, folded.fold), (1, 1))
        old_rules = rules(b"EST5EDT,M4.1.0,M10.5.0")
        when = instant("2006-03-20T09:30:00")
        historical = subject.project_pmc_schedule(old_rules, utc_unix_ns=when)
        modern = subject.project_pmc_schedule(rules(), utc_unix_ns=when)
        self.assertEqual((historical.utc_offset_seconds, modern.utc_offset_seconds), (-18000, -14400))
        self.assertFalse(historical.weekday_0500_2100_window)
        self.assertTrue(modern.weekday_0500_2100_window)
        self.assertNotEqual(historical.tzif_sha256, modern.tzif_sha256)

    def test_projection_ignores_environment_and_never_opens_rule_paths(self):
        expected = subject.project_pmc_schedule(rules(), utc_unix_ns=0)
        with patch.dict(os.environ, {"HOME": "/not-used", "TZ": "UTC", "PYTHONTZPATH": "/not-used"}), \
             patch("builtins.open", side_effect=AssertionError("no file reads")), \
             patch.object(os, "open", side_effect=AssertionError("no native reads")):
            self.assertEqual(subject.project_pmc_schedule(rules(), utc_unix_ns=0), expected)

    def test_bad_types_overflow_and_unsupported_versions_are_static(self):
        class Bytes(bytes):
            pass
        class Integer(int):
            pass
        for raw in (None, bytearray(rules()), Bytes(rules()), b"", b"TZif2", rules() + b"trailing",
                    rules().replace(b"TZif2", b"TZif3"), b"x" * 65537):
            with self.subTest(raw_type=type(raw).__name__):
                with self.assertRaises(subject.PmcScheduleProjectionError) as caught:
                    subject.project_pmc_schedule(raw, utc_unix_ns=0)
                self.assertEqual(str(caught.exception), "SCHEDULE_RULES_INVALID")
                self.assertIsNone(caught.exception.__context__)
        for value in (True, Integer(0), 1.0, "0", None, -(1 << 63) - 1, 1 << 63):
            with self.assertRaises(subject.PmcScheduleProjectionError):
                subject.project_pmc_schedule(rules(), utc_unix_ns=value)

    def test_tzif_counts_reserved_structure_and_footer_refuse(self):
        data = rules()
        variants = [data[:20] + struct.pack(">6I", 0, 0, 0, 0xffffffff, 1, 1) + data[44:],
                    data[:5] + b"x" + data[6:], data[:-1], data + b"\n",
                    rules(b"PRIVATE_BAD_FOOTER"), data[:48] + b"\x02" + data[49:],
                    data[:49] + b"\x08" + data[50:]]
        for raw in variants:
            with self.subTest(size=len(raw)):
                with self.assertRaises(subject.PmcScheduleProjectionError):
                    subject.project_pmc_schedule(raw, utc_unix_ns=0)

    def test_signed64_endpoints_and_negative_subsecond_are_exact(self):
        for value in (-(1 << 63), -1, 0, (1 << 63) - 1):
            projected = subject.project_pmc_schedule(rules(), utc_unix_ns=value)
            self.assertEqual(projected.utc_unix_ns, value)
            self.assertEqual(projected.local_nanosecond, value % 1_000_000_000)

    def test_malicious_counts_rejected_before_zoneinfo_allocator(self):
        import zoneinfo
        calls = []
        class ObservedZoneInfo:
            @staticmethod
            def from_file(stream):
                calls.append(True)
                raise AssertionError("allocator must not be entered")
        name = "_pmc_tzif_precheck_fixture"
        spec = importlib.util.spec_from_file_location(name, subject.__file__)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        with patch.object(zoneinfo, "ZoneInfo", ObservedZoneInfo):
            spec.loader.exec_module(module)
        data = rules()
        for field in range(6):
            count_offset = 20 + field * 4
            bad = data[:count_offset] + b"\xff" * 4 + data[count_offset + 4:]
            with self.assertRaises(module.PmcScheduleProjectionError):
                module.project_pmc_schedule(bad, utc_unix_ns=0)
        self.assertEqual(calls, [])

    def test_explicit_transition_table_is_used(self):
        counts = struct.pack(">6I", 0, 0, 0, 2, 2, 8)
        header = b"TZif2" + b"\x00" * 15 + counts
        types = struct.pack(">iBBiBB", -18000, 0, 0, -14400, 1, 4) + b"EST\x00EDT\x00"
        first = struct.pack(">2i", 100, 200) + b"\x01\x00" + types
        second = struct.pack(">2q", 100, 200) + b"\x01\x00" + types
        data = header + first + header + second + b"\n\n"
        for seconds, offset in ((99, -18000), (100, -14400), (199, -14400), (200, -18000)):
            self.assertEqual(subject.project_pmc_schedule(data, utc_unix_ns=seconds * 10**9).utc_offset_seconds, offset)
        for bad in (header + struct.pack(">2i", 200, 100) + first[8:] + header + second + b"\n\n",
                    header + first[:8] + b"\x02\x00" + first[10:] + header + second + b"\n\n"):
            with self.assertRaises(subject.PmcScheduleProjectionError):
                subject.project_pmc_schedule(bad, utc_unix_ns=0)


class NativeContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = NativeFixture(Path(temporary.name))
        self.module = self.fixture.load()

    def test_fixture_context_is_private_closeable_and_read_only(self):
        with patch.dict(os.environ, {"HOME": "/not-used", "TZ": "UTC", "PYTHONTZPATH": "/not-used"}):
            context = self.module.acquire_native_pmc_context()
        self.assertTrue(context._fds)
        self.assertEqual(context._tzif_bytes, rules())
        self.assertNotIn("fixture-principal", repr(context))
        self.assertNotIn("12345678", repr(context))
        with self.assertRaises(TypeError):
            pickle.dumps(context)
        with self.assertRaises(TypeError):
            json.dumps(context)
        with context:
            self.assertEqual(context._monotonic_interval_ns, (100, 200))
        self.assertFalse(self.fixture.fd_paths)
        context.close()
        with self.assertRaises(self.module.NativePmcContextUnavailable):
            context.__enter__()
        forbidden = os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR
        self.assertTrue(all(not flags & forbidden for flags in self.fixture.open_flags))
        with self.assertRaises(TypeError):
            self.module.acquire_native_pmc_context(path=self.fixture.root)

    def test_missing_native_local_refuses_before_open_without_python_fallback(self):
        import _threading_local
        with patch.object(threading, "local", _threading_local.local):
            for replacement in ("missing", None):
                with patch.object(_thread, "_local", replacement):
                    if replacement == "missing":
                        del _thread._local
                    unavailable = self.fixture.load()
                    with self.assertRaises(unavailable.NativePmcContextUnavailable) as caught:
                        unavailable.acquire_native_pmc_context()
                    self.assertEqual(str(caught.exception), "PLATFORM_UNAVAILABLE")
                    self.assertIsNone(caught.exception.__context__)
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertEqual(self.fixture.open_flags, [])
                    self.assertFalse(self.fixture.fd_paths)
                    projected = unavailable.project_pmc_schedule(rules(), utc_unix_ns=0)
                    self.assertEqual(projected.rule_identity_status, "UNVERIFIED_SUPPLIED_TZIF_BYTES")

    def test_captured_native_local_survives_later_factory_replacement(self):
        with patch.object(_thread, "_local", side_effect=AssertionError("PRIVATE_CHANGED_FACTORY")), \
             patch.object(threading, "local", side_effect=AssertionError("no fallback")):
            with self.module.acquire_native_pmc_context() as context:
                self.assertIs(context.__enter__(), context)
        self.assertFalse(self.fixture.fd_paths)

    def test_raw_native_owner_reentry_and_idempotent_close_remain_legitimate(self):
        observed = []

        def owner():
            first = self.module.acquire_native_pmc_context()
            second = self.module.acquire_native_pmc_context()
            self.assertIs(first._owner_lifetime, second._owner_lifetime)
            self.assertIs(first._owner_thread, threading.current_thread())
            with first:
                self.assertIs(first.__enter__(), first)
            first.close()
            second.close()
            second.close()
            observed.append((first._closed, second._closed))

        bounded_raw_thread(owner)
        self.assertEqual(observed, [(True, True)])
        self.assertFalse(self.fixture.fd_paths)

    def test_raw_native_successor_reused_identity_cannot_enter_or_close_owner_fds(self):
        owner, observations = {}, []

        def acquire():
            context = self.module.acquire_native_pmc_context()
            self.assertIs(context.__enter__(), context)
            owner.update(context=context, ident=threading.get_ident(), native_id=threading.get_native_id(),
                         thread=threading.current_thread())

        bounded_raw_thread(acquire)
        context = owner["context"]
        held = tuple(context._fds)

        def successor():
            result = {"ident_reused": threading.get_ident() == owner["ident"],
                      "distinct_native_id": threading.get_native_id() != owner["native_id"],
                      "same_thread_object": threading.current_thread() is owner["thread"]}
            for label, action in (("enter", context.__enter__), ("close", context.close)):
                with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
                    action()
                self.assertEqual(caught.exception.reason.value, "OWNER_MISMATCH")
                result[label] = caught.exception.reason.value
            observations.append(result)

        try:
            for _ in range(16):
                bounded_raw_thread(successor)
                if observations[-1]["ident_reused"]:
                    break
            result = observations[-1]
            self.assertTrue(result["ident_reused"], "actual raw-thread ID reuse was not demonstrated")
            self.assertTrue(result["distinct_native_id"])
            if sys.version_info[:2] == (3, 11):
                self.assertTrue(result["same_thread_object"], "cached 3.11 dummy-owner case was not demonstrated")
            self.assertFalse(context._closed)
            self.assertEqual(tuple(context._fds), held)
            for fd in held:
                self.fixture.real_fstat(fd)
            print("RAW_THREAD_LIFETIME_CONTROL", json.dumps({"attempts": len(observations), **result,
                  "owner_same_thread_reentry": True, "owner_fds_retained": len(held)}, sort_keys=True), flush=True)
        finally:
            context.__del__()
        self.assertFalse(self.fixture.fd_paths)

    def test_missing_namespace_is_not_created(self):
        self.fixture.namespace.rmdir()
        with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
            self.module.acquire_native_pmc_context()
        self.assertEqual(caught.exception.reason.value, "NAMESPACE_UNAVAILABLE")
        self.assertFalse(self.fixture.namespace.exists())
        self.assertFalse(self.fixture.fd_paths)
        self.assertIsNone(caught.exception.__context__)

    def test_mode_owner_and_user_symlink_refuse(self):
        self.fixture.namespace.chmod(0o755)
        with self.assertRaises(self.module.NativePmcContextUnavailable):
            self.module.acquire_native_pmc_context()
        self.assertFalse(self.fixture.fd_paths)
        self.fixture.namespace.chmod(0o700)
        self.fixture.owner_overrides[str(self.fixture.namespace)] = 999
        with self.assertRaises(self.module.NativePmcContextUnavailable):
            self.module.acquire_native_pmc_context()
        self.fixture.owner_overrides.clear()
        self.fixture.namespace.rmdir()
        self.fixture.namespace.symlink_to(self.fixture.namespace.parent)
        with self.assertRaises(self.module.NativePmcContextUnavailable):
            self.module.acquire_native_pmc_context()
        self.assertFalse(self.fixture.fd_paths)

    def test_native_principal_and_privilege_mismatch_refuse_before_open(self):
        for uid, euid, gid, egid in ((0, 0, 0, 0), (501, 502, 20, 20), (501, 501, 20, 21)):
            self.fixture.uid, self.fixture.euid, self.fixture.gid, self.fixture.egid = uid, euid, gid, egid
            with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
                self.module.acquire_native_pmc_context()
            self.assertEqual(caught.exception.reason.value, "PRINCIPAL_UNAVAILABLE")
            self.assertFalse(self.fixture.open_flags)

    def test_nonlocal_or_ignored_ownership_mount_refuses(self):
        for flags in (0, 0x1000 | 0x200000):
            self.fixture.mount_flags = flags
            with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
                self.module.acquire_native_pmc_context()
            self.assertEqual(caught.exception.reason.value, "LOCAL_FILESYSTEM_UNAVAILABLE")
            self.assertFalse(self.fixture.fd_paths)

    def test_boot_permission_malformed_and_changed_boot_refuse(self):
        self.fixture.boot_error = PermissionError("PRIVATE_NATIVE_MARKER")
        with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
            self.module.acquire_native_pmc_context()
        self.assertEqual(str(caught.exception), "BOOT_IDENTITY_UNAVAILABLE")
        self.assertIsNone(caught.exception.__context__)
        self.fixture.boot_error = None
        for boots in ([b"x" * 37], [b"0" * 36 + b"\x00"],
                      [b"12345678-1234-4234-8234-123456789abc\x00", b"22345678-1234-4234-8234-123456789abc\x00"]):
            self.fixture.boots, self.fixture.boot_reads = boots, 0
            with self.assertRaises(self.module.NativePmcContextUnavailable):
                self.module.acquire_native_pmc_context()
            self.assertFalse(self.fixture.fd_paths)

    def test_regressed_and_invalid_clock_refuse(self):
        for readings in ([200, 100], [-1, 100], [True, 200]):
            self.fixture.monotonic_values, self.fixture.monotonic_index = readings, 0
            with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
                self.module.acquire_native_pmc_context()
            self.assertEqual(caught.exception.reason.value, "CLOCK_UNAVAILABLE")
            self.assertFalse(self.fixture.fd_paths)

    def test_root_owned_system_symlinks_work_but_user_link_and_bad_rules_refuse(self):
        self.fixture.owner_overrides[str(self.fixture.root / "usr/share/zoneinfo")] = 501
        with self.assertRaises(self.module.NativePmcContextUnavailable):
            self.module.acquire_native_pmc_context()
        self.fixture.owner_overrides.clear()
        self.fixture.zone.write_bytes(b"TZif2_PRIVATE_INVALID")
        with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
            self.module.acquire_native_pmc_context()
        self.assertEqual(caught.exception.reason.value, "TIMEZONE_UNAVAILABLE")
        self.assertFalse(self.fixture.fd_paths)

    def test_ordinary_and_cancellation_failures_close_owned_fds(self):
        for error in (RuntimeError("PRIVATE_READ_MARKER"), KeyboardInterrupt("fixture cancel")):
            self.fixture.read_error = error
            expected = self.module.NativePmcContextUnavailable if isinstance(error, Exception) else KeyboardInterrupt
            with self.assertRaises(expected) as caught:
                self.module.acquire_native_pmc_context()
            if expected is KeyboardInterrupt:
                self.assertIs(caught.exception, error)
            self.assertFalse(self.fixture.fd_paths)

    def test_foreign_thread_cannot_enter_or_explicitly_close(self):
        context = self.module.acquire_native_pmc_context()
        held = tuple(context._fds)
        errors = []
        def foreign():
            for action in (context.__enter__, context.close):
                try:
                    action()
                except self.module.NativePmcContextUnavailable as error:
                    errors.append(error.reason.value)
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["OWNER_MISMATCH", "OWNER_MISMATCH"])
        self.assertFalse(context._closed)
        self.assertEqual(tuple(context._fds), held)
        for fd in held:
            self.fixture.real_fstat(fd)
        context.close()
        self.assertFalse(self.fixture.fd_paths)

    def test_final_validation_failure_and_cancellation_release_context_fds(self):
        for error in (RuntimeError("PRIVATE_FINAL_STAT"), KeyboardInterrupt("final cancellation")):
            self.fixture.boot_reads = 0
            self.fixture.final_stat_error = error
            expected = self.module.NativePmcContextUnavailable if isinstance(error, Exception) else KeyboardInterrupt
            with self.assertRaises(expected) as caught:
                self.module.acquire_native_pmc_context()
            self.assertFalse(self.fixture.fd_paths)
            if expected is KeyboardInterrupt:
                self.assertIs(caught.exception, error)
            else:
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("PRIVATE", str(caught.exception))

    def test_namespace_replacement_refuses_context_reentry(self):
        context = self.module.acquire_native_pmc_context()
        previous = self.fixture.namespace.with_name("old-coordinator")
        self.fixture.namespace.rename(previous)
        self.fixture.namespace.mkdir(mode=0o700)
        with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
            context.__enter__()
        self.assertEqual(caught.exception.reason.value, "NAMESPACE_UNAVAILABLE")
        self.assertIsNone(caught.exception.__context__)
        self.assertTrue(context._closed)
        self.assertFalse(self.fixture.fd_paths)
        context.close()
        self.assertFalse(self.fixture.fd_paths)

    def test_real_home_rename_reentry_is_static_and_expires_all_fds(self):
        context = self.module.acquire_native_pmc_context()
        held = tuple(context._fds)
        moved = self.fixture.home.with_name("moved-fixture-home")
        self.fixture.home.rename(moved)
        try:
            with self.assertRaises(self.module.NativePmcContextUnavailable) as caught:
                with context:
                    self.fail("missing namespace entered")
            self.assertEqual(str(caught.exception), "NAMESPACE_UNAVAILABLE")
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertFalse(hasattr(caught.exception, "filename"))
            self.assertTrue(context._closed)
            self.assertFalse(self.fixture.fd_paths)
            self.assertEqual(context._fds, [])
            for fd in held:
                with self.assertRaises(OSError):
                    self.fixture.real_fstat(fd)
            with self.assertRaises(self.module.NativePmcContextUnavailable) as closed:
                context.__enter__()
            self.assertEqual(closed.exception.reason.value, "CONTEXT_CLOSED")
            context.close()
        finally:
            context.__del__()
            moved.rename(self.fixture.home)

    def test_reentry_typed_ordinary_and_cancellation_failures_expire_context(self):
        errors = (self.module.NativePmcContextUnavailable(self.module.NativeContextReason.NAMESPACE_UNAVAILABLE),
                  PermissionError(13, "PRIVATE_ERROR", "fixture-principal"), KeyboardInterrupt("fixture cancellation"))
        for error in errors:
            self.fixture.final_stat_error = None
            self.fixture.boot_reads = 0
            context = self.module.acquire_native_pmc_context()
            self.fixture.final_stat_error = error
            expected = self.module.NativePmcContextUnavailable if isinstance(error, Exception) else KeyboardInterrupt
            with self.assertRaises(expected) as caught:
                context.__enter__()
            self.assertTrue(context._closed)
            self.assertFalse(self.fixture.fd_paths)
            if expected is KeyboardInterrupt:
                self.assertIs(caught.exception, error)
            else:
                self.assertEqual(str(caught.exception), "NAMESPACE_UNAVAILABLE")
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
            context.close()

    def test_captured_fstat_error_and_cancellation_expire_context(self):
        for error in (PermissionError(13, "PRIVATE_FSTAT", "fixture-principal"),
                      KeyboardInterrupt("fstat cancellation")):
            self.fixture.fstat_error = None
            context = self.module.acquire_native_pmc_context()
            held = tuple(context._fds)
            self.fixture.fstat_error = error
            expected = self.module.NativePmcContextUnavailable if isinstance(error, Exception) else KeyboardInterrupt
            with self.assertRaises(expected) as caught:
                context.__enter__()
            self.assertTrue(context._closed)
            self.assertEqual(context._fds, [])
            self.assertFalse(self.fixture.fd_paths)
            for fd in held:
                with self.assertRaises(OSError):
                    self.fixture.real_fstat(fd)
            if expected is KeyboardInterrupt:
                self.assertIs(caught.exception, error)
            else:
                self.assertEqual(str(caught.exception), "NAMESPACE_UNAVAILABLE")
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertFalse(hasattr(caught.exception, "filename"))
            with self.assertRaises(self.module.NativePmcContextUnavailable) as closed:
                context.__enter__()
            self.assertEqual(closed.exception.reason.value, "CONTEXT_CLOSED")
            context.close()

    def test_legitimate_body_exception_and_cancellation_propagate_with_cleanup(self):
        for error in (RuntimeError("body error"), KeyboardInterrupt("body cancellation")):
            context = self.module.acquire_native_pmc_context()
            self.assertIs(context._owner_thread, threading.current_thread())
            with self.assertRaises(type(error)) as caught:
                with context:
                    raise error
            self.assertIs(caught.exception, error)
            self.assertTrue(context._closed)
            self.assertFalse(self.fixture.fd_paths)
            context.close()

    def test_distinct_successor_recycled_ident_cannot_enter_or_close_owner_fds(self):
        acquired, owner_errors, successor_results, successor_errors = [], [], [], []

        def acquire_in_owner():
            try:
                context = self.module.acquire_native_pmc_context()
                acquired.append((context, threading.get_ident(), threading.get_native_id()))
            except BaseException as error:
                owner_errors.append(type(error).__name__)

        owner = threading.Thread(target=acquire_in_owner)
        owner.start()
        owner.join(3)
        self.assertFalse(owner.is_alive())
        self.assertEqual(owner_errors, [])
        self.assertEqual(len(acquired), 1)
        context, owner_ident, owner_native_id = acquired[0]
        self.assertIs(context._owner_thread, owner)
        held = tuple(context._fds)

        def use_in_successor():
            try:
                refusals = []
                for action in (context.__enter__, context.close):
                    try:
                        action()
                    except self.module.NativePmcContextUnavailable as error:
                        refusals.append(error.reason.value)
                    else:
                        raise AssertionError("successor accepted")
                successor_results.append((threading.get_ident() == owner_ident,
                                          threading.get_native_id() != owner_native_id, refusals))
            except BaseException as error:
                successor_errors.append(type(error).__name__)

        try:
            for _ in range(16):
                successor = threading.Thread(target=use_in_successor)
                self.assertIsNot(successor, owner)
                successor.start()
                successor.join(3)
                self.assertFalse(successor.is_alive())
                self.assertEqual(successor_errors, [])
                if successor_results[-1][0]:
                    break
            self.assertEqual(successor_results[-1], (True, True, ["OWNER_MISMATCH", "OWNER_MISMATCH"]),
                             "actual recycled-ident control was not demonstrated")
            self.assertFalse(context._closed)
            self.assertEqual(tuple(context._fds), held)
            for fd in held:
                self.fixture.real_fstat(fd)
        finally:
            # Owner has exited. Exercise the existing permitted close-only
            # finalizer cleanup, not a foreign-thread ownership exception.
            context.__del__()
        self.assertFalse(self.fixture.fd_paths)

    def test_real_fork_child_can_only_close_its_descriptor_copies(self):
        context = self.module.acquire_native_pmc_context()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            successful = False
            try:
                self.fixture.final_stat_error = AssertionError("child must not read namespace")
                self.fixture.read_error = AssertionError("child must not read rules")
                try:
                    context.__enter__()
                except self.module.NativePmcContextUnavailable as error:
                    if error.reason.value != "OWNER_MISMATCH":
                        raise
                else:
                    raise AssertionError("child entered context")
                context.close()
                successful = not self.fixture.fd_paths
                os.write(write_fd, b"1" if successful else b"0")
            finally:
                os._exit(0 if successful else 1)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 1), b"1")
            _, status = os.waitpid(child, 0)
            self.assertEqual(status, 0)
            self.assertTrue(self.fixture.fd_paths)
            with context:
                self.assertTrue(context._fds)
        finally:
            os.close(read_fd)
            context.close()
        self.assertFalse(self.fixture.fd_paths)
