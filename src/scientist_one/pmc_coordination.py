"""Private LOCAL_MAC context foundation, NOT a coordinator or authority.

No state, locks, provisioning, admission, network, signatures, or scientific
provenance are implemented. Future source-owned entrypoints must acquire fresh
native context internally, never authorize a caller-supplied context object.
Historical projection is pure and does not authenticate its supplied rule bytes.
"""
from dataclasses import dataclass
import ctypes
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import io
import os
import pwd
import re
import stat
import struct
import sys
import threading
import time
from zoneinfo import ZoneInfo


class NativeContextReason(str, Enum):
    PLATFORM_UNAVAILABLE = "PLATFORM_UNAVAILABLE"
    PRINCIPAL_UNAVAILABLE = "PRINCIPAL_UNAVAILABLE"
    NAMESPACE_UNAVAILABLE = "NAMESPACE_UNAVAILABLE"
    LOCAL_FILESYSTEM_UNAVAILABLE = "LOCAL_FILESYSTEM_UNAVAILABLE"
    BOOT_IDENTITY_UNAVAILABLE = "BOOT_IDENTITY_UNAVAILABLE"
    CLOCK_UNAVAILABLE = "CLOCK_UNAVAILABLE"
    TIMEZONE_UNAVAILABLE = "TIMEZONE_UNAVAILABLE"
    OWNER_MISMATCH = "OWNER_MISMATCH"
    CONTEXT_CLOSED = "CONTEXT_CLOSED"


class NativePmcContextUnavailable(RuntimeError):
    """Static native-context refusal; never includes account/path/kernel text."""
    def __init__(self, reason: NativeContextReason):
        if type(reason) is not NativeContextReason:
            raise TypeError("native context reason must be closed")
        self.reason = reason
        super().__init__(reason.value)


class PmcScheduleProjectionError(ValueError):
    """Static error for unverified supplied-rule projection."""


@dataclass(frozen=True)
class PmcScheduleProjection:
    """Data only: no claim that supplied TZif bytes are native New_York rules."""
    tzif_sha256: str
    utc_unix_ns: int
    local_year: int
    local_month: int
    local_day: int
    local_hour: int
    local_minute: int
    local_second: int
    local_nanosecond: int
    local_iso_weekday: int
    utc_offset_seconds: int
    fold: int
    weekday_0500_2100_window: bool
    schema_version: str = "pmc-oai-supplied-rule-projection/v1"
    rule_identity_status: str = "UNVERIFIED_SUPPLIED_TZIF_BYTES"


class _PmcSpacingProjectionError(ValueError):
    """Static input refusal for unverified post-cleanup timing projection."""


@dataclass(frozen=True)
class _PmcSpacingProjection:
    """Data-only timing projection; never an admission or reservation token."""

    earliest_ns: int
    wait_ns: int
    deadline_feasible: bool
    classification: str = "UNVERIFIED_SUPPLIED_TIMING_PROJECTION"


_PMC_SPACING_NS = 333_333_334
_PMC_MAX_NS = (1 << 63) - 1
_PMC_BOOT_UUID = re.compile(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def _pmc_spacing_error(message: str) -> _PmcSpacingProjectionError:
    return _PmcSpacingProjectionError(message)


def _pmc_exact_nonnegative_ns(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _PMC_MAX_NS:
        raise _pmc_spacing_error("PMC_NANOSECONDS_INVALID")
    return value


def _pmc_exact_boot_uuid(value: object) -> bytes:
    if (
        type(value) is not bytes
        or _PMC_BOOT_UUID.fullmatch(value) is None
        or value.replace(b"-", b"") == b"0" * 32
    ):
        raise _pmc_spacing_error("PMC_BOOT_UUID_INVALID")
    return value


def _pmc_floor_deadline_ns(deadline_seconds: float) -> int:
    """Floor a supplied float's exact value; never establish native clock trust.

    A future owner must bind this to its original gateway deadline and clock
    domain. This is not a new budget, an admission, or proof that clocks agree.
    Float multiplication before int() could round the deadline upward.
    """
    # This coarse finite bound also rejects NaN and infinities without invoking
    # caller conversions. The precise nanosecond bound is checked below.
    if type(deadline_seconds) is not float or not 0.0 <= deadline_seconds < 2**63:
        raise _PmcSpacingProjectionError("PMC_DEADLINE_SECONDS_INVALID")
    numerator, denominator = deadline_seconds.as_integer_ratio()
    deadline_ns = numerator * 1_000_000_000 // denominator
    if deadline_ns > _PMC_MAX_NS:
        raise _PmcSpacingProjectionError("PMC_DEADLINE_SECONDS_INVALID")
    return deadline_ns


def _project_pmc_post_cleanup_spacing(
    *,
    now_ns: int,
    cleanup_completed_ns: int,
    deadline_ns: int,
    current_boot_uuid: bytes,
    cleanup_boot_uuid: bytes,
) -> _PmcSpacingProjection:
    """Project supplied same-boot cleanup spacing without granting authority."""

    now = _pmc_exact_nonnegative_ns(now_ns)
    cleanup = _pmc_exact_nonnegative_ns(cleanup_completed_ns)
    deadline = _pmc_exact_nonnegative_ns(deadline_ns)
    current_boot = _pmc_exact_boot_uuid(current_boot_uuid)
    cleanup_boot = _pmc_exact_boot_uuid(cleanup_boot_uuid)
    if current_boot != cleanup_boot:
        raise _pmc_spacing_error("PMC_BOOT_UUID_MISMATCH")
    if now < cleanup:
        raise _pmc_spacing_error("PMC_TIME_ORDER_INVALID")
    if cleanup > _PMC_MAX_NS - _PMC_SPACING_NS:
        raise _pmc_spacing_error("PMC_CLEANUP_SPACING_OVERFLOW")
    earliest = max(now, cleanup + _PMC_SPACING_NS)
    return _PmcSpacingProjection(
        earliest_ns=earliest,
        wait_ns=earliest - now,
        deadline_feasible=earliest < deadline,
    )


class _PmcTraceProjectionError(ValueError):
    """Static refusal of a complete supplied operational trace."""


@dataclass(frozen=True, kw_only=True)
class _PmcCoordinationTraceProjection:
    """Conformance data only; even an unblocked result is not admission."""

    classification: str = "UNVERIFIED_SUPPLIED_COORDINATION_TRACE"
    committed_phase: str
    last_sequence: int
    pending_sequence: int | None
    last_cleanup_ns: int | None
    last_observed_ns: int
    uncertain_commit: str | None
    continuation_blocked: bool


_PMC_TRACE_SCHEMA = "pmc-supplied-coordination-trace/v1"
_PMC_TRACE_ANCHOR_KEYS = frozenset({
    "schema", "coordinator_uuid", "boot_uuid", "initialized_ns", "initial_sequence",
})
_PMC_TRACE_COMMON_KEYS = frozenset({
    "kind", "coordinator_uuid", "boot_uuid", "sequence", "request_id",
    "prepared_claim_sha256", "policy_claim_sha256", "attempt_number", "observed_ns",
})
_PMC_TRACE_BINDING_KEYS = (
    "coordinator_uuid", "boot_uuid", "sequence", "request_id",
    "prepared_claim_sha256", "policy_claim_sha256", "attempt_number",
)
_PMC_TRACE_KINDS = frozenset({
    "PENDING", "NOT_SENT", "LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED",
})
_PMC_TRACE_HASH = re.compile(r"[0-9a-f]{64}")


def _pmc_trace_keys(value, expected):
    # Check exact container/key types before looking up fields or forming sets.
    if (type(value) is not dict or len(value) != len(expected)
            or any(type(key) is not str or len(key) > 32 for key in value)
            or set(value) != expected):
        raise _PmcTraceProjectionError("PMC_TRACE_SHAPE_INVALID")


def _pmc_trace_ns(value, *, positive=False):
    if type(value) is not int or not (1 if positive else 0) <= value <= _PMC_MAX_NS:
        raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
    return value


def _pmc_trace_uuid(value):
    if type(value) is not bytes or len(value) != 36:
        raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
    try:
        return _pmc_exact_boot_uuid(value)
    except _PmcSpacingProjectionError:
        raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID") from None


def _project_pmc_coordination_trace(anchor, records, *, uncertain_commit=None):
    """Validate an entire bounded declared trace, never actual state or cleanup.

    No I/O, persistence, clocks, locks, provisioning or dispatch is performed.
    Supplied bindings and commit/cleanup declarations are unverified even when
    structurally consistent. A changed uncertainty argument is not recovery.
    """
    _pmc_trace_keys(anchor, _PMC_TRACE_ANCHOR_KEYS)
    schema = anchor["schema"]
    if type(schema) is not str or len(schema) != len(_PMC_TRACE_SCHEMA) or schema != _PMC_TRACE_SCHEMA:
        raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
    coordinator = _pmc_trace_uuid(anchor["coordinator_uuid"])
    boot = _pmc_trace_uuid(anchor["boot_uuid"])
    last_observed = _pmc_trace_ns(anchor["initialized_ns"])
    if type(anchor["initial_sequence"]) is not int or anchor["initial_sequence"] != 0:
        raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
    if type(records) is not tuple or len(records) > 256:
        raise _PmcTraceProjectionError("PMC_TRACE_SHAPE_INVALID")
    if uncertain_commit is not None and (
        type(uncertain_commit) is not str or len(uncertain_commit) > 8
        or uncertain_commit not in {"PENDING", "TERMINAL"}
    ):
        raise _PmcTraceProjectionError("PMC_TRACE_UNCERTAINTY_INVALID")

    last_sequence = 0
    pending_bindings = None
    pending_observed = None
    last_cleanup = None
    for record in records:
        if (type(record) is not dict or len(record) not in (9, 10)
                or any(type(key) is not str or len(key) > 32 for key in record)):
            raise _PmcTraceProjectionError("PMC_TRACE_SHAPE_INVALID")
        kind = record.get("kind")
        if type(kind) is not str or len(kind) > 32 or kind not in _PMC_TRACE_KINDS:
            raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
        additional = (
            {"deadline_seconds"} if kind == "PENDING"
            else set() if kind == "NOT_SENT" else {"cleanup_ns"}
        )
        _pmc_trace_keys(record, _PMC_TRACE_COMMON_KEYS | additional)
        if (_pmc_trace_uuid(record["coordinator_uuid"]) != coordinator
                or _pmc_trace_uuid(record["boot_uuid"]) != boot):
            raise _PmcTraceProjectionError("PMC_TRACE_IDENTITY_MISMATCH")
        sequence = _pmc_trace_ns(record["sequence"], positive=True)
        _pmc_trace_ns(record["attempt_number"], positive=True)
        observed = _pmc_trace_ns(record["observed_ns"])
        for key in ("request_id", "prepared_claim_sha256", "policy_claim_sha256"):
            value = record[key]
            if type(value) is not str or len(value) != 64 or _PMC_TRACE_HASH.fullmatch(value) is None:
                raise _PmcTraceProjectionError("PMC_TRACE_VALUE_INVALID")
        if observed < last_observed:
            raise _PmcTraceProjectionError("PMC_TRACE_TIME_INVALID")
        bindings = tuple(record[key] for key in _PMC_TRACE_BINDING_KEYS)
        if kind == "PENDING":
            if pending_bindings is not None or sequence != last_sequence + 1:
                raise _PmcTraceProjectionError("PMC_TRACE_TRANSITION_INVALID")
            try:
                deadline = _pmc_floor_deadline_ns(record["deadline_seconds"])
                if last_cleanup is None:
                    feasible = observed < deadline
                else:
                    timing = _project_pmc_post_cleanup_spacing(
                        now_ns=observed, cleanup_completed_ns=last_cleanup,
                        deadline_ns=deadline, current_boot_uuid=boot, cleanup_boot_uuid=boot,
                    )
                    feasible = timing.wait_ns == 0 and timing.deadline_feasible
            except _PmcSpacingProjectionError:
                raise _PmcTraceProjectionError("PMC_TRACE_TIME_INVALID") from None
            if not feasible:
                raise _PmcTraceProjectionError("PMC_TRACE_TIME_INVALID")
            pending_bindings, pending_observed = bindings, observed
            last_sequence = sequence
        else:
            if pending_bindings is None or bindings != pending_bindings:
                raise _PmcTraceProjectionError("PMC_TRACE_TRANSITION_INVALID")
            if kind != "NOT_SENT":
                cleanup = _pmc_trace_ns(record["cleanup_ns"])
                if not pending_observed <= cleanup <= observed:
                    raise _PmcTraceProjectionError("PMC_TRACE_TIME_INVALID")
                last_cleanup = cleanup
            pending_bindings, pending_observed = None, None
        last_observed = observed

    is_pending = pending_bindings is not None
    if ((uncertain_commit == "PENDING" and is_pending)
            or (uncertain_commit == "TERMINAL" and not is_pending)):
        raise _PmcTraceProjectionError("PMC_TRACE_UNCERTAINTY_INVALID")
    return _PmcCoordinationTraceProjection(
        committed_phase="PENDING" if is_pending else "QUIESCENT",
        last_sequence=last_sequence,
        pending_sequence=last_sequence if is_pending else None,
        last_cleanup_ns=last_cleanup,
        last_observed_ns=last_observed,
        uncertain_commit=uncertain_commit,
        continuation_blocked=is_pending or uncertain_commit is not None,
    )


# BEGIN PRIVATE PMC PERSISTENCE CANDIDATE
import fcntl as _pmc_fcntl  # noqa: E402 - isolated private insertion preserves prior bytes
import json as _pmc_json  # noqa: E402


class _PmcStoreUnavailable(RuntimeError):
    """Static operational refusal; no filesystem or supplied text escapes."""


class _PmcStoreDeadlineExpired(_PmcStoreUnavailable):
    """The original supplied deadline expired; not a fresh allowance."""


_PMC_STORE_LIMIT = 16 * 1024
_PMC_STORE_NAMES = frozenset({"coordinator.lock", "anchor.json", "state.json"})
_pmc_store_open, _pmc_store_close = os.open, os.close
_pmc_store_read, _pmc_store_write = os.read, os.write
_pmc_store_fsync, _pmc_store_replace = os.fsync, os.replace
_pmc_store_clock, _pmc_store_sleep = time.monotonic_ns, time.sleep
_pmc_store_flock = _pmc_fcntl.flock


def _pmc_store_fail():
    raise _PmcStoreUnavailable("PMC_STORE_INVALID")


def _pmc_store_cleanup(descriptors, *, primary=None):
    """Close detached ownership once, preserving primary failure/cancellation."""
    failure = primary
    for fd in descriptors:
        if fd is None:
            continue
        try:
            _pmc_store_close(fd)
        except BaseException as error:
            if failure is None:
                failure = (_PmcStoreUnavailable("PMC_STORE_CLOSE_FAILED")
                           if isinstance(error, Exception) else error)
            else:
                try:
                    BaseException.add_note(failure, "PMC_STORE_CLOSE_FAILED")
                except BaseException:
                    pass  # Optional diagnostics cannot mask the primary or skip cleanup.
    if primary is None and failure is not None:
        raise failure from None


def _pmc_store_sanitized(error):
    refused = _PmcStoreUnavailable("PMC_STORE_INVALID")
    try:
        if "PMC_STORE_CLOSE_FAILED" in getattr(error, "__notes__", ()):
            BaseException.add_note(refused, "PMC_STORE_CLOSE_FAILED")
    except BaseException:
        pass  # A diagnostic field is never required to construct a static refusal.
    return refused


def _pmc_store_json(value):
    return (_pmc_json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _pmc_store_encode(payload):
    value = _pmc_store_json({"payload": payload,
                             "sha256": hashlib.sha256(_pmc_store_json(payload)).hexdigest()})
    if len(value) > _PMC_STORE_LIMIT:
        _pmc_store_fail()
    return value


def _pmc_store_decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _pmc_store_fail()
            result[key] = value
        return result

    def constant(value):
        _pmc_store_fail()

    if type(raw) is not bytes or not 1 <= len(raw) <= _PMC_STORE_LIMIT:
        _pmc_store_fail()
    value = _pmc_json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    _pmc_trace_keys(value, {"payload", "sha256"})
    digest = value["sha256"]
    if (type(value["payload"]) is not dict or type(digest) is not str
            or len(digest) != 64 or _PMC_TRACE_HASH.fullmatch(digest) is None
            or hashlib.sha256(_pmc_store_json(value["payload"])).hexdigest() != digest
            or _pmc_store_json(value) != raw):
        _pmc_store_fail()
    return value["payload"]


def _pmc_store_identity(metadata):
    return [metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid]


def _pmc_store_record(record, *, decode):
    """Convert only a validated closed scalar record; never a native fact."""
    if type(record) is not dict or len(record) not in (9, 10):
        _pmc_store_fail()
    for key, value in record.items():
        if type(key) is not str or len(key) > 32 or type(value) not in (str, bytes, int, float):
            _pmc_store_fail()
    result = dict(record)
    for key in ("coordinator_uuid", "boot_uuid"):
        value = result.get(key)
        if decode:
            if type(value) is not str or len(value) != 36:
                _pmc_store_fail()
            result[key] = value.encode("ascii")
        else:
            result[key] = _pmc_trace_uuid(value).decode("ascii")
    if result.get("kind") == "PENDING":
        value = result.get("deadline_seconds")
        if decode:
            if type(value) is not str or not 1 <= len(value) <= 32:
                _pmc_store_fail()
            deadline = float.fromhex(value)
            if deadline.hex() != value:
                _pmc_store_fail()
            _pmc_floor_deadline_ns(deadline)
            result["deadline_seconds"] = deadline
        else:
            _pmc_floor_deadline_ns(value)
            result["deadline_seconds"] = value.hex()
    return result


def _pmc_store_anchor(payload, directory_identity, lock_identity, boot):
    _pmc_trace_keys(payload, {"schema", "trace_anchor", "directory_identity", "lock_identity"})
    if payload["schema"] != "pmc-operational-anchor/v1":
        _pmc_store_fail()
    for key, expected in (("directory_identity", directory_identity), ("lock_identity", lock_identity)):
        value = payload[key]
        if (type(value) is not list or len(value) != len(expected)
                or any(type(item) is not int or not 0 <= item <= _PMC_MAX_NS for item in value)
                or value != expected):
            _pmc_store_fail()
    anchor = payload["trace_anchor"]
    _pmc_trace_keys(anchor, _PMC_TRACE_ANCHOR_KEYS)
    result = dict(anchor)
    for key in ("coordinator_uuid", "boot_uuid"):
        if type(result[key]) is not str or len(result[key]) != 36:
            _pmc_store_fail()
        result[key] = result[key].encode("ascii")
    _project_pmc_coordination_trace(result, ())
    if result["boot_uuid"] != boot:
        _pmc_store_fail()
    return result


def _pmc_store_state(payload, anchor, anchor_sha256):
    _pmc_trace_keys(payload, {
        "schema", "anchor_sha256", "generation", "sequence", "phase", "predecessor",
        "pending", "terminal", "last_cleanup_ns", "last_observed_ns",
    })
    if (payload["schema"] != "pmc-operational-state/v1"
            or payload["anchor_sha256"] != anchor_sha256
            or type(payload["phase"]) is not str):
        _pmc_store_fail()
    sequence = _pmc_trace_ns(payload["sequence"])
    generation = _pmc_trace_ns(payload["generation"])
    observed = _pmc_trace_ns(payload["last_observed_ns"])
    cleanup = payload["last_cleanup_ns"]
    if cleanup is not None:
        _pmc_trace_ns(cleanup)
    if sequence == 0:
        if (generation != 0 or payload["phase"] != "QUIESCENT"
                or any(payload[key] is not None for key in ("predecessor", "pending", "terminal"))
                or cleanup is not None or observed != anchor["initialized_ns"]):
            _pmc_store_fail()
        return
    predecessor = payload["predecessor"]
    _pmc_trace_keys(predecessor, {"sequence", "cleanup_ns", "observed_ns"})
    if _pmc_trace_ns(predecessor["sequence"]) != sequence - 1:
        _pmc_store_fail()
    prior_time = _pmc_trace_ns(predecessor["observed_ns"])
    prior_cleanup = predecessor["cleanup_ns"]
    if prior_time < anchor["initialized_ns"]:
        _pmc_store_fail()
    if prior_cleanup is not None and not anchor["initialized_ns"] <= _pmc_trace_ns(prior_cleanup) <= prior_time:
        _pmc_store_fail()
    if sequence == 1 and (prior_time != anchor["initialized_ns"] or prior_cleanup is not None):
        _pmc_store_fail()
    pending = _pmc_store_record(payload["pending"], decode=True)
    if _pmc_trace_ns(pending.get("sequence"), positive=True) != sequence or pending.get("kind") != "PENDING":
        _pmc_store_fail()
    # Replay the retained pair as one local step, separately checking the real
    # retained predecessor sequence/floor. No discarded history is invented.
    local_anchor = dict(anchor, initialized_ns=prior_time)
    local_pending = dict(pending, sequence=1)
    terminal = payload["terminal"]
    records = (local_pending,)
    if terminal is not None:
        terminal = _pmc_store_record(terminal, decode=True)
        if _pmc_trace_ns(terminal.get("sequence"), positive=True) != sequence or terminal.get("kind") == "PENDING":
            _pmc_store_fail()
        records += (dict(terminal, sequence=1),)
    projection = _project_pmc_coordination_trace(local_anchor, records)
    if prior_cleanup is not None:
        timing = _project_pmc_post_cleanup_spacing(
            now_ns=pending["observed_ns"], cleanup_completed_ns=prior_cleanup,
            deadline_ns=_pmc_floor_deadline_ns(pending["deadline_seconds"]),
            current_boot_uuid=anchor["boot_uuid"], cleanup_boot_uuid=anchor["boot_uuid"],
        )
        if timing.wait_ns or not timing.deadline_feasible:
            _pmc_store_fail()
    expected_cleanup = (projection.last_cleanup_ns if projection.last_cleanup_ns is not None
                        else prior_cleanup)
    if (generation != 2 * sequence - (1 if terminal is None else 0)
            or payload["phase"] != projection.committed_phase
            or observed != projection.last_observed_ns or cleanup != expected_cleanup):
        _pmc_store_fail()


class _PmcCoordinationStore:
    """Private fixture-bound operational owner, NOT native admission/cleanup.

    No bootstrap, dispatch, signing, quota, history repair or public capability.
    Supplied descriptor/boot/deadline/cleanup must never authorize production I/O.
    """

    def __init__(self, directory_fd, *, boot_uuid, deadline_seconds):
        self._directory = self._lock = None
        self._entered = self._failed = False
        self._owned_pending = None
        self._post_pending_expired = False
        self._pid, self._thread = os.getpid(), threading.current_thread()
        try:
            if type(directory_fd) is not int or directory_fd < 0:
                _pmc_store_fail()
            self._boot = _pmc_trace_uuid(boot_uuid)
            self._deadline = deadline_seconds
            self._deadline_ns = _pmc_floor_deadline_ns(deadline_seconds)
            self._directory = os.dup(directory_fd)
            metadata = os.fstat(self._directory)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o7777 != 0o700):
                _pmc_store_fail()
            self._directory_identity = _pmc_store_identity(metadata)
            self._last_clock = None
        except BaseException as error:
            self._close_owned(primary=error)
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def _owner(self):
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise _PmcStoreUnavailable("PMC_STORE_OWNER_MISMATCH")
        if self._directory is None or self._failed:
            raise _PmcStoreUnavailable("PMC_STORE_CLOSED")

    def _now(self, *, admission=False):
        now = _pmc_exact_nonnegative_ns(_pmc_store_clock())
        if self._last_clock is not None and now < self._last_clock:
            _pmc_store_fail()
        self._last_clock = now
        if admission and now >= self._deadline_ns:
            raise _PmcStoreDeadlineExpired("PMC_STORE_DEADLINE_EXPIRED")
        return now

    def _file(self, name, *, lock=False):
        flags = (os.O_RDWR if lock else os.O_RDONLY) | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = _pmc_store_open(name, flags, dir_fd=self._directory)
        try:
            meta = os.fstat(fd)
            named = os.stat(name, dir_fd=self._directory, follow_symlinks=False)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                    or meta.st_mode & 0o7777 != 0o600 or meta.st_nlink != 1
                    or _pmc_store_identity(meta) != _pmc_store_identity(named)
                    or (meta.st_size != 0 if lock else not 1 <= meta.st_size <= _PMC_STORE_LIMIT)):
                _pmc_store_fail()
            return fd, meta
        except BaseException as error:
            closing, fd = fd, None
            _pmc_store_cleanup((closing,), primary=error)
            raise

    def _read(self, name, *, sync=False):
        fd, before = self._file(name)
        primary = None
        try:
            if sync:
                _pmc_store_fsync(fd)
            data = bytearray()
            while len(data) <= _PMC_STORE_LIMIT:
                part = _pmc_store_read(fd, min(4096, _PMC_STORE_LIMIT + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=self._directory, follow_symlinks=False)
            if (len(data) != before.st_size or len(data) > _PMC_STORE_LIMIT
                    or _pmc_store_identity(after) != _pmc_store_identity(before)
                    or _pmc_store_identity(named) != _pmc_store_identity(before)
                    or (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
                    != (before.st_size, before.st_mtime_ns, before.st_ctime_ns, 1)):
                _pmc_store_fail()
            raw = bytes(data)
            return raw, _pmc_store_decode(raw), _pmc_store_identity(after)
        except BaseException as error:
            primary = error
            raise
        finally:
            closing, fd = fd, None
            _pmc_store_cleanup((closing,), primary=primary)

    def _namespace(self, temporary=None, *, membership=True):
        if (_pmc_store_identity(os.fstat(self._directory)) != self._directory_identity
                or (membership and set(os.listdir(self._directory))
                    != (_PMC_STORE_NAMES | ({temporary} if temporary else set())))):
            _pmc_store_fail()
        if self._lock is not None:
            actual = os.fstat(self._lock)
            named = os.stat("coordinator.lock", dir_fd=self._directory, follow_symlinks=False)
            if (_pmc_store_identity(actual) != self._lock_identity
                    or _pmc_store_identity(named) != self._lock_identity
                    or actual.st_nlink != 1 or actual.st_size != 0):
                _pmc_store_fail()

    def _current(self, temporary=None):
        self._namespace(temporary)
        anchor_raw, _, anchor_identity = self._read("anchor.json")
        if anchor_raw != self._anchor_raw or anchor_identity != self._anchor_identity:
            _pmc_store_fail()
        raw, payload, identity = self._read("state.json")
        _pmc_store_state(payload, self._anchor, self._anchor_hash)
        if raw != self._raw or identity != self._state_identity:
            _pmc_store_fail()
        return payload

    def __enter__(self):
        self._owner()
        try:
            if self._entered:
                _pmc_store_fail()
            self._now(admission=True)
            self._namespace(membership=False)
            self._lock, metadata = self._file("coordinator.lock", lock=True)
            self._lock_identity = _pmc_store_identity(metadata)
            while True:
                self._now(admission=True)
                self._namespace(membership=False)
                try:
                    _pmc_store_flock(self._lock, _pmc_fcntl.LOCK_EX | _pmc_fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = self._deadline_ns - self._now(admission=True)
                    _pmc_store_sleep(min(0.01, remaining / 1_000_000_000))
            self._now(admission=True)
            self._namespace()
            self._anchor_raw, anchor_payload, self._anchor_identity = self._read("anchor.json")
            self._anchor = _pmc_store_anchor(
                anchor_payload, self._directory_identity, self._lock_identity, self._boot,
            )
            self._anchor_hash = hashlib.sha256(_pmc_store_json(anchor_payload)).hexdigest()
            self._raw, payload, self._state_identity = self._read("state.json", sync=True)
            _pmc_store_state(payload, self._anchor, self._anchor_hash)
            _pmc_store_fsync(self._directory)
            self._current()  # Source-owned exact fresh readback, not uncertainty flag.
            self._now(admission=True)
            if payload["phase"] == "PENDING":
                raise _PmcStoreUnavailable("PMC_STORE_PENDING")
            self._entered = True
            return self
        except BaseException as error:
            self._failed = True
            self._close_owned(primary=error)
            if isinstance(error, _PmcStoreUnavailable):
                raise
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def _ready(self):
        self._owner()
        if not self._entered:
            raise _PmcStoreUnavailable("PMC_STORE_CLOSED")

    def _commit(self, payload):
        self._current()
        _pmc_store_state(payload, self._anchor, self._anchor_hash)
        raw = _pmc_store_encode(payload)
        name = "state.pending." + os.urandom(16).hex()
        fd = None
        primary = None
        try:
            fd = _pmc_store_open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                                 | os.O_NOFOLLOW, 0o600, dir_fd=self._directory)
            offset = 0
            while offset < len(raw):
                count = _pmc_store_write(fd, raw[offset:])
                if type(count) is not int or not 0 < count <= len(raw) - offset:
                    _pmc_store_fail()
                offset += count
            _pmc_store_fsync(fd)
            closing, fd = fd, None
            _pmc_store_cleanup((closing,))
            self._current(temporary=name)
            # No caller or fixture hook is invoked between derivation and commit.
            _pmc_store_replace(name, "state.json", src_dir_fd=self._directory, dst_dir_fd=self._directory)
            _pmc_store_fsync(self._directory)
            self._namespace()
            actual, checked, identity = self._read("state.json")
            _pmc_store_state(checked, self._anchor, self._anchor_hash)
            if actual != raw:
                _pmc_store_fail()
            self._raw, self._state_identity = actual, identity
            self._current()
        except BaseException as error:
            primary = error
            self._failed = True
            raise
        finally:
            if fd is not None:
                closing, fd = fd, None
                _pmc_store_cleanup((closing,), primary=primary)

    def read_snapshot(self):
        self._ready()
        try:
            payload = self._current()
            self._now(admission=True)
            return payload  # Newly decoded, no live mutable state is returned.
        except BaseException as error:
            self._failed = True
            if isinstance(error, _PmcStoreUnavailable):
                raise
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def begin_pending(self, bindings):
        self._ready()
        try:
            _pmc_trace_keys(bindings, {
                "request_id", "prepared_claim_sha256", "policy_claim_sha256", "attempt_number",
            })
            for key in ("request_id", "prepared_claim_sha256", "policy_claim_sha256"):
                value = bindings[key]
                if type(value) is not str or len(value) != 64 or _PMC_TRACE_HASH.fullmatch(value) is None:
                    _pmc_store_fail()
            _pmc_trace_ns(bindings["attempt_number"], positive=True)
            old = self._current()
            if old["phase"] != "QUIESCENT" or self._owned_pending is not None:
                _pmc_store_fail()
            if old["generation"] > _PMC_MAX_NS - 2:
                _pmc_store_fail()  # Reserve representable pending AND terminal generations.
            now = self._now(admission=True)
            if now < old["last_observed_ns"]:
                _pmc_store_fail()
            cleanup = old["last_cleanup_ns"]
            if cleanup is not None:
                while True:
                    timing = _project_pmc_post_cleanup_spacing(
                        now_ns=now, cleanup_completed_ns=cleanup, deadline_ns=self._deadline_ns,
                        current_boot_uuid=self._boot, cleanup_boot_uuid=self._boot,
                    )
                    if not timing.deadline_feasible:
                        raise _PmcStoreDeadlineExpired("PMC_STORE_DEADLINE_EXPIRED")
                    if timing.wait_ns == 0:
                        break
                    _pmc_store_sleep(min(0.01, timing.wait_ns / 1_000_000_000))
                    now = self._now(admission=True)
                self._current()
                now = self._now(admission=True)
            record = dict(bindings, kind="PENDING", coordinator_uuid=self._anchor["coordinator_uuid"],
                          boot_uuid=self._boot, sequence=old["sequence"] + 1,
                          observed_ns=now, deadline_seconds=self._deadline)
            payload = dict(old, generation=old["generation"] + 1, sequence=record["sequence"],
                           phase="PENDING", predecessor={"sequence": old["sequence"],
                           "cleanup_ns": cleanup, "observed_ns": old["last_observed_ns"]},
                           pending=_pmc_store_record(record, decode=False), terminal=None,
                           last_observed_ns=now)
            self._commit(payload)
            self._owned_pending = record
            # A confirmed pending remains owned on expiry solely so this same
            # synthetic control flow can record NOT_SENT; restart cannot do so.
            self._now(admission=True)
            return dict(record)
        except BaseException as error:
            if not (isinstance(error, _PmcStoreDeadlineExpired) and self._owned_pending is not None):
                self._failed = True
            else:
                self._post_pending_expired = True
            if isinstance(error, _PmcStoreUnavailable):
                raise
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def commit_terminal(self, kind, *, cleanup_ns=None):
        self._ready()
        try:
            if (self._owned_pending is None or type(kind) is not str
                    or kind not in {"NOT_SENT", "LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED"}
                    or (self._post_pending_expired and kind != "NOT_SENT")):
                _pmc_store_fail()
            old = self._current()
            if old["phase"] != "PENDING" or old["pending"] != _pmc_store_record(self._owned_pending, decode=False):
                _pmc_store_fail()
            record = {key: value for key, value in self._owned_pending.items() if key != "deadline_seconds"}
            record.update(kind=kind, observed_ns=self._now())
            if kind == "NOT_SENT":
                if cleanup_ns is not None:
                    _pmc_store_fail()
            else:
                record["cleanup_ns"] = _pmc_trace_ns(cleanup_ns)
            payload = dict(old, generation=old["generation"] + 1, phase="QUIESCENT",
                           terminal=_pmc_store_record(record, decode=False),
                           last_cleanup_ns=(old["last_cleanup_ns"] if kind == "NOT_SENT" else cleanup_ns),
                           last_observed_ns=record["observed_ns"])
            self._commit(payload)
            self._owned_pending = None
            self._post_pending_expired = False
            return dict(record)
        except BaseException as error:
            self._failed = True
            if isinstance(error, _PmcStoreUnavailable):
                raise
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def confirm_current_transition(self, record):
        self._ready()
        try:
            # Caller data selects exact readback only, never state mutation.
            expected = _pmc_store_record(record, decode=False)
            payload = self._current()
            current = payload["terminal"] if payload["terminal"] is not None else payload["pending"]
            if expected != current:
                _pmc_store_fail()
            self._read("state.json", sync=True)
            _pmc_store_fsync(self._directory)
            self._current()
            return True
        except BaseException as error:
            self._failed = True
            if isinstance(error, _PmcStoreUnavailable):
                raise
            if isinstance(error, Exception):
                raise _pmc_store_sanitized(error) from None
            raise

    def _close_owned(self, *, primary=None):
        descriptors = (self._lock, self._directory)
        self._lock = self._directory = None
        self._entered = False
        _pmc_store_cleanup(descriptors, primary=primary)

    def close(self):
        if os.getpid() == self._pid and threading.current_thread() is not self._thread:
            raise _PmcStoreUnavailable("PMC_STORE_OWNER_MISMATCH")
        # Always close-only, including inherited child copies; never LOCK_UN.
        self._close_owned()

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.close()
        except BaseException:
            if exc_value is None:
                raise
            # Preserve primary accounting/cancellation; retain static cleanup
            # failure evidence without substituting OS text for that outcome.
            try:
                BaseException.add_note(exc_value, "PMC_STORE_CLOSE_FAILED")
            except BaseException:
                pass  # Preserve the actual body exception even if its notes are invalid.
        return False


# END PRIVATE PMC PERSISTENCE CANDIDATE


class _DarwinStatFs64(ctypes.Structure):
    # Installed Darwin SDK sys/mount.h __DARWIN_STRUCT_STATFS64, LP64.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64), ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64), ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64), ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32), ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32), ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16), ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024), ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _build_native_foundation():
    """Capture native primitives once; this builder is deleted after import."""
    exact_type, exact_int, exact_bytes, exact_str = type, int, bytes, str
    exact_len, exact_tuple, exact_min, exact_object = len, tuple, min, object
    exact_open, exact_close, exact_read = os.open, os.close, os.read
    exact_stat, exact_fstat, exact_readlink = os.stat, os.fstat, os.readlink
    exact_uid, exact_euid, exact_gid, exact_egid = os.getuid, os.geteuid, os.getgid, os.getegid
    exact_pid, exact_thread = os.getpid, threading.current_thread
    exact_passwd = pwd.getpwuid
    exact_monotonic, exact_wall = time.monotonic_ns, time.time_ns
    exact_isdir, exact_isreg, exact_islink = stat.S_ISDIR, stat.S_ISREG, stat.S_ISLNK
    exact_unpack = struct.unpack_from
    exact_sha256, exact_stream = hashlib.sha256, io.BytesIO
    exact_from_file = ZoneInfo.from_file
    exact_datetime, exact_delta, exact_utc = datetime, timedelta, timezone.utc
    exact_projection, exact_projection_error = PmcScheduleProjection, PmcScheduleProjectionError
    exact_unavailable, reason = NativePmcContextUnavailable, NativeContextReason
    exact_byref, exact_buffer, exact_size = ctypes.byref, ctypes.create_string_buffer, ctypes.c_size_t
    exact_fs_type = _DarwinStatFs64
    uuid_pattern = re.compile(rb"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\x00")
    max_tzif, max_transitions, max_types, max_chars = 65536, 4096, 256, 4096
    minimum_ns, maximum_ns = -(1 << 63), (1 << 63) - 1
    suffix = ("Library", "Application Support", "Scientist-Ultra", "pmc-oai-coordinator")
    zone_path = ("usr", "share", "zoneinfo", "America", "New_York")
    platform_ready = sys.platform == "darwin" and ctypes.sizeof(ctypes.c_void_p) == 8
    native_lifetime_storage = None
    try:
        # Native storage is tied to thread-state lifetime, not current_thread's
        # potentially cached _DummyThread. Never use the Python local fallback.
        from _thread import _local as exact_native_local
        native_lifetime_storage = exact_native_local()
    except Exception:
        platform_ready = False
    sysctl, fstatfs = None, None
    directory_flags, file_flags = 0, 0
    try:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        if platform_ready and ctypes.sizeof(exact_fs_type) == 2168:
            native_library = ctypes.CDLL(None, use_errno=True)
            sysctl = native_library.sysctlbyname
            sysctl.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                              ctypes.c_void_p, ctypes.c_size_t]
            sysctl.restype = ctypes.c_int
            # Explicit statfs64 ABI, not an ambiguous unversioned symbol/layout.
            fstatfs = native_library.fstatfs64
            fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(exact_fs_type)]
            fstatfs.restype = ctypes.c_int
    except (AttributeError, OSError):
        platform_ready = False

    def thread_lifetime():
        # An ordinary local attribute (no subclass/slots) is distinct for every
        # native thread-state lifetime. Context retention keeps the token alive.
        try:
            return native_lifetime_storage.pmc_lifetime
        except AttributeError:
            token = exact_object()
            native_lifetime_storage.pmc_lifetime = token
            return token

    def validate_tzif(raw):
        if exact_type(raw) is not exact_bytes or not 44 <= exact_len(raw) <= max_tzif:
            raise exact_projection_error("SCHEDULE_RULES_INVALID")

        def block(offset, width):
            if offset + 44 > exact_len(raw) or raw[offset:offset + 5] != b"TZif2":
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            if raw[offset + 5:offset + 20] != b"\x00" * 15:
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            ut_count, std_count, leap_count, transition_count, type_count, char_count = exact_unpack(
                ">6I", raw, offset + 20,
            )
            if (
                leap_count != 0 or transition_count > max_transitions
                or not 1 <= type_count <= max_types or not 1 <= char_count <= max_chars
                or ut_count not in (0, type_count) or std_count not in (0, type_count)
            ):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            cursor = offset + 44
            end = cursor + transition_count * (width + 1) + type_count * 6 + char_count + std_count + ut_count
            if end > exact_len(raw) or end > max_tzif:
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            transitions = exact_unpack(f">{transition_count}{'i' if width == 4 else 'q'}", raw, cursor)
            if any(left >= right for left, right in zip(transitions, transitions[1:])):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            cursor += transition_count * width
            indices = raw[cursor:cursor + transition_count]
            if any(index >= type_count for index in indices):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            cursor += transition_count
            abbreviations = []
            for _ in range(type_count):
                offset_seconds, is_dst, abbreviation = exact_unpack(">iBB", raw, cursor)
                if not -86400 < offset_seconds < 86400 or is_dst not in (0, 1) or abbreviation >= char_count:
                    raise exact_projection_error("SCHEDULE_RULES_INVALID")
                abbreviations.append(abbreviation)
                cursor += 6
            chars = raw[cursor:cursor + char_count]
            if chars[-1] != 0 or any(value != 0 and not 32 <= value <= 126 for value in chars):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            for index in abbreviations:
                stop = chars.find(b"\x00", index)
                if stop < 0 or not 1 <= stop - index <= 32:
                    raise exact_projection_error("SCHEDULE_RULES_INVALID")
            cursor += char_count
            std = raw[cursor:cursor + std_count]
            cursor += std_count
            ut = raw[cursor:cursor + ut_count]
            if any(value not in (0, 1) for value in std + ut):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            if any(value and (not std or not std[index]) for index, value in enumerate(ut)):
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            return end

        first_end = block(0, 4)
        second_end = block(first_end, 8)
        footer = raw[second_end:]
        if (
            not 2 <= exact_len(footer) <= 258 or not footer.startswith(b"\n") or not footer.endswith(b"\n")
            or any(not 32 <= value <= 126 for value in footer[1:-1])
        ):
            raise exact_projection_error("SCHEDULE_RULES_INVALID")

    def project_pmc_schedule(tzif_bytes, *, utc_unix_ns):
        """Project supplied rules only; neither rule identity nor admission is verified.

        Closed profile: TZif2, no leap table, <=64KiB, bounded counts, signed64
        Unix nanoseconds. Integer conversion preserves 05:00/21:00 boundaries.
        """
        if exact_type(utc_unix_ns) is not exact_int or not minimum_ns <= utc_unix_ns <= maximum_ns:
            raise exact_projection_error("SCHEDULE_INSTANT_INVALID")
        refused = False
        try:
            validate_tzif(tzif_bytes)
            zone = exact_from_file(exact_stream(tzif_bytes))
            seconds, nanoseconds = divmod(utc_unix_ns, 1_000_000_000)
            utc = exact_datetime(1970, 1, 1, tzinfo=exact_utc) + exact_delta(
                seconds=seconds, microseconds=nanoseconds // 1000,
            )
            local = utc.astimezone(zone)
            offset = local.utcoffset()
            offset_seconds = offset.days * 86400 + offset.seconds
            if offset.microseconds or not -86400 < offset_seconds < 86400:
                raise exact_projection_error("SCHEDULE_RULES_INVALID")
            result = exact_projection(
                tzif_sha256=exact_sha256(tzif_bytes).hexdigest(), utc_unix_ns=utc_unix_ns,
                local_year=local.year, local_month=local.month, local_day=local.day,
                local_hour=local.hour, local_minute=local.minute, local_second=local.second,
                local_nanosecond=nanoseconds, local_iso_weekday=local.isoweekday(),
                utc_offset_seconds=offset_seconds, fold=local.fold,
                weekday_0500_2100_window=local.isoweekday() <= 5 and 5 <= local.hour < 21,
            )
        except Exception:
            refused = True
        if refused:
            raise exact_projection_error("SCHEDULE_RULES_INVALID") from None
        return result

    def identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid)

    def private_directory(fd, owner, *, exact_private=False):
        metadata = exact_fstat(fd)
        mode = metadata.st_mode & 0o7777
        if (not exact_isdir(metadata.st_mode) or metadata.st_uid != owner
                or mode & 0o7022 or (exact_private and mode != 0o700)):
            raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE)
        return metadata

    def close_all(fds):
        interruption = None
        for fd in reversed(fds):
            try:
                exact_close(fd)
            except OSError:
                pass
            except BaseException as error:
                if interruption is None:
                    interruption = error
        fds.clear()
        if interruption is not None:
            raise interruption

    def components(path, *, absolute):
        if exact_type(path) is not exact_str or not path or exact_len(path) > 4096 or "\x00" in path:
            raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE)
        if absolute != path.startswith("/"):
            raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE)
        values = path.split("/")[1:] if absolute else path.split("/")
        if not values or exact_len(values) > 64 or any(value in ("", ".", "..") for value in values):
            raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE)
        return values

    def require_local(fd):
        value = exact_fs_type()
        if fstatfs(fd, exact_byref(value)) != 0 or not value.f_flags & 0x1000 or value.f_flags & 0x200000:
            raise exact_unavailable(reason.LOCAL_FILESYSTEM_UNAVAILABLE)

    def boot_session():
        size = exact_size(0)
        if sysctl(b"kern.bootsessionuuid", None, exact_byref(size), None, 0) != 0 or size.value != 37:
            raise exact_unavailable(reason.BOOT_IDENTITY_UNAVAILABLE)
        value = exact_buffer(37)
        if sysctl(b"kern.bootsessionuuid", value, exact_byref(size), None, 0) != 0 or size.value != 37:
            raise exact_unavailable(reason.BOOT_IDENTITY_UNAVAILABLE)
        raw = value.raw
        if uuid_pattern.fullmatch(raw) is None or raw[:-1].replace(b"-", b"") == b"0" * 32:
            raise exact_unavailable(reason.BOOT_IDENTITY_UNAVAILABLE)
        return raw[:-1].lower()

    def read_fixed_zone():
        fds, names = [], []
        try:
            root = exact_open("/", directory_flags)
            fds.append(root)
            private_directory(root, 0)
            parent, pending, links = root, list(zone_path), 0
            while pending:
                name = pending.pop(0)
                named = exact_stat(name, dir_fd=parent, follow_symlinks=False)
                if exact_islink(named.st_mode):
                    links += 1
                    if links > 8 or named.st_uid != 0:
                        raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                    target = exact_readlink(name, dir_fd=parent)
                    if identity(exact_stat(name, dir_fd=parent, follow_symlinks=False)) != identity(named):
                        raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                    names.append((parent, name, identity(named)))
                    is_absolute = target.startswith("/")
                    pending = components(target, absolute=is_absolute) + pending
                    if exact_len(pending) > 64:
                        raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                    if is_absolute:
                        parent = root
                    continue
                child = exact_open(name, directory_flags if pending else file_flags, dir_fd=parent)
                fds.append(child)
                actual = exact_fstat(child)
                if identity(actual) != identity(named):
                    raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                names.append((parent, name, identity(actual)))
                if pending:
                    private_directory(child, 0)
                    parent = child
                    continue
                if (not exact_isreg(actual.st_mode) or actual.st_uid != 0 or actual.st_mode & 0o7022
                        or actual.st_nlink != 1 or not 44 <= actual.st_size <= max_tzif):
                    raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                require_local(child)
                data = bytearray()
                while exact_len(data) <= max_tzif:
                    part = exact_read(child, exact_min(4096, max_tzif + 1 - exact_len(data)))
                    if not part:
                        break
                    data.extend(part)
                after = exact_fstat(child)
                if (identity(after) != identity(actual) or after.st_size != actual.st_size
                        or after.st_mtime_ns != actual.st_mtime_ns or after.st_ctime_ns != actual.st_ctime_ns
                        or exact_len(data) != actual.st_size):
                    raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                for parent_fd, component, expected in names:
                    if identity(exact_stat(component, dir_fd=parent_fd, follow_symlinks=False)) != expected:
                        raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
                return exact_bytes(data)
            raise exact_unavailable(reason.TIMEZONE_UNAVAILABLE)
        finally:
            close_all(fds)

    class _NativePmcContext:
        """Private descriptive observation. Exact type/construction is not authority."""
        __slots__ = ("_fds", "_namespace_chain", "_principal", "_native_home", "_boot_session_uuid",
                     "_monotonic_interval_ns", "_wall_unix_ns", "_tzif_bytes", "_tzif_sha256",
                     "_owner_pid", "_owner_thread", "_owner_lifetime", "_closed")

        def __init__(self, fds, chain, uid, home, boot, clocks, wall, tzif, pid, thread, lifetime):
            self._fds, self._namespace_chain = fds, exact_tuple(chain)
            self._principal, self._native_home, self._boot_session_uuid = uid, home, boot
            self._monotonic_interval_ns, self._wall_unix_ns = clocks, wall
            self._tzif_bytes, self._tzif_sha256 = tzif, exact_sha256(tzif).hexdigest()
            self._owner_pid, self._owner_thread, self._closed = pid, thread, False
            self._owner_lifetime = lifetime

        def __repr__(self):
            return "<_NativePmcContext closed>" if self._closed else "<_NativePmcContext open; no authority>"

        def __reduce_ex__(self, protocol):
            raise TypeError("native context is not serializable")

        def _assert_owner(self):
            if self._closed:
                raise exact_unavailable(reason.CONTEXT_CLOSED)
            if exact_pid() != self._owner_pid or exact_thread() is not self._owner_thread or exact_euid() != self._principal:
                raise exact_unavailable(reason.OWNER_MISMATCH)
            if thread_lifetime() is not self._owner_lifetime:
                raise exact_unavailable(reason.OWNER_MISMATCH)

        def __enter__(self):
            # Foreign callers may neither inspect nor expire the owner's FDs.
            self._assert_owner()
            validated = False
            try:
                for parent, component, fd, expected in self._namespace_chain:
                    if identity(exact_fstat(fd)) != expected or identity(exact_stat(component, dir_fd=parent, follow_symlinks=False)) != expected:
                        raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE)
                validated = True
            except Exception:
                pass
            finally:
                if not validated:
                    self._closed = True
                    close_all(self._fds)
            if not validated:
                raise exact_unavailable(reason.NAMESPACE_UNAVAILABLE) from None
            return self

        def close(self):
            if self._closed:
                return
            # A fork child only closes inherited descriptor copies. No reads or
            # unlock/shutdown operation is performed in that branch.
            if exact_pid() == self._owner_pid:
                self._assert_owner()
            self._closed = True
            close_all(self._fds)

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()
            return False

        def __del__(self):
            # Close-only last-reference cleanup, also safe for child copies.
            # Explicit use/close by a foreign thread remains refused above.
            try:
                close_all(self._fds)
            except BaseException:
                pass

    def acquire_native_pmc_context():
        """Require existing fixed native LOCAL_MAC paths; never provision or admit."""
        fds, chain, context = [], [], None
        completed = False
        failure = None
        stage = reason.PLATFORM_UNAVAILABLE
        try:
            if not platform_ready or sysctl is None or fstatfs is None or native_lifetime_storage is None:
                raise exact_unavailable(stage)
            lifetime = thread_lifetime()
            stage = reason.PRINCIPAL_UNAVAILABLE
            uid, gid = exact_euid(), exact_egid()
            pid, thread = exact_pid(), exact_thread()
            if (exact_type(uid) is not exact_int or uid <= 0 or exact_type(gid) is not exact_int or gid <= 0
                    or uid != exact_uid() or gid != exact_gid()):
                raise exact_unavailable(stage)
            account = exact_passwd(uid)
            if account.pw_uid != uid:
                raise exact_unavailable(stage)
            home = account.pw_dir
            home_parts = components(home, absolute=True)
            stage = reason.NAMESPACE_UNAVAILABLE
            root = exact_open("/", directory_flags)
            fds.append(root)
            private_directory(root, 0)
            parent = root
            for index, component in enumerate(home_parts + list(suffix)):
                child = exact_open(component, directory_flags, dir_fd=parent)
                fds.append(child)
                at_home = index >= exact_len(home_parts) - 1
                private = index >= exact_len(home_parts) + 2
                actual = private_directory(child, uid if at_home else 0, exact_private=private)
                if identity(exact_stat(component, dir_fd=parent, follow_symlinks=False)) != identity(actual):
                    raise exact_unavailable(stage)
                chain.append((parent, component, child, identity(actual)))
                parent = child
            require_local(parent)
            stage = reason.BOOT_IDENTITY_UNAVAILABLE
            boot = boot_session()
            stage = reason.CLOCK_UNAVAILABLE
            before, wall, after = exact_monotonic(), exact_wall(), exact_monotonic()
            if (any(exact_type(value) is not exact_int or not 0 <= value <= maximum_ns for value in (before, wall, after))
                    or before > after):
                raise exact_unavailable(stage)
            stage = reason.TIMEZONE_UNAVAILABLE
            tzif = read_fixed_zone()
            project_pmc_schedule(tzif, utc_unix_ns=wall)
            stage = reason.BOOT_IDENTITY_UNAVAILABLE
            if boot_session() != boot:
                raise exact_unavailable(stage)
            stage = reason.PRINCIPAL_UNAVAILABLE
            if exact_euid() != uid or exact_uid() != uid or exact_egid() != gid or exact_gid() != gid or exact_pid() != pid or exact_thread() is not thread:
                raise exact_unavailable(stage)
            if thread_lifetime() is not lifetime:
                raise exact_unavailable(stage)
            context = _NativePmcContext(fds, chain, uid, home, boot, (before, after), wall, tzif, pid, thread, lifetime)
            context.__enter__()
            completed = True
        except exact_unavailable as error:
            failure = error.reason
        except Exception:
            failure = stage
        finally:
            if not completed:
                close_all(fds)
        if failure is not None:
            raise exact_unavailable(failure) from None
        return context

    return acquire_native_pmc_context, project_pmc_schedule, _NativePmcContext


acquire_native_pmc_context, project_pmc_schedule, _NativePmcContext = _build_native_foundation()
del _build_native_foundation

__all__ = ["acquire_native_pmc_context", "project_pmc_schedule", "NativePmcContextUnavailable",
           "NativeContextReason", "PmcScheduleProjection", "PmcScheduleProjectionError"]


# BEGIN PRIVATE PMC ATTEMPT ADAPTER
def _build_pmc_attempt_native_owner():
    """Capture existing boundaries; no dependency arguments or lifetime changes."""
    acquire, context_type = acquire_native_pmc_context, _NativePmcContext
    enter_context, close_context = context_type.__enter__, context_type.close
    slots = {name: context_type.__dict__[name].__get__ for name in
             ("_fds", "_namespace_chain", "_principal", "_native_home", "_boot_session_uuid",
              "_tzif_bytes", "_wall_unix_ns", "_monotonic_interval_ns")}
    store_type = _PmcCoordinationStore
    enter_store, close_store = store_type.__enter__, store_type.close
    begin, confirm, terminal = (store_type.begin_pending, store_type.confirm_current_transition,
                                store_type.commit_terminal)
    project, clock = project_pmc_schedule, _pmc_store_clock

    def refuse():
        raise _PmcStoreUnavailable("PMC_ATTEMPT_NATIVE_REFUSED")

    def observation(context):
        if type(context) is not context_type:
            refuse()
        enter_context(context)
        values = {name: getter(context) for name, getter in slots.items()}
        chain, fds = values["_namespace_chain"], values["_fds"]
        if (type(chain) is not tuple or not chain or type(fds) is not list or not fds
                or type(fds[-1]) is not int or fds[-1] < 0
                or type(values["_principal"]) is not int or type(values["_native_home"]) is not str):
            refuse()
        components = []
        for item in chain:
            if (type(item) is not tuple or len(item) != 4 or type(item[1]) is not str
                    or type(item[3]) is not tuple or len(item[3]) != 5
                    or any(type(value) is not int for value in item[3])):
                refuse()
            components.append((item[1], item[3]))
        if chain[-1][2] != fds[-1]:
            refuse()
        boot = _pmc_trace_uuid(values["_boot_session_uuid"])
        identity = (values["_principal"], values["_native_home"], boot, tuple(components))
        return identity, fds[-1], values["_tzif_bytes"], values["_wall_unix_ns"], values["_monotonic_interval_ns"]

    class _PmcAttemptNativeOwner:
        """Driver-private acquisition/store scope; never supplied-context authority."""

        def __init__(self, deadline_seconds):
            self._deadline = deadline_seconds
            self._context = self._store = self._identity = None
            self._opened = self._closed = False

        def open(self):
            if self._opened or self._closed:
                refuse()
            self._opened = True
            context = acquire()
            if type(context) is not context_type:
                refuse()
            self._context = context
            self._identity, directory, _, _, _ = observation(context)
            self._store = store_type(directory, boot_uuid=self._identity[2], deadline_seconds=self._deadline)
            enter_store(self._store)

        def schedule(self):
            if self._closed or self._context is None or self._store is None:
                refuse()
            fresh, primary = None, None
            try:
                retained, _, _, _, _ = observation(self._context)
                if retained != self._identity:
                    refuse()
                candidate = acquire()
                if type(candidate) is not context_type:
                    refuse()
                fresh = candidate
                identity, _, tzif, wall, interval = observation(fresh)
                if identity != self._identity or observation(self._context)[0] != self._identity:
                    refuse()
                projected = project(tzif, utc_unix_ns=wall)
                if type(projected.weekday_0500_2100_window) is not bool or projected.weekday_0500_2100_window:
                    refuse()
                if (type(tzif) is not bytes or type(wall) is not int or type(interval) is not tuple
                        or len(interval) != 2 or any(type(v) is not int or not 0 <= v <= _PMC_MAX_NS for v in interval)
                        or interval[0] > interval[1]):
                    refuse()
            except BaseException as error:
                primary = error
            if fresh is not None:
                try:
                    close_context(fresh)
                except BaseException as error:
                    if primary is None:
                        primary = error
            if primary is not None:
                raise primary
            return (tzif, wall, interval[0], interval[1])

        def begin_pending(self, bindings):
            return begin(self._store, bindings)

        def confirm(self, record):
            return confirm(self._store, record)

        def terminal(self, kind):
            cleanup = None if kind == "NOT_SENT" else _pmc_exact_nonnegative_ns(clock())
            return terminal(self._store, kind, cleanup_ns=cleanup)

        def close(self):
            if self._closed:
                return
            self._closed = True
            store, context = self._store, self._context
            self._store = self._context = None
            primary = None
            for owned, close in ((store, close_store), (context, close_context)):
                if owned is not None:
                    try:
                        close(owned)
                    except BaseException as error:
                        if primary is None:
                            primary = error
            if primary is not None:
                raise primary

    return _PmcAttemptNativeOwner


_PmcAttemptNativeOwner = _build_pmc_attempt_native_owner()
del _build_pmc_attempt_native_owner
# END PRIVATE PMC ATTEMPT ADAPTER
