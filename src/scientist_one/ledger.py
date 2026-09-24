"""Append-only, hash-chained JSONL evidence ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterable, Mapping
import uuid

try:  # Scientist-One's primary platform is macOS/POSIX.
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported platforms
    fcntl = None  # type: ignore[assignment]

from .errors import LedgerCorruptionError, LedgerError, PathSecurityError, ValidationError
from .models import (
    State,
    evaluation_to_dict,
    freeze_json,
    parse_state,
    thaw_json,
    utc_now,
    validate_identifier,
    validate_sha256,
)
from .roles import Role
from .security import (
    PathPolicy,
    atomic_write_bytes,
    canonical_json_bytes,
    open_confined_directory_fd,
    safe_json_loads,
    secure_directory,
    sha256_bytes,
)


EVENT_TYPES = frozenset(
    {
        "TRANSITION",
        "CORRECTION",
        "CHECKPOINT",
        "APPROVAL_REQUESTED",
        "CONFIRMATORY_STARTED",
        "CONFIRMATORY_COMPLETED",
        "RECOVERY",
        "SECURITY_STOP",
    }
)
EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# A ledger is control-plane metadata, not an artifact payload.  Give it a
# generous but explicit process-memory and event-count budget so corrupted or
# adversarial local evidence cannot make verify/resume/package materialize an
# unbounded file.  Individual event JSON remains subject to the shared JSON
# parser's independent eight-MiB bound.
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_LEDGER_EVENTS = 10_000


def event_hash(event: Mapping[str, Any]) -> str:
    """Hash the canonical event body, including prior hash, excluding itself."""

    if not isinstance(event, Mapping):
        raise ValidationError("ledger event must be an object")
    return sha256_bytes(canonical_json_bytes({key: value for key, value in event.items() if key != "event_hash"}))


@dataclass(frozen=True)
class LedgerEvent:
    run_id: str
    event_id: str
    timestamp: str
    actor_role: Role
    state_before: State
    requested_state_after: State
    artifact_hashes: tuple[str, ...]
    code_version: str
    configuration_hash: str
    dataset_identifiers: tuple[str, ...]
    random_seeds: tuple[int, ...]
    evaluator_outputs: tuple[Mapping[str, Any], ...]
    reason: str
    prior_event_hash: str | None
    event_type: str = "TRANSITION"
    supersedes_event_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    event_hash: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "run ID")
        validate_identifier(self.event_id, "event ID")
        if not isinstance(self.timestamp, str) or not self.timestamp.endswith("Z"):
            raise ValidationError("event timestamp must be UTC ISO-8601 with Z suffix")
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("event timestamp is malformed") from exc
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ValidationError("event timestamp must be UTC")
        if not isinstance(self.actor_role, Role):
            raise ValidationError("event actor role must be a Role")
        object.__setattr__(self, "state_before", parse_state(self.state_before))
        object.__setattr__(self, "requested_state_after", parse_state(self.requested_state_after))
        if not isinstance(self.artifact_hashes, tuple):
            raise ValidationError("artifact hashes must be a tuple")
        for digest in self.artifact_hashes:
            validate_sha256(digest, "artifact SHA-256")
        if len(set(self.artifact_hashes)) != len(self.artifact_hashes):
            raise ValidationError("artifact hashes must be unique")
        if not isinstance(self.code_version, str) or not self.code_version.strip() or len(self.code_version) > 512:
            raise ValidationError("code version or working-tree fingerprint is required")
        validate_sha256(self.configuration_hash, "configuration SHA-256")
        if not isinstance(self.dataset_identifiers, tuple) or any(
            not isinstance(item, str) or not item or len(item) > 512 for item in self.dataset_identifiers
        ):
            raise ValidationError("dataset identifiers must be bounded strings")
        if not isinstance(self.random_seeds, tuple) or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in self.random_seeds
        ):
            raise ValidationError("random seeds must be non-negative integers")
        if not isinstance(self.evaluator_outputs, tuple) or any(
            not isinstance(item, Mapping) for item in self.evaluator_outputs
        ):
            raise ValidationError("evaluator outputs must be an object tuple")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > 8192:
            raise ValidationError("event reason must be non-empty bounded text")
        if self.prior_event_hash is not None:
            validate_sha256(self.prior_event_hash, "prior event SHA-256")
        if (
            not isinstance(self.event_type, str)
            or not EVENT_TYPE_RE.fullmatch(self.event_type)
            or self.event_type not in EVENT_TYPES
        ):
            raise ValidationError("invalid event type")
        if self.supersedes_event_id is not None:
            validate_identifier(self.supersedes_event_id, "superseded event ID")
        if self.event_type == "CORRECTION" and self.supersedes_event_id is None:
            raise ValidationError("correction events must reference a superseded event")
        if self.event_type != "CORRECTION" and self.supersedes_event_id is not None:
            raise ValidationError("only correction events may supersede another event")
        if self.supersedes_event_id == self.event_id:
            raise ValidationError("an event cannot supersede itself")
        if not isinstance(self.metadata, Mapping):
            raise ValidationError("event metadata must be an object")
        object.__setattr__(
            self,
            "evaluator_outputs",
            tuple(freeze_json(item) for item in self.evaluator_outputs),
        )
        object.__setattr__(self, "metadata", freeze_json(self.metadata))
        # Canonicalization is also a JSON-safety and finite-number check.
        computed = event_hash(self.to_dict(include_hash=False))
        if self.event_hash is None:
            object.__setattr__(self, "event_hash", computed)
        else:
            validate_sha256(self.event_hash, "event SHA-256")
            if self.event_hash != computed:
                raise LedgerCorruptionError("event hash does not match canonical event body")

    @property
    def state_after(self) -> State:
        return self.requested_state_after

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "run_id": self.run_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor_role": self.actor_role.value,
            "state_before": self.state_before.value,
            "requested_state_after": self.requested_state_after.value,
            "artifact_hashes": list(self.artifact_hashes),
            "code_version": self.code_version,
            "configuration_hash": self.configuration_hash,
            "dataset_identifiers": list(self.dataset_identifiers),
            "random_seeds": list(self.random_seeds),
            "evaluator_outputs": [thaw_json(item) for item in self.evaluator_outputs],
            "reason": self.reason,
            "prior_event_hash": self.prior_event_hash,
            "event_type": self.event_type,
            "supersedes_event_id": self.supersedes_event_id,
            "metadata": thaw_json(self.metadata),
        }
        if include_hash:
            value["event_hash"] = self.event_hash
        return value

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        actor_role: Role,
        state_before: State,
        requested_state_after: State,
        artifact_hashes: Iterable[str],
        code_version: str,
        configuration_hash: str,
        dataset_identifiers: Iterable[str] = (),
        random_seeds: Iterable[int] = (),
        evaluator_outputs: Iterable[Any] = (),
        reason: str,
        prior_event_hash: str | None,
        event_id: str | None = None,
        timestamp: str | None = None,
        event_type: str = "TRANSITION",
        supersedes_event_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "LedgerEvent":
        output_records = tuple(
            evaluation_to_dict(item) if hasattr(item, "evaluator_class") else dict(item)
            for item in evaluator_outputs
        )
        return cls(
            run_id=run_id,
            event_id=event_id or f"evt-{uuid.uuid4().hex}",
            timestamp=timestamp or utc_now(),
            actor_role=actor_role,
            state_before=state_before,
            requested_state_after=requested_state_after,
            artifact_hashes=tuple(artifact_hashes),
            code_version=code_version,
            configuration_hash=configuration_hash,
            dataset_identifiers=tuple(dataset_identifiers),
            random_seeds=tuple(random_seeds),
            evaluator_outputs=output_records,
            reason=reason,
            prior_event_hash=prior_event_hash,
            event_type=event_type,
            supersedes_event_id=supersedes_event_id,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LedgerEvent":
        if not isinstance(value, Mapping):
            raise LedgerCorruptionError("ledger line must be a JSON object")
        required = {
            "run_id",
            "event_id",
            "timestamp",
            "actor_role",
            "state_before",
            "requested_state_after",
            "artifact_hashes",
            "code_version",
            "configuration_hash",
            "dataset_identifiers",
            "random_seeds",
            "evaluator_outputs",
            "reason",
            "prior_event_hash",
            "event_type",
            "supersedes_event_id",
            "metadata",
            "event_hash",
        }
        if set(value) != required:
            raise LedgerCorruptionError("ledger event schema is incomplete or has unknown fields")
        try:
            return cls(
                run_id=value["run_id"],
                event_id=value["event_id"],
                timestamp=value["timestamp"],
                actor_role=Role(value["actor_role"]),
                state_before=parse_state(value["state_before"]),
                requested_state_after=parse_state(value["requested_state_after"]),
                artifact_hashes=tuple(value["artifact_hashes"]),
                code_version=value["code_version"],
                configuration_hash=value["configuration_hash"],
                dataset_identifiers=tuple(value["dataset_identifiers"]),
                random_seeds=tuple(value["random_seeds"]),
                evaluator_outputs=tuple(value["evaluator_outputs"]),
                reason=value["reason"],
                prior_event_hash=value["prior_event_hash"],
                event_type=value["event_type"],
                supersedes_event_id=value["supersedes_event_id"],
                metadata=value["metadata"],
                event_hash=value["event_hash"],
            )
        except LedgerCorruptionError:
            raise
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise LedgerCorruptionError("malformed ledger event") from exc


@dataclass(frozen=True)
class LedgerValidationResult:
    valid: bool
    events: tuple[LedgerEvent, ...]
    head_hash: str | None
    error: str | None = None
    error_line: int | None = None
    recoverable_truncated_tail: bool = False
    valid_prefix_bytes: int = 0

    @property
    def event_count(self) -> int:
        return len(self.events)

    def __bool__(self) -> bool:
        return self.valid


@dataclass(frozen=True)
class _LedgerLock:
    root_fd: int
    namespace_fds: tuple[int, ...]
    parent_versions: tuple[tuple[int, int], ...]
    parent_change_times: tuple[int, ...]
    root_lock_fd: int
    root_lock_identity: tuple[int, int]
    ledger_lock_fd: int
    ledger_lock_identity: tuple[int, int]


class EventLedger:
    """A project-confined JSONL ledger with durable serialized appends."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        path: str | os.PathLike[str] = "state/events.jsonl",
    ) -> None:
        self.policy = PathPolicy(root)
        raw = Path(path)
        if raw.is_absolute():
            try:
                raw = raw.relative_to(self.policy.root)
            except ValueError as exc:
                raise LedgerError("ledger path is outside the project root") from exc
        if ".." in raw.parts or not raw.name.endswith(".jsonl"):
            raise LedgerError("ledger path must be a confined JSONL file")
        self.relative_path = raw
        self.path = self.policy.root / raw
        secure_directory(self.policy.root, raw.parent, create=True)
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        root_metadata = os.stat(self.policy.root, follow_symlinks=False)
        self._root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        parent_fd = open_confined_directory_fd(
            self.policy.root, self.relative_path.parent, create=False
        )
        try:
            parent_metadata = os.fstat(parent_fd)
            self._parent_identity = (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
            )
        finally:
            os.close(parent_fd)

    @staticmethod
    def _directory_version(metadata: os.stat_result) -> tuple[int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
        )

    @staticmethod
    def _ledger_parent_fd(guard: _LedgerLock) -> int:
        return guard.namespace_fds[-1] if guard.namespace_fds else guard.root_fd

    def _open_lock(self) -> _LedgerLock:
        if fcntl is None:
            raise LedgerError("safe ledger locking is unavailable on this platform")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        root_fd: int | None = None
        namespace_fds: list[int] = []
        root_lock_fd: int | None = None
        ledger_lock_fd: int | None = None
        root_locked = False
        ledger_locked = False
        try:
            root_fd = os.open(self.policy.root, directory_flags)
            root_metadata = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise LedgerError("ledger project root identity changed")

            lock_flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            root_lock_name = ".scientist-one-event-ledger.lock"
            root_lock_fd = os.open(root_lock_name, lock_flags, 0o600, dir_fd=root_fd)
            root_lock_metadata = os.fstat(root_lock_fd)
            root_lock_named = os.stat(
                root_lock_name, dir_fd=root_fd, follow_symlinks=False
            )
            root_lock_identity = (
                root_lock_metadata.st_dev,
                root_lock_metadata.st_ino,
            )
            if (
                not stat.S_ISREG(root_lock_metadata.st_mode)
                or root_lock_metadata.st_nlink != 1
                or (root_lock_metadata.st_mode & 0o077) != 0
                or root_lock_identity
                != (root_lock_named.st_dev, root_lock_named.st_ino)
            ):
                raise LedgerError("ledger namespace lock is not a private regular file")
            fcntl.flock(root_lock_fd, fcntl.LOCK_EX)
            root_locked = True
            root_lock_named = os.stat(
                root_lock_name, dir_fd=root_fd, follow_symlinks=False
            )
            if root_lock_identity != (
                root_lock_named.st_dev,
                root_lock_named.st_ino,
            ):
                raise LedgerError("ledger namespace lock identity changed")

            parent_versions: list[tuple[int, int]] = []
            parent_change_times: list[int] = []
            parent_fd = root_fd
            for component in self.relative_path.parent.parts:
                parent_metadata = os.fstat(parent_fd)
                parent_versions.append(self._directory_version(parent_metadata))
                parent_change_times.append(parent_metadata.st_ctime_ns)
                child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                child_metadata = os.fstat(child_fd)
                named_child = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(child_metadata.st_mode)
                    or (child_metadata.st_dev, child_metadata.st_ino)
                    != (named_child.st_dev, named_child.st_ino)
                ):
                    os.close(child_fd)
                    raise LedgerError("ledger parent namespace is unsafe")
                namespace_fds.append(child_fd)
                parent_fd = child_fd
            parent_metadata = os.fstat(parent_fd)
            if (parent_metadata.st_dev, parent_metadata.st_ino) != self._parent_identity:
                raise LedgerError("ledger parent namespace identity changed")

            ledger_lock_fd = os.open(
                self.lock_path.name,
                lock_flags,
                0o600,
                dir_fd=parent_fd,
            )
            lock_metadata = os.fstat(ledger_lock_fd)
            named_lock = os.stat(
                self.lock_path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            ledger_lock_identity = (lock_metadata.st_dev, lock_metadata.st_ino)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or (lock_metadata.st_mode & 0o077) != 0
                or ledger_lock_identity != (named_lock.st_dev, named_lock.st_ino)
            ):
                raise LedgerError("ledger lock is not a private regular file")
            fcntl.flock(ledger_lock_fd, fcntl.LOCK_EX)
            ledger_locked = True
            guard = _LedgerLock(
                root_fd=root_fd,
                namespace_fds=tuple(namespace_fds),
                parent_versions=tuple(parent_versions),
                parent_change_times=tuple(parent_change_times),
                root_lock_fd=root_lock_fd,
                root_lock_identity=root_lock_identity,
                ledger_lock_fd=ledger_lock_fd,
                ledger_lock_identity=ledger_lock_identity,
            )
            self._verify_lock_namespace(guard)
            return guard
        except Exception as exc:
            if ledger_lock_fd is not None:
                if ledger_locked:
                    fcntl.flock(ledger_lock_fd, fcntl.LOCK_UN)
                os.close(ledger_lock_fd)
            for descriptor in reversed(namespace_fds):
                os.close(descriptor)
            if root_lock_fd is not None:
                if root_locked:
                    fcntl.flock(root_lock_fd, fcntl.LOCK_UN)
                os.close(root_lock_fd)
            if root_fd is not None:
                os.close(root_fd)
            if isinstance(exc, LedgerError):
                raise
            raise LedgerError("cannot open ledger lock safely") from exc

    def _verify_lock_namespace(self, guard: _LedgerLock) -> None:
        root_metadata = os.fstat(guard.root_fd)
        try:
            named_root = os.stat(self.policy.root, follow_symlinks=False)
        except OSError as exc:
            raise LedgerError("ledger project root name changed") from exc
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_dev, root_metadata.st_ino) != self._root_identity
            or (named_root.st_dev, named_root.st_ino) != self._root_identity
        ):
            raise LedgerError("ledger project root identity changed")

        root_lock_metadata = os.fstat(guard.root_lock_fd)
        root_lock_named = os.stat(
            ".scientist-one-event-ledger.lock",
            dir_fd=guard.root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(root_lock_metadata.st_mode)
            or root_lock_metadata.st_nlink != 1
            or (root_lock_metadata.st_dev, root_lock_metadata.st_ino)
            != guard.root_lock_identity
            or guard.root_lock_identity
            != (root_lock_named.st_dev, root_lock_named.st_ino)
        ):
            raise LedgerError("ledger namespace lock identity changed")

        parent_fds = (guard.root_fd,) + guard.namespace_fds[:-1]
        for component, parent_fd, child_fd, parent_version in zip(
            self.relative_path.parent.parts,
            parent_fds,
            guard.namespace_fds,
            guard.parent_versions,
        ):
            if self._directory_version(os.fstat(parent_fd)) != parent_version:
                raise LedgerError("ledger parent namespace changed")
            child_metadata = os.fstat(child_fd)
            try:
                named_child = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise LedgerError("ledger parent namespace name changed") from exc
            if (
                not stat.S_ISDIR(child_metadata.st_mode)
                or (child_metadata.st_dev, child_metadata.st_ino)
                != (named_child.st_dev, named_child.st_ino)
            ):
                raise LedgerError("ledger parent namespace identity changed")
        ledger_parent_fd = self._ledger_parent_fd(guard)
        parent_metadata = os.fstat(ledger_parent_fd)
        if (parent_metadata.st_dev, parent_metadata.st_ino) != self._parent_identity:
            raise LedgerError("ledger parent namespace identity changed")

        lock_metadata = os.fstat(guard.ledger_lock_fd)
        try:
            named_lock = os.stat(
                self.lock_path.name,
                dir_fd=ledger_parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise LedgerError("ledger lock name changed") from exc
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or (lock_metadata.st_dev, lock_metadata.st_ino)
            != guard.ledger_lock_identity
            or guard.ledger_lock_identity != (named_lock.st_dev, named_lock.st_ino)
        ):
            raise LedgerError("ledger lock identity changed")

    def _verify_no_parent_namespace_aba(self, guard: _LedgerLock) -> None:
        parent_fds = (guard.root_fd,) + guard.namespace_fds[:-1]
        for parent_fd, admitted_ctime in zip(
            parent_fds, guard.parent_change_times
        ):
            if os.fstat(parent_fd).st_ctime_ns != admitted_ctime:
                raise LedgerError("ledger parent namespace changed during operation")

    def _unlock(self, guard: _LedgerLock) -> None:
        error: BaseException | None = None
        try:
            self._verify_no_parent_namespace_aba(guard)
            self._verify_lock_namespace(guard)
        except BaseException as exc:
            error = exc
        finally:
            if fcntl is not None:
                fcntl.flock(guard.ledger_lock_fd, fcntl.LOCK_UN)
            os.close(guard.ledger_lock_fd)
            for descriptor in reversed(guard.namespace_fds):
                os.close(descriptor)
            if fcntl is not None:
                fcntl.flock(guard.root_lock_fd, fcntl.LOCK_UN)
            os.close(guard.root_lock_fd)
            os.close(guard.root_fd)
        if error is not None:
            raise error

    def _open_ledger_fd(
        self,
        guard: _LedgerLock,
        *,
        writable: bool,
        create: bool,
    ) -> int | None:
        flags = (
            (os.O_RDWR | os.O_APPEND if writable else os.O_RDONLY)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        if create:
            flags |= os.O_CREAT
        try:
            descriptor = os.open(
                self.path.name,
                flags,
                0o600,
                dir_fd=self._ledger_parent_fd(guard),
            )
        except FileNotFoundError:
            if not create:
                return None
            raise
        metadata = os.fstat(descriptor)
        try:
            named = os.stat(
                self.path.name,
                dir_fd=self._ledger_parent_fd(guard),
                follow_symlinks=False,
            )
        except OSError:
            os.close(descriptor)
            raise
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            os.close(descriptor)
            raise LedgerCorruptionError("ledger is not a private named regular file")
        return descriptor

    def _verify_ledger_fd(self, guard: _LedgerLock, descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        try:
            named = os.stat(
                self.path.name,
                dir_fd=self._ledger_parent_fd(guard),
                follow_symlinks=False,
            )
        except OSError as exc:
            raise LedgerCorruptionError("ledger name changed during locked access") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise LedgerCorruptionError("ledger name no longer denotes the locked file")

    def _read_ledger_fd(self, descriptor: int) -> bytes:
        before = os.fstat(descriptor)
        if before.st_size > MAX_LEDGER_BYTES:
            raise LedgerCorruptionError("ledger exceeds its size limit")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_LEDGER_BYTES - total + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_LEDGER_BYTES:
                raise LedgerCorruptionError("ledger exceeds its size limit")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise LedgerCorruptionError("ledger changed during locked read")
        return b"".join(chunks)

    def _read_raw_locked(self, guard: _LedgerLock) -> bytes:
        descriptor: int | None = None
        try:
            descriptor = self._open_ledger_fd(
                guard, writable=False, create=False
            )
            if descriptor is None:
                return b""
            data = self._read_ledger_fd(descriptor)
            self._verify_ledger_fd(guard, descriptor)
            return data
        except (OSError, LedgerCorruptionError) as exc:
            if isinstance(exc, LedgerCorruptionError):
                raise
            raise LedgerCorruptionError("ledger cannot be safely read") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _validate_bytes(data: bytes) -> LedgerValidationResult:
        if len(data) > MAX_LEDGER_BYTES:
            return LedgerValidationResult(
                False,
                (),
                None,
                "LEDGER_SIZE_LIMIT_EXCEEDED",
                None,
                False,
                0,
            )
        if not data:
            return LedgerValidationResult(True, (), None, valid_prefix_bytes=0)
        if not data.endswith(b"\n"):
            prefix_end = data.rfind(b"\n") + 1
            prefix = data[:prefix_end]
            prefix_result = EventLedger._validate_bytes(prefix) if prefix else LedgerValidationResult(True, (), None)
            if prefix_result.valid and prefix_result.events:
                return LedgerValidationResult(
                    False,
                    prefix_result.events,
                    prefix_result.head_hash,
                    "TRUNCATED_FINAL_EVENT",
                    len(prefix_result.events) + 1,
                    True,
                    prefix_end,
                )
            if prefix_result.valid and not prefix_result.events:
                return LedgerValidationResult(
                    False,
                    (),
                    None,
                    "TRUNCATED_FIRST_EVENT",
                    1,
                    False,
                    0,
                )
        events: list[LedgerEvent] = []
        seen_ids: set[str] = set()
        seen_hashes: set[str] = set()
        run_id: str | None = None
        byte_offset = 0
        for line_number, raw_line in enumerate(data.splitlines(keepends=True), 1):
            if line_number > MAX_LEDGER_EVENTS:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    events[-1].event_hash if events else None,
                    "LEDGER_EVENT_LIMIT_EXCEEDED",
                    line_number,
                    False,
                    byte_offset,
                )
            line_start = byte_offset
            byte_offset += len(raw_line)
            if not raw_line.endswith(b"\n"):
                return LedgerValidationResult(
                    False, tuple(events), events[-1].event_hash if events else None,
                    "TRUNCATED_FINAL_EVENT", line_number, True, line_start,
                )
            payload = raw_line[:-1]
            if not payload:
                return LedgerValidationResult(
                    False, tuple(events), events[-1].event_hash if events else None,
                    "BLANK_LEDGER_LINE", line_number, False, line_start,
                )
            try:
                parsed = safe_json_loads(payload)
                event = LedgerEvent.from_dict(parsed)
            except (ValidationError, LedgerCorruptionError) as exc:
                return LedgerValidationResult(
                    False, tuple(events), events[-1].event_hash if events else None,
                    type(exc).__name__, line_number, False, line_start,
                )
            expected_prior = events[-1].event_hash if events else None
            if event.prior_event_hash != expected_prior:
                return LedgerValidationResult(
                    False, tuple(events), expected_prior,
                    "PRIOR_EVENT_HASH_MISMATCH", line_number, False, line_start,
                )
            if event.event_id in seen_ids or event.event_hash in seen_hashes:
                return LedgerValidationResult(
                    False, tuple(events), expected_prior,
                    "DUPLICATE_EVENT_ID_OR_HASH", line_number, False, line_start,
                )
            if run_id is None:
                run_id = event.run_id
            elif event.run_id != run_id:
                return LedgerValidationResult(
                    False, tuple(events), expected_prior,
                    "RUN_ID_MISMATCH", line_number, False, line_start,
                )
            if event.event_type == "CORRECTION" and event.supersedes_event_id not in seen_ids:
                return LedgerValidationResult(
                    False, tuple(events), expected_prior,
                    "INVALID_SUPERSEDED_EVENT", line_number, False, line_start,
                )
            seen_ids.add(event.event_id)
            seen_hashes.add(event.event_hash or "")
            events.append(event)
        return LedgerValidationResult(
            True,
            tuple(events),
            events[-1].event_hash if events else None,
            valid_prefix_bytes=len(data),
        )

    def validate(self, *, raise_on_error: bool = False) -> LedgerValidationResult:
        guard: _LedgerLock | None = None
        try:
            guard = self._open_lock()
            result = self._validate_bytes(self._read_raw_locked(guard))
        except (LedgerError, LedgerCorruptionError):
            result = LedgerValidationResult(
                False,
                (),
                None,
                "LEDGER_READ_OR_SIZE_LIMIT_FAILED",
                None,
                False,
                0,
            )
        finally:
            if guard is not None:
                try:
                    self._unlock(guard)
                except LedgerError:
                    result = LedgerValidationResult(
                        False,
                        (),
                        None,
                        "LEDGER_NAMESPACE_IDENTITY_CHANGED",
                        None,
                        False,
                        0,
                    )
        if raise_on_error and not result.valid:
            raise LedgerCorruptionError(
                f"ledger validation failed at line {result.error_line}: {result.error}"
            )
        return result

    def assert_valid(self) -> LedgerValidationResult:
        return self.validate(raise_on_error=True)

    def events(self) -> tuple[LedgerEvent, ...]:
        return self.assert_valid().events

    def read_events(self) -> tuple[LedgerEvent, ...]:
        return self.events()

    def last_event(self) -> LedgerEvent | None:
        events = self.events()
        return events[-1] if events else None

    def _append_locked(
        self,
        guard: _LedgerLock,
        build_event: Callable[[LedgerValidationResult], LedgerEvent],
    ) -> LedgerEvent:
        descriptor: int | None = None
        try:
            descriptor = self._open_ledger_fd(guard, writable=True, create=True)
            if descriptor is None:  # pragma: no cover - create=True is exhaustive
                raise LedgerError("ledger cannot be created")
            result = self._validate_bytes(self._read_ledger_fd(descriptor))
            if not result.valid:
                raise LedgerCorruptionError(
                    f"ledger validation failed at line {result.error_line}: {result.error}"
                )
            event = build_event(result)
            self._verify_ledger_fd(guard, descriptor)
            if event.event_hash != event_hash(event.to_dict(include_hash=False)):
                raise LedgerCorruptionError(
                    "event changed after its integrity hash was computed"
                )
            expected_prior = result.head_hash
            if event.prior_event_hash != expected_prior:
                raise LedgerError("event prior hash does not match current ledger head")
            if result.events and event.run_id != result.events[0].run_id:
                raise LedgerError("event run ID does not match ledger")
            if any(item.event_id == event.event_id for item in result.events):
                raise LedgerError("event ID already exists")
            if event.event_type == "CORRECTION" and not any(
                item.event_id == event.supersedes_event_id for item in result.events
            ):
                raise LedgerError("correction does not reference an earlier event")
            line = canonical_json_bytes(event.to_dict()) + b"\n"
            if len(result.events) + 1 > MAX_LEDGER_EVENTS:
                raise LedgerError("ledger event limit would be exceeded")
            if result.valid_prefix_bytes + len(line) > MAX_LEDGER_BYTES:
                raise LedgerError("ledger byte limit would be exceeded")
            metadata = os.fstat(descriptor)
            if metadata.st_size != result.valid_prefix_bytes:
                raise LedgerError("ledger changed outside the serialized append lock")
            written = 0
            while written < len(line):
                count = os.write(descriptor, line[written:])
                if count <= 0:
                    raise OSError("short ledger append")
                written += count
            os.fsync(descriptor)
            os.fsync(self._ledger_parent_fd(guard))
            self._verify_ledger_fd(guard, descriptor)
            final_metadata = os.fstat(descriptor)
            if final_metadata.st_size != result.valid_prefix_bytes + len(line):
                raise LedgerError("ledger append size is inconsistent")
            return event
        except OSError as exc:
            raise LedgerError("durable ledger append failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def append(self, event: LedgerEvent | Mapping[str, Any]) -> LedgerEvent:
        typed = event if isinstance(event, LedgerEvent) else LedgerEvent.from_dict(event)
        lock = self._open_lock()
        try:
            return self._append_locked(lock, lambda _result: typed)
        finally:
            self._unlock(lock)

    def record(
        self,
        *,
        run_id: str,
        actor_role: Role,
        state_before: State,
        requested_state_after: State,
        artifact_hashes: Iterable[str],
        code_version: str,
        configuration_hash: str,
        reason: str,
        dataset_identifiers: Iterable[str] = (),
        random_seeds: Iterable[int] = (),
        evaluator_outputs: Iterable[Any] = (),
        event_id: str | None = None,
        timestamp: str | None = None,
        event_type: str = "TRANSITION",
        supersedes_event_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> LedgerEvent:
        lock = self._open_lock()
        try:
            return self._append_locked(
                lock,
                lambda result: LedgerEvent.create(
                    run_id=run_id,
                    event_id=event_id,
                    timestamp=timestamp,
                    actor_role=actor_role,
                    state_before=state_before,
                    requested_state_after=requested_state_after,
                    artifact_hashes=artifact_hashes,
                    code_version=code_version,
                    configuration_hash=configuration_hash,
                    dataset_identifiers=dataset_identifiers,
                    random_seeds=random_seeds,
                    evaluator_outputs=evaluator_outputs,
                    reason=reason,
                    prior_event_hash=result.head_hash,
                    event_type=event_type,
                    supersedes_event_id=supersedes_event_id,
                    metadata=metadata,
                ),
            )
        finally:
            self._unlock(lock)

    append_event = record

    def append_correction(
        self,
        supersedes_event_id: str,
        *,
        actor_role: Role,
        reason: str,
        corrected_fields: Mapping[str, Any],
        event_id: str | None = None,
        timestamp: str | None = None,
        code_version: str | None = None,
        configuration_hash: str | None = None,
    ) -> LedgerEvent:
        validate_identifier(supersedes_event_id, "superseded event ID")
        if not isinstance(corrected_fields, Mapping) or not corrected_fields:
            raise LedgerError("correction must contain typed replacement data")
        lock = self._open_lock()
        try:
            def build(result: LedgerValidationResult) -> LedgerEvent:
                target = next(
                    (
                        item
                        for item in result.events
                        if item.event_id == supersedes_event_id
                    ),
                    None,
                )
                if target is None:
                    raise LedgerError("superseded event does not exist")
                return LedgerEvent.create(
                    run_id=target.run_id,
                    actor_role=actor_role,
                    state_before=target.requested_state_after,
                    requested_state_after=target.requested_state_after,
                    artifact_hashes=target.artifact_hashes,
                    code_version=code_version or target.code_version,
                    configuration_hash=(
                        configuration_hash or target.configuration_hash
                    ),
                    dataset_identifiers=target.dataset_identifiers,
                    random_seeds=target.random_seeds,
                    evaluator_outputs=target.evaluator_outputs,
                    reason=reason,
                    event_id=event_id,
                    timestamp=timestamp,
                    prior_event_hash=result.head_hash,
                    event_type="CORRECTION",
                    supersedes_event_id=supersedes_event_id,
                    metadata={"corrected_fields": dict(corrected_fields)},
                )

            return self._append_locked(lock, build)
        finally:
            self._unlock(lock)

    def recover_truncated_tail(
        self,
        quarantine_directory: str | os.PathLike[str] = ".scientist-one-build/quarantine",
    ) -> Path:
        """Quarantine only a proven torn final append and restore its valid prefix."""

        lock = self._open_lock()
        descriptor: int | None = None
        try:
            quarantine_root = secure_directory(
                self.policy.root, quarantine_directory, create=True
            )
            self._verify_lock_namespace(lock)
            # Creating an unrelated quarantine path may legitimately update an
            # ancestor ctime.  Refresh that admission point only after proving
            # every held/named namespace inode still matches.
            parent_fds = (lock.root_fd,) + lock.namespace_fds[:-1]
            lock = _LedgerLock(
                root_fd=lock.root_fd,
                namespace_fds=lock.namespace_fds,
                parent_versions=lock.parent_versions,
                parent_change_times=tuple(
                    os.fstat(parent_fd).st_ctime_ns for parent_fd in parent_fds
                ),
                root_lock_fd=lock.root_lock_fd,
                root_lock_identity=lock.root_lock_identity,
                ledger_lock_fd=lock.ledger_lock_fd,
                ledger_lock_identity=lock.ledger_lock_identity,
            )
            descriptor = self._open_ledger_fd(lock, writable=True, create=False)
            if descriptor is None:
                raise LedgerError("ledger does not contain a recoverable torn final append")
            data = self._read_ledger_fd(descriptor)
            self._verify_ledger_fd(lock, descriptor)
            result = self._validate_bytes(data)
            if result.valid or not result.recoverable_truncated_tail:
                raise LedgerError("ledger does not contain a recoverable torn final append")
            prefix = data[: result.valid_prefix_bytes]
            tail = data[result.valid_prefix_bytes :]
            if not tail or tail.endswith(b"\n"):
                raise LedgerError("only an unterminated final append may be recovered")
            digest = sha256_bytes(tail)
            quarantine = Path(quarantine_directory) / f"ledger-tail-{digest}.partial"
            atomic_write_bytes(
                self.policy.root,
                quarantine,
                tail,
                immutable=True,
                create_parents=False,
            )
            self._verify_ledger_fd(lock, descriptor)
            os.ftruncate(descriptor, len(prefix))
            os.fsync(descriptor)
            os.fsync(self._ledger_parent_fd(lock))
            self._verify_ledger_fd(lock, descriptor)
            restored = self._read_ledger_fd(descriptor)
            if restored != prefix or not self._validate_bytes(restored).valid:
                raise LedgerCorruptionError("recovered ledger prefix is invalid")
            return quarantine_root / quarantine.name
        except OSError as exc:
            raise LedgerError("durable ledger recovery failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            self._unlock(lock)


Ledger = EventLedger
