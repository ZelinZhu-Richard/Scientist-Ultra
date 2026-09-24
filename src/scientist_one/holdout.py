"""Holdout custody contracts and a one-shot local simulated adapter.

``SimulatedHoldoutCustody`` is useful for deterministic tests only.  It is
always labeled ``NON_INDEPENDENT`` because the local process can ultimately
inspect both the adapter and its payload.  The interfaces at the bottom of the
module define, but do not pretend to implement, human and service custody.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Callable, Iterator, TypeVar

from .errors import PathSecurityError, ScientistOneError, ValidationError
from .security import (
    canonical_json_bytes,
    canonical_root,
    open_confined_directory_fd,
    resolve_confined,
    safe_json_loads,
    secure_directory,
)


class HoldoutCustodyError(ScientistOneError):
    """Base failure for custody operations."""


class HoldoutPreconditionError(HoldoutCustodyError, ValidationError):
    """A reveal was requested before all frozen artifacts existed."""


class HoldoutAccessViolation(HoldoutCustodyError):
    """Unauthorized or accidental access invalidated confirmatory use."""


class HoldoutAlreadyRevealed(HoldoutCustodyError):
    """The one authorized reveal was already consumed."""


class HoldoutJournalError(HoldoutCustodyError):
    """The durable custody journal is missing, corrupt, or inconsistent."""


class CustodyIndependence(StrEnum):
    NON_INDEPENDENT = "NON_INDEPENDENT"
    HUMAN_INDEPENDENT = "HUMAN_INDEPENDENT"
    SERVICE_INDEPENDENT = "SERVICE_INDEPENDENT"


class AccessOutcome(StrEnum):
    RELEASED = "RELEASED"
    DENIED_PRECONDITION = "DENIED_PRECONDITION"
    UNAUTHORIZED_VIOLATION = "UNAUTHORIZED_VIOLATION"
    ACCIDENTAL_ACCESS_VIOLATION = "ACCIDENTAL_ACCESS_VIOLATION"


_T = TypeVar("_T")
_JOURNAL_SCHEMA_VERSION = "1.0"
_JOURNAL_GENESIS_HASH = "0" * 64
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_JOURNAL_EVENTS = 10_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HoldoutCustodyError(f"{field_name} must be a non-empty string")
    return value.strip()


def _sha256(value: str, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise HoldoutCustodyError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _object_hash(value: Any) -> str:
    payload = asdict(value)
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _enum_dict(value: Any) -> dict[str, Any]:
    result = asdict(value)
    for key, item in tuple(result.items()):
        if isinstance(item, StrEnum):
            result[key] = item.value
    return result


@dataclass(frozen=True, slots=True)
class CustodyJournalEvent:
    event_index: int
    event_type: str
    payload: dict[str, Any]
    prior_event_hash: str
    event_hash: str
    schema_version: str = _JOURNAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.event_index, bool) or not isinstance(self.event_index, int) or self.event_index < 0:
            raise HoldoutJournalError("custody journal event index is invalid")
        if self.event_type not in {"SEAL", "ACCESS", "RELEASE"}:
            raise HoldoutJournalError("custody journal event type is invalid")
        if not isinstance(self.payload, dict):
            raise HoldoutJournalError("custody journal event payload must be an object")
        _sha256(self.prior_event_hash, "prior_event_hash")
        _sha256(self.event_hash, "event_hash")
        if self.schema_version != _JOURNAL_SCHEMA_VERSION:
            raise HoldoutJournalError("unsupported custody journal schema")

    @property
    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_index": self.event_index,
            "event_type": self.event_type,
            "payload": self.payload,
            "prior_event_hash": self.prior_event_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict, "event_hash": self.event_hash}


@dataclass(frozen=True, slots=True)
class RevealPreconditions:
    protocol_frozen: bool
    code_frozen: bool
    configuration_frozen: bool
    pre_unblinding_interpretation_frozen: bool
    midrun_review_passed: bool
    confirmatory_reserve_untouched: bool

    def __post_init__(self) -> None:
        for name in (
            "protocol_frozen",
            "code_frozen",
            "configuration_frozen",
            "pre_unblinding_interpretation_frozen",
            "midrun_review_passed",
            "confirmatory_reserve_untouched",
        ):
            if not isinstance(getattr(self, name), bool):
                raise HoldoutPreconditionError(f"{name} must be boolean")

    @property
    def satisfied(self) -> bool:
        return all(
            (
                self.protocol_frozen,
                self.code_frozen,
                self.configuration_frozen,
                self.pre_unblinding_interpretation_frozen,
                self.midrun_review_passed,
                self.confirmatory_reserve_untouched,
            )
        )

    @property
    def missing(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in (
                "protocol_frozen",
                "code_frozen",
                "configuration_frozen",
                "pre_unblinding_interpretation_frozen",
                "midrun_review_passed",
                "confirmatory_reserve_untouched",
            )
            if not getattr(self, name)
        )


@dataclass(frozen=True, slots=True)
class HoldoutSeal:
    holdout_identity_hash: str
    split_manifest_hash: str
    protocol_hash: str
    code_hash: str
    configuration_hash: str
    pre_unblinding_interpretation_hash: str
    sealed_at: str
    custody_independence: CustodyIndependence
    authorized_access_limit: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.custody_independence, CustodyIndependence):
            try:
                object.__setattr__(
                    self,
                    "custody_independence",
                    CustodyIndependence(self.custody_independence),
                )
            except (TypeError, ValueError) as exc:
                raise HoldoutCustodyError("invalid custody independence") from exc
        for name in (
            "holdout_identity_hash",
            "split_manifest_hash",
            "protocol_hash",
            "code_hash",
            "configuration_hash",
            "pre_unblinding_interpretation_hash",
        ):
            _sha256(getattr(self, name), name)
        _nonempty(self.sealed_at, "sealed_at")
        if self.authorized_access_limit != 1:
            raise HoldoutCustodyError("confirmatory custody permits exactly one authorized reveal")

    @property
    def seal_hash(self) -> str:
        return _object_hash(self)


@dataclass(frozen=True, slots=True)
class HoldoutAccessRecord:
    event_id: str
    requested_at: str
    requester: str
    reason: str
    authorized: bool
    outcome: AccessOutcome
    authorized_access_count: int
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, AccessOutcome):
            try:
                object.__setattr__(self, "outcome", AccessOutcome(self.outcome))
            except (TypeError, ValueError) as exc:
                raise HoldoutCustodyError("invalid access outcome") from exc
        _sha256(self.event_id, "event_id")
        _nonempty(self.requested_at, "requested_at")
        _nonempty(self.requester, "requester")
        _nonempty(self.reason, "reason")
        if not isinstance(self.authorized, bool):
            raise HoldoutCustodyError("authorized must be boolean")
        if (
            isinstance(self.authorized_access_count, bool)
            or not isinstance(self.authorized_access_count, int)
            or self.authorized_access_count < 0
            or self.authorized_access_count > 1
        ):
            raise HoldoutCustodyError("authorized_access_count must be zero or one")
        _nonempty(self.detail, "access detail")


@dataclass(frozen=True, slots=True)
class HoldoutRelease:
    release_id: str
    released_at: str
    requester: str
    reason: str
    seal_hash: str
    holdout_identity_hash: str
    authorized_access_count: int

    def __post_init__(self) -> None:
        for name in ("release_id", "seal_hash", "holdout_identity_hash"):
            _sha256(getattr(self, name), name)
        _nonempty(self.released_at, "released_at")
        _nonempty(self.requester, "requester")
        _nonempty(self.reason, "reason")
        if self.authorized_access_count != 1:
            raise HoldoutCustodyError("the only valid release has authorized_access_count one")


@dataclass(frozen=True, slots=True)
class ReleasedHoldout:
    release: HoldoutRelease
    content: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise HoldoutCustodyError("released holdout content must be bytes")
        if _content_hash(self.content) != self.release.holdout_identity_hash:
            raise HoldoutCustodyError("released content does not match holdout identity")


@dataclass(frozen=True, slots=True)
class CustodyStatus:
    custody_independence: CustodyIndependence
    sealed: bool
    revealed: bool
    invalidated: bool
    confirmatory_claims_valid: bool
    authorized_access_count: int
    violation_reasons: tuple[str, ...]
    release_event: HoldoutRelease | None
    durable_journal: bool = False
    journal_head_hash: str | None = None


@dataclass(frozen=True, slots=True)
class HoldoutAdmissionSnapshot:
    """Provider-owned live custody state and bytes from one locked journal fd."""

    seal: HoldoutSeal
    status: CustodyStatus
    journal_head_hash: str
    custody_label: str
    journal_bytes: bytes = field(repr=False)
    journal_sha256: str
    journal_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.seal, HoldoutSeal):
            raise HoldoutJournalError("custody admission snapshot lacks a typed seal")
        if not isinstance(self.status, CustodyStatus):
            raise HoldoutJournalError("custody admission snapshot lacks typed status")
        _sha256(self.journal_head_hash, "custody admission journal head")
        _sha256(self.journal_sha256, "custody admission journal bytes")
        _sha256(
            self.journal_identity_sha256,
            "custody admission stable journal identity",
        )
        _nonempty(self.custody_label, "custody admission label")
        if not isinstance(self.journal_bytes, bytes) or not self.journal_bytes:
            raise HoldoutJournalError("custody admission requires non-empty journal bytes")
        if len(self.journal_bytes) > _MAX_JOURNAL_BYTES:
            raise HoldoutJournalError("custody admission journal bytes exceed the size limit")
        if _content_hash(self.journal_bytes) != self.journal_sha256:
            raise HoldoutJournalError("custody admission journal byte hash mismatch")
        if not self.journal_bytes.endswith(b"\n"):
            raise HoldoutJournalError("custody admission journal bytes are incomplete")
        try:
            last_event = safe_json_loads(
                self.journal_bytes.splitlines()[-1],
                max_bytes=_MAX_JOURNAL_BYTES,
            )
        except Exception as exc:
            raise HoldoutJournalError(
                "custody admission journal tail is malformed"
            ) from exc
        if (
            not isinstance(last_event, dict)
            or last_event.get("event_hash") != self.journal_head_hash
        ):
            raise HoldoutJournalError(
                "custody admission journal bytes do not bind their head"
            )
        if not self.status.durable_journal:
            raise HoldoutJournalError("custody admission requires a durable journal")
        if self.status.journal_head_hash != self.journal_head_hash:
            raise HoldoutJournalError("custody admission status is not bound to its journal head")
        if not self.status.sealed or self.status.custody_independence is not self.seal.custody_independence:
            raise HoldoutJournalError("custody admission status does not match its seal")

    @property
    def seal_hash(self) -> str:
        return self.seal.seal_hash

    @property
    def protocol_hash(self) -> str:
        return self.seal.protocol_hash

    @property
    def authorized_access_count(self) -> int:
        return self.status.authorized_access_count

    @property
    def durable_journal(self) -> bool:
        return self.status.durable_journal

    @property
    def sealed(self) -> bool:
        return self.status.sealed

    @property
    def revealed(self) -> bool:
        return self.status.revealed

    @property
    def invalidated(self) -> bool:
        return self.status.invalidated

    @property
    def confirmatory_claims_valid(self) -> bool:
        return self.status.confirmatory_claims_valid

    @property
    def code_hash(self) -> str:
        return self.seal.code_hash

    @property
    def configuration_hash(self) -> str:
        return self.seal.configuration_hash

    @property
    def split_manifest_hash(self) -> str:
        return self.seal.split_manifest_hash

    @property
    def pre_unblinding_interpretation_hash(self) -> str:
        return self.seal.pre_unblinding_interpretation_hash

    @property
    def holdout_identity_hash(self) -> str:
        return self.seal.holdout_identity_hash

    @property
    def journal_size(self) -> int:
        return len(self.journal_bytes)


# Compatibility name for provider consumers that use custody terminology.
CustodyAdmissionSnapshot = HoldoutAdmissionSnapshot


class HoldoutCustody(ABC):
    """Provider-neutral boundary for confirmatory holdout access."""

    independence: CustodyIndependence

    @abstractmethod
    def seal(self, holdout_content: bytes, **frozen_hashes: str) -> HoldoutSeal:
        raise NotImplementedError

    @abstractmethod
    def request_reveal(self, **request: Any) -> ReleasedHoldout:
        raise NotImplementedError

    @abstractmethod
    def record_violation(self, *, requester: str, reason: str, occurred_at: str | None = None) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> CustodyStatus:
        raise NotImplementedError

    @abstractmethod
    def admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
    ) -> Any:
        """Return a context manager retaining the provider's live-state lock."""

        raise NotImplementedError


class SimulatedHoldoutCustody(HoldoutCustody):
    """One-shot local adapter for tests, explicitly not independent custody."""

    independence = CustodyIndependence.NON_INDEPENDENT
    custody_label = "SIMULATED_NON_INDEPENDENT"

    def __init__(
        self,
        authorized_requesters: tuple[str, ...],
        *,
        journal_root: str | os.PathLike[str] | None = None,
        journal_path: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(authorized_requesters, tuple) or not authorized_requesters:
            raise HoldoutCustodyError("authorized_requesters must be a non-empty tuple")
        normalized = tuple(_nonempty(value, "authorized_requester") for value in authorized_requesters)
        if len(set(normalized)) != len(normalized):
            raise HoldoutCustodyError("authorized_requesters must be unique")
        self._authorized_requesters = frozenset(normalized)
        self._seal: HoldoutSeal | None = None
        self._payload: bytes | None = None
        self._release: HoldoutRelease | None = None
        self._records: list[HoldoutAccessRecord] = []
        self._violations: list[str] = []
        self._authorized_access_count = 0
        self._lock = threading.RLock()
        self._journal_root: Path | None = None
        self._journal_relative: Path | None = None
        self._journal_head_hash: str | None = None
        self._journal_root_identity: tuple[int, int] | None = None
        if (journal_root is None) != (journal_path is None):
            raise HoldoutJournalError("journal_root and journal_path must be supplied together")
        if journal_root is not None and journal_path is not None:
            root = canonical_root(journal_root)
            raw_path = Path(journal_path)
            if raw_path.is_absolute():
                try:
                    relative = raw_path.relative_to(root)
                except ValueError as exc:
                    raise PathSecurityError("custody journal is outside the project root") from exc
            else:
                relative = raw_path
            if not relative.parts or relative.name in {"", ".", ".."}:
                raise PathSecurityError("custody journal filename is invalid")
            secure_directory(root, relative.parent, create=True)
            resolve_confined(
                root,
                relative,
                must_exist=False,
                expected_kind="file",
                reject_hardlinks=True,
            )
            self._journal_root = root
            self._journal_relative = relative
            root_metadata = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise PathSecurityError("custody journal root is not a directory")
            self._journal_root_identity = (
                root_metadata.st_dev,
                root_metadata.st_ino,
            )
            with self._journal_guard():
                pass

    @property
    def durable(self) -> bool:
        return self._journal_root is not None

    @property
    def journal_path(self) -> Path | None:
        if self._journal_root is None or self._journal_relative is None:
            return None
        return self._journal_root / self._journal_relative

    def _open_journal(self) -> int:
        if self._journal_root is None or self._journal_relative is None:
            raise HoldoutJournalError("durable journal is not configured")
        directory_fd = open_confined_directory_fd(
            self._journal_root,
            self._journal_relative.parent,
            create=False,
        )
        try:
            flags = (
                os.O_RDWR
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                descriptor = os.open(self._journal_relative.name, flags, 0o600, dir_fd=directory_fd)
            except OSError as exc:
                raise PathSecurityError("custody journal cannot be opened safely") from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise PathSecurityError("custody journal must be a non-hard-linked regular file")
            os.fsync(directory_fd)
            return descriptor
        finally:
            os.close(directory_fd)

    def _open_namespace_lock(self) -> int:
        """Lock the stable project-root namespace before resolving the journal."""

        if self._journal_root is None or self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal is not configured")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(self._journal_root, flags)
        except OSError as exc:
            raise PathSecurityError("custody namespace cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != self._journal_root_identity
            ):
                raise PathSecurityError("custody namespace identity changed")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._verify_namespace_lock_identity(descriptor)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _verify_namespace_lock_identity(self, descriptor: int) -> None:
        if self._journal_root is None or self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal is not configured")
        held = os.fstat(descriptor)
        try:
            named = os.stat(self._journal_root, follow_symlinks=False)
        except OSError as exc:
            raise HoldoutJournalError("custody namespace name changed") from exc
        if (
            not stat.S_ISDIR(held.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or (held.st_dev, held.st_ino) != self._journal_root_identity
            or (named.st_dev, named.st_ino) != self._journal_root_identity
        ):
            raise HoldoutJournalError("custody namespace no longer denotes its locked root")

    def _journal_identity_hash(self, descriptor: int) -> str:
        if self._journal_root_identity is None:
            raise HoldoutJournalError("durable journal root identity is unavailable")
        held = os.fstat(descriptor)
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "root_device": self._journal_root_identity[0],
                    "root_inode": self._journal_root_identity[1],
                    "journal_device": held.st_dev,
                    "journal_inode": held.st_ino,
                }
            )
        ).hexdigest()

    def _read_journal_bytes_locked(self, descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_JOURNAL_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_JOURNAL_BYTES:
                raise HoldoutJournalError("custody journal exceeds its size limit")
        return b"".join(chunks)

    def _parse_journal_bytes(self, content: bytes) -> tuple[CustodyJournalEvent, ...]:
        if not content:
            return ()
        if not content.endswith(b"\n"):
            raise HoldoutJournalError("custody journal has an incomplete final event")
        lines = content.splitlines()
        if len(lines) > _MAX_JOURNAL_EVENTS:
            raise HoldoutJournalError("custody journal exceeds its event limit")
        events: list[CustodyJournalEvent] = []
        prior = _JOURNAL_GENESIS_HASH
        expected_keys = {
            "schema_version",
            "event_index",
            "event_type",
            "payload",
            "prior_event_hash",
            "event_hash",
        }
        for index, line in enumerate(lines):
            try:
                value = safe_json_loads(line, max_bytes=_MAX_JOURNAL_BYTES)
            except Exception as exc:
                raise HoldoutJournalError("custody journal contains invalid JSON") from exc
            if not isinstance(value, dict) or set(value) != expected_keys:
                raise HoldoutJournalError("custody journal event schema is invalid")
            try:
                event = CustodyJournalEvent(**value)
            except (TypeError, ValueError) as exc:
                raise HoldoutJournalError("custody journal event is malformed") from exc
            if event.event_index != index or event.prior_event_hash != prior:
                raise HoldoutJournalError("custody journal sequence or hash link is invalid")
            computed = hashlib.sha256(canonical_json_bytes(event.unsigned_dict)).hexdigest()
            if computed != event.event_hash:
                raise HoldoutJournalError("custody journal event hash mismatch")
            events.append(event)
            prior = event.event_hash
        return tuple(events)

    def _read_journal_locked(self, descriptor: int) -> tuple[CustodyJournalEvent, ...]:
        return self._parse_journal_bytes(self._read_journal_bytes_locked(descriptor))

    def _verify_locked_journal_identity(self, descriptor: int) -> bytes:
        """Prove the configured name still denotes the locked, verified inode."""

        if self._journal_root is None or self._journal_relative is None:
            raise HoldoutJournalError("durable journal is not configured")
        content = self._read_journal_bytes_locked(descriptor)
        events = self._parse_journal_bytes(content)
        head = events[-1].event_hash if events else None
        if head != self._journal_head_hash:
            raise HoldoutJournalError("custody journal head changed during the locked operation")
        held = os.fstat(descriptor)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or held.st_size != len(content)
        ):
            raise HoldoutJournalError("locked custody journal identity is unsafe")
        directory_fd = open_confined_directory_fd(
            self._journal_root,
            self._journal_relative.parent,
            create=False,
        )
        try:
            try:
                named = os.stat(
                    self._journal_relative.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise HoldoutJournalError(
                    "custody journal name changed during the locked operation"
                ) from exc
            if (
                not stat.S_ISREG(named.st_mode)
                or named.st_nlink != 1
                or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
                or named.st_size != held.st_size
            ):
                raise HoldoutJournalError(
                    "custody journal name no longer denotes the locked file"
                )
        finally:
            os.close(directory_fd)
        return content

    def _restore_from_events(self, events: tuple[CustodyJournalEvent, ...]) -> None:
        prior_payload = self._payload
        self._seal = None
        self._release = None
        self._records = []
        self._violations = []
        self._authorized_access_count = 0
        self._journal_head_hash = events[-1].event_hash if events else None
        for event in events:
            payload = event.payload
            if event.event_type == "SEAL":
                if self._seal is not None or event.event_index != 0:
                    raise HoldoutJournalError("custody journal contains duplicate or misplaced seal")
                if set(payload) != {"seal", "authorized_requesters"}:
                    raise HoldoutJournalError("custody seal event payload is invalid")
                requesters = payload["authorized_requesters"]
                if not isinstance(requesters, list) or frozenset(requesters) != self._authorized_requesters:
                    raise HoldoutJournalError("custody journal requester policy mismatch")
                try:
                    self._seal = HoldoutSeal(**payload["seal"])
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody seal event is malformed") from exc
                continue
            if self._seal is None:
                raise HoldoutJournalError("custody journal records access before seal")
            if event.event_type == "ACCESS":
                if set(payload) != {"record", "violation_reason"}:
                    raise HoldoutJournalError("custody access event payload is invalid")
                try:
                    record = HoldoutAccessRecord(**payload["record"])
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody access record is malformed") from exc
                if record.outcome is AccessOutcome.RELEASED:
                    raise HoldoutJournalError("release access must be recorded in a release event")
                self._records.append(record)
                violation = payload["violation_reason"]
                if violation is not None:
                    self._violations.append(_nonempty(violation, "violation_reason"))
            elif event.event_type == "RELEASE":
                if self._release is not None or set(payload) != {"record", "release"}:
                    raise HoldoutJournalError("custody journal contains an invalid duplicate release")
                try:
                    record = HoldoutAccessRecord(**payload["record"])
                    release = HoldoutRelease(**payload["release"])
                except (TypeError, ValueError) as exc:
                    raise HoldoutJournalError("custody release event is malformed") from exc
                if (
                    record.outcome is not AccessOutcome.RELEASED
                    or not record.authorized
                    or record.authorized_access_count != 1
                    or release.authorized_access_count != 1
                    or release.seal_hash != self._seal.seal_hash
                    or release.holdout_identity_hash != self._seal.holdout_identity_hash
                ):
                    raise HoldoutJournalError("custody release does not bind the sealed holdout")
                self._records.append(record)
                self._release = release
                self._authorized_access_count = 1
        if events and self._seal is None:
            raise HoldoutJournalError("custody journal lacks a seal")
        if (
            prior_payload is not None
            and self._seal is not None
            and self._release is None
            and _content_hash(prior_payload) == self._seal.holdout_identity_hash
        ):
            self._payload = prior_payload
        else:
            self._payload = None

    @contextmanager
    def _journal_guard(self) -> Iterator[int | None]:
        if not self.durable:
            yield None
            return
        namespace_descriptor = self._open_namespace_lock()
        descriptor: int | None = None
        try:
            descriptor = self._open_journal()
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            events = self._read_journal_locked(descriptor)
            self._restore_from_events(events)
            yield descriptor
        finally:
            try:
                if descriptor is not None:
                    self._verify_locked_journal_identity(descriptor)
                self._verify_namespace_lock_identity(namespace_descriptor)
            finally:
                try:
                    if descriptor is not None:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    try:
                        fcntl.flock(namespace_descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(namespace_descriptor)

    def _append_journal_locked(
        self,
        descriptor: int | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> CustodyJournalEvent | None:
        if descriptor is None:
            return None
        events = self._read_journal_locked(descriptor)
        disk_head = events[-1].event_hash if events else None
        if disk_head != self._journal_head_hash:
            raise HoldoutJournalError("custody journal changed during the locked operation")
        event_index = len(events)
        prior_hash = self._journal_head_hash or _JOURNAL_GENESIS_HASH
        unsigned = {
            "schema_version": _JOURNAL_SCHEMA_VERSION,
            "event_index": event_index,
            "event_type": event_type,
            "payload": payload,
            "prior_event_hash": prior_hash,
        }
        event = CustodyJournalEvent(
            **unsigned,
            event_hash=hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
        )
        encoded = canonical_json_bytes(event.to_dict()) + b"\n"
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HoldoutJournalError("custody journal append made no progress")
            view = view[written:]
        os.fsync(descriptor)
        self._journal_head_hash = event.event_hash
        return event

    def verify_journal(self) -> str | None:
        """Reload and validate the complete durable custody hash chain."""

        with self._lock, self._journal_guard():
            return self._journal_head_hash

    def _status_locked(self) -> CustodyStatus:
        invalidated = bool(self._violations)
        return CustodyStatus(
            custody_independence=self.independence,
            sealed=self._seal is not None,
            revealed=self._release is not None,
            invalidated=invalidated,
            confirmatory_claims_valid=self._release is not None and not invalidated,
            authorized_access_count=self._authorized_access_count,
            violation_reasons=tuple(self._violations),
            release_event=self._release,
            durable_journal=self.durable,
            journal_head_hash=self._journal_head_hash,
        )

    @contextmanager
    def admission_guard(
        self,
        *,
        expected_journal_head_hash: str | None = None,
        expected_journal_identity_sha256: str | None = None,
    ) -> Iterator[HoldoutAdmissionSnapshot]:
        """Yield freshly verified custody state while retaining both locks.

        Security-sensitive admission must perform its receipt/ledger checks
        inside this context.  The in-process lock prevents another thread from
        recording access, and the exclusive journal lock prevents another
        adapter or process from appending an ACCESS/RELEASE event until the
        admission decision completes.
        """

        if not self.durable:
            raise HoldoutJournalError("custody admission requires a durable journal")
        if expected_journal_head_hash is not None:
            _sha256(expected_journal_head_hash, "expected_journal_head_hash")
        if expected_journal_identity_sha256 is not None:
            _sha256(
                expected_journal_identity_sha256,
                "expected_journal_identity_sha256",
            )
        with self._lock, self._journal_guard() as descriptor:
            if descriptor is None:
                raise HoldoutJournalError("custody admission requires a durable journal")
            if self._seal is None or self._journal_head_hash is None:
                raise HoldoutJournalError("custody admission requires a durable seal")
            if (
                expected_journal_head_hash is not None
                and self._journal_head_hash != expected_journal_head_hash
            ):
                raise HoldoutJournalError(
                    "custody journal head differs from its immutable external anchor"
                )
            journal_identity_sha256 = self._journal_identity_hash(descriptor)
            if (
                expected_journal_identity_sha256 is not None
                and journal_identity_sha256
                != expected_journal_identity_sha256
            ):
                raise HoldoutJournalError(
                    "custody journal identity differs from its immutable external anchor"
                )
            journal_bytes = self._verify_locked_journal_identity(descriptor)
            snapshot = HoldoutAdmissionSnapshot(
                seal=self._seal,
                status=self._status_locked(),
                journal_head_hash=self._journal_head_hash,
                custody_label=self.custody_label,
                journal_bytes=journal_bytes,
                journal_sha256=_content_hash(journal_bytes),
                journal_identity_sha256=journal_identity_sha256,
            )
            yield snapshot
            if self._verify_locked_journal_identity(descriptor) != journal_bytes:
                raise HoldoutJournalError(
                    "custody journal bytes changed during admission"
                )
            if self._journal_identity_hash(descriptor) != journal_identity_sha256:
                raise HoldoutJournalError(
                    "custody journal identity changed during admission"
                )

    def admission_snapshot(self) -> HoldoutAdmissionSnapshot:
        """Return an observational live snapshot; admission must use the guard."""

        with self.admission_guard() as snapshot:
            return snapshot

    def seal(
        self,
        holdout_content: bytes,
        *,
        split_manifest_hash: str,
        protocol_hash: str,
        code_hash: str,
        configuration_hash: str,
        pre_unblinding_interpretation_hash: str,
        sealed_at: str | None = None,
        expected_holdout_identity_hash: str | None = None,
    ) -> HoldoutSeal:
        if not isinstance(holdout_content, bytes) or not holdout_content:
            raise HoldoutCustodyError("holdout_content must be non-empty bytes")
        with self._lock, self._journal_guard() as journal:
            identity = _content_hash(holdout_content)
            if expected_holdout_identity_hash is not None:
                _sha256(expected_holdout_identity_hash, "expected_holdout_identity_hash")
                if identity != expected_holdout_identity_hash:
                    raise HoldoutCustodyError("holdout content does not match expected identity")
            if self._seal is not None:
                supplied = {
                    "holdout_identity_hash": identity,
                    "split_manifest_hash": split_manifest_hash,
                    "protocol_hash": protocol_hash,
                    "code_hash": code_hash,
                    "configuration_hash": configuration_hash,
                    "pre_unblinding_interpretation_hash": pre_unblinding_interpretation_hash,
                }
                mismatch = tuple(
                    name for name, value in supplied.items() if value != getattr(self._seal, name)
                )
                if sealed_at is not None and sealed_at != self._seal.sealed_at:
                    mismatch += ("sealed_at",)
                if mismatch:
                    raise HoldoutCustodyError(
                        "custody reseal does not match durable seal: " + ", ".join(mismatch)
                    )
                if self._release is None:
                    self._payload = bytes(holdout_content)
                return self._seal
            seal = HoldoutSeal(
                holdout_identity_hash=identity,
                split_manifest_hash=split_manifest_hash,
                protocol_hash=protocol_hash,
                code_hash=code_hash,
                configuration_hash=configuration_hash,
                pre_unblinding_interpretation_hash=pre_unblinding_interpretation_hash,
                sealed_at=sealed_at or _now(),
                custody_independence=self.independence,
            )
            self._append_journal_locked(
                journal,
                "SEAL",
                {
                    "seal": _enum_dict(seal),
                    "authorized_requesters": sorted(self._authorized_requesters),
                },
            )
            self._seal = seal
            self._payload = bytes(holdout_content)
            return seal

    def _make_record(
        self,
        *,
        requested_at: str,
        requester: str,
        reason: str,
        authorized: bool,
        outcome: AccessOutcome,
        detail: str,
        authorized_access_count: int | None = None,
    ) -> HoldoutAccessRecord:
        count = (
            self._authorized_access_count
            if authorized_access_count is None
            else authorized_access_count
        )
        body = {
            "index": len(self._records),
            "requested_at": requested_at,
            "requester": requester,
            "reason": reason,
            "authorized": authorized,
            "outcome": outcome.value,
            "authorized_access_count": count,
            "detail": detail,
        }
        record = HoldoutAccessRecord(
            event_id=hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            requested_at=requested_at,
            requester=requester,
            reason=reason,
            authorized=authorized,
            outcome=outcome,
            authorized_access_count=count,
            detail=detail,
        )
        return record

    def request_reveal(
        self,
        *,
        requester: str,
        reason: str,
        protocol_hash: str,
        code_hash: str,
        configuration_hash: str,
        split_manifest_hash: str,
        pre_unblinding_interpretation_hash: str,
        preconditions: RevealPreconditions,
        requested_at: str | None = None,
    ) -> ReleasedHoldout:
        requester = _nonempty(requester, "requester")
        reason = _nonempty(reason, "reason")
        when = requested_at or _now()
        _nonempty(when, "requested_at")
        with self._lock, self._journal_guard() as journal:
            if self._seal is None or self._payload is None:
                if self._release is not None:
                    raise HoldoutAlreadyRevealed("confirmatory holdout was already revealed")
                raise HoldoutPreconditionError("holdout has not been sealed")
            if self._violations:
                raise HoldoutAccessViolation("holdout was invalidated before reveal")
            if self._release is not None or self._authorized_access_count:
                raise HoldoutAlreadyRevealed("confirmatory holdout was already revealed")
            if requester not in self._authorized_requesters:
                detail = "requester is not authorized by the sealed custody policy"
                record = self._make_record(
                    requested_at=when,
                    requester=requester,
                    reason=reason,
                    authorized=False,
                    outcome=AccessOutcome.UNAUTHORIZED_VIOLATION,
                    detail=detail,
                )
                self._append_journal_locked(
                    journal,
                    "ACCESS",
                    {"record": _enum_dict(record), "violation_reason": detail},
                )
                self._records.append(record)
                self._violations.append(detail)
                raise HoldoutAccessViolation(detail)
            if not isinstance(preconditions, RevealPreconditions) or not preconditions.satisfied:
                missing = preconditions.missing if isinstance(preconditions, RevealPreconditions) else ("preconditions",)
                detail = "missing reveal preconditions: " + ", ".join(missing)
                record = self._make_record(
                    requested_at=when,
                    requester=requester,
                    reason=reason,
                    authorized=True,
                    outcome=AccessOutcome.DENIED_PRECONDITION,
                    detail=detail,
                )
                self._append_journal_locked(
                    journal,
                    "ACCESS",
                    {"record": _enum_dict(record), "violation_reason": None},
                )
                self._records.append(record)
                raise HoldoutPreconditionError(detail)
            supplied = {
                "protocol_hash": protocol_hash,
                "code_hash": code_hash,
                "configuration_hash": configuration_hash,
                "split_manifest_hash": split_manifest_hash,
                "pre_unblinding_interpretation_hash": pre_unblinding_interpretation_hash,
            }
            mismatch = tuple(
                name
                for name, value in supplied.items()
                if value != getattr(self._seal, name)
            )
            for name, value in supplied.items():
                _sha256(value, name)
            if mismatch:
                detail = "frozen artifact mismatch: " + ", ".join(mismatch)
                record = self._make_record(
                    requested_at=when,
                    requester=requester,
                    reason=reason,
                    authorized=False,
                    outcome=AccessOutcome.UNAUTHORIZED_VIOLATION,
                    detail=detail,
                )
                self._append_journal_locked(
                    journal,
                    "ACCESS",
                    {"record": _enum_dict(record), "violation_reason": detail},
                )
                self._records.append(record)
                self._violations.append(detail)
                raise HoldoutAccessViolation(detail)
            record = self._make_record(
                requested_at=when,
                requester=requester,
                reason=reason,
                authorized=True,
                outcome=AccessOutcome.RELEASED,
                detail="single authorized confirmatory reveal",
                authorized_access_count=1,
            )
            release_body = {
                "seal_hash": self._seal.seal_hash,
                "released_at": when,
                "requester": requester,
                "reason": reason,
                "authorized_access_count": 1,
            }
            release_id = hashlib.sha256(
                json.dumps(release_body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            release = HoldoutRelease(
                release_id=release_id,
                released_at=when,
                requester=requester,
                reason=reason,
                seal_hash=self._seal.seal_hash,
                holdout_identity_hash=self._seal.holdout_identity_hash,
                authorized_access_count=1,
            )
            # The append and fsync happen before raw content can leave this
            # method.  A crash after this point reloads as already revealed.
            self._append_journal_locked(
                journal,
                "RELEASE",
                {"record": _enum_dict(record), "release": _enum_dict(release)},
            )
            payload = self._payload
            if payload is None:
                raise HoldoutJournalError("sealed payload is unavailable for the durable reveal")
            self._records.append(record)
            self._authorized_access_count = 1
            self._payload = None
            self._release = release
            return ReleasedHoldout(release=release, content=payload)

    def record_violation(
        self,
        *,
        requester: str,
        reason: str,
        occurred_at: str | None = None,
    ) -> None:
        """Record an accidental/out-of-band access and invalidate claims."""

        requester = _nonempty(requester, "requester")
        reason = _nonempty(reason, "reason")
        when = occurred_at or _now()
        with self._lock, self._journal_guard() as journal:
            record = self._make_record(
                requested_at=when,
                requester=requester,
                reason=reason,
                authorized=False,
                outcome=AccessOutcome.ACCIDENTAL_ACCESS_VIOLATION,
                detail="reported access invalidates this holdout for confirmatory claims",
            )
            self._append_journal_locked(
                journal,
                "ACCESS",
                {"record": _enum_dict(record), "violation_reason": reason},
            )
            self._records.append(record)
            self._violations.append(reason)

    @property
    def seal_record(self) -> HoldoutSeal | None:
        with self._lock, self._journal_guard():
            return self._seal

    @property
    def access_records(self) -> tuple[HoldoutAccessRecord, ...]:
        with self._lock, self._journal_guard():
            return tuple(self._records)

    @property
    def status(self) -> CustodyStatus:
        with self._lock, self._journal_guard():
            return self._status_locked()

    def assert_confirmatory_claims_valid(self) -> None:
        status = self.status
        if not status.confirmatory_claims_valid:
            raise HoldoutAccessViolation(
                "holdout is not eligible for confirmatory claims: it is unrevealed or invalidated"
            )

    def run_confirmatory(
        self,
        evaluator: Callable[[bytes], _T],
        **reveal_request: Any,
    ) -> tuple[HoldoutRelease, _T]:
        """Evaluate inside the custody boundary and return only the result.

        This is the preferred adapter path: ordinary orchestration receives a
        result rather than raw holdout bytes.  ``request_reveal`` remains
        available as an explicit unblinding operation for tests and future
        provider implementations whose policy permits releasing content.
        """

        if not callable(evaluator):
            raise HoldoutCustodyError("confirmatory evaluator must be callable")
        released = self.request_reveal(**reveal_request)
        try:
            result = evaluator(released.content)
        except Exception as exc:
            self.record_violation(
                requester=str(reveal_request.get("requester", "confirmatory-evaluator")),
                reason="confirmatory evaluator failed after reveal; holdout cannot be retried",
            )
            raise HoldoutCustodyError("confirmatory evaluator failed after reveal") from exc
        return released.release, result


class HumanControlledHoldoutCustody(HoldoutCustody, ABC):
    """Future adapter contract; an actual human attestation is mandatory."""

    independence = CustodyIndependence.HUMAN_INDEPENDENT

    @abstractmethod
    def verify_human_attestation(self, attestation_id: str) -> bool:
        raise NotImplementedError


class IndependentServiceHoldoutCustody(HoldoutCustody, ABC):
    """Future remote/service contract; no local implementation is implied."""

    independence = CustodyIndependence.SERVICE_INDEPENDENT

    @abstractmethod
    def verify_service_attestation(self, attestation: bytes) -> bool:
        raise NotImplementedError


__all__ = [
    "HoldoutCustodyError",
    "HoldoutPreconditionError",
    "HoldoutAccessViolation",
    "HoldoutAlreadyRevealed",
    "CustodyIndependence",
    "AccessOutcome",
    "RevealPreconditions",
    "HoldoutSeal",
    "HoldoutAccessRecord",
    "HoldoutRelease",
    "ReleasedHoldout",
    "CustodyStatus",
    "HoldoutAdmissionSnapshot",
    "CustodyAdmissionSnapshot",
    "HoldoutCustody",
    "SimulatedHoldoutCustody",
    "HumanControlledHoldoutCustody",
    "IndependentServiceHoldoutCustody",
]
