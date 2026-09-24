"""Fail-closed restart validation and confined partial-write quarantine.

Recovery treats the append-only ledger as authoritative.  Cached state and
checkpoint modification times are never trusted.  A confirmatory run or
holdout access observed anywhere in the validated ledger/custody record is an
irreversible fact: missing output does not authorize a confirmatory rerun.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Iterable, Mapping, Sequence

from .artifacts import MAX_ARTIFACT_OBJECT_BYTES, MAX_REGISTRY_RECORDS
from .errors import PathSecurityError, UnsafeSerializationError
from .security import (
    atomic_write_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
)

try:  # Scientist-One's supported runtime is POSIX/macOS.
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported platforms
    fcntl = None  # type: ignore[assignment]


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GENESIS_HASHES = {None}
INCOMPLETE_SUFFIXES = (".partial", ".incomplete", ".tmp")
CURRENT_CHECKPOINT_SCHEMA = "1.0"
MAX_CHECKPOINT_ENTRIES = 10_000
MAX_CHECKPOINT_SELECTION_BYTES = 64 * 1024**2


class RecoveryError(RuntimeError):
    """Base class for unsafe or invalid recovery state."""


class LedgerValidationError(RecoveryError):
    pass


class ArtifactValidationError(RecoveryError):
    pass


class ConfirmatoryRerunError(RecoveryError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def event_digest(event: Mapping[str, object]) -> str:
    canonical = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()


def checkpoint_digest(checkpoint: Mapping[str, object]) -> str:
    canonical = {key: value for key, value in checkpoint.items() if key != "checkpoint_hash"}
    return hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()


@dataclass(frozen=True)
class LedgerValidationResult:
    valid: bool
    events: tuple[Mapping[str, object], ...]
    head_hash: str | None
    run_id: str | None
    error: str | None = None
    error_line: int | None = None
    recoverable_truncated_tail: bool = False
    valid_prefix_bytes: int = 0
    tail_bytes: int = 0
    source_sha256: str | None = None
    source_size: int | None = None
    source_device: int | None = None
    source_inode: int | None = None

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass(frozen=True)
class ArtifactIssue:
    index: int
    path: str | None
    code: str
    detail: str
    frozen: bool


@dataclass(frozen=True)
class ArtifactValidationResult:
    valid: bool
    records_validated: int
    records: tuple[Mapping[str, object], ...]
    issues: tuple[ArtifactIssue, ...] = ()

    @property
    def has_frozen_failure(self) -> bool:
        return any(issue.frozen for issue in self.issues)


@dataclass(frozen=True)
class QuarantineRecord:
    original_relative_path: str
    quarantine_relative_path: str
    reason: str
    size_bytes: int
    sha256: str
    metadata_relative_path: str


@dataclass(frozen=True)
class CheckpointSelection:
    path: str
    checkpoint: Mapping[str, object]
    ledger_event_index: int


@dataclass(frozen=True)
class FreshCustodyEvidence:
    """Selectors for a frozen receipt; live state comes only from its provider."""

    receipt_artifact_sha256: str
    artifact_record_hash: str
    ledger_event_id: str

    def __post_init__(self) -> None:
        for name in ("receipt_artifact_sha256", "artifact_record_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                raise RecoveryError(f"fresh custody {name} must be SHA-256")
        if not isinstance(self.ledger_event_id, str) or not self.ledger_event_id:
            raise RecoveryError("fresh custody ledger_event_id must be non-empty")


class ResumeAction(str, Enum):
    START_FRESH = "START_FRESH"
    RESUME_FROM_LEDGER = "RESUME_FROM_LEDGER"
    RESUME_FROM_CHECKPOINT = "RESUME_FROM_CHECKPOINT"
    SKIP_COMPLETED = "SKIP_COMPLETED"
    START_NEW_STUDY = "START_NEW_STUDY"
    NEW_STUDY_REQUIRED = "NEW_STUDY_REQUIRED"
    STOP_SECURITY = "STOP_SECURITY"
    STOP_SCIENTIFIC_INVALIDITY = "STOP_SCIENTIFIC_INVALIDITY"


@dataclass(frozen=True)
class RecoveryReport:
    action: ResumeAction
    reasons: tuple[str, ...]
    ledger_valid: bool
    ledger_event_count: int
    ledger_head_hash: str | None
    artifacts_valid: bool
    artifact_issues: tuple[ArtifactIssue, ...]
    quarantined: tuple[QuarantineRecord, ...]
    checkpoint: CheckpointSelection | None
    derived_state: str | None
    confirmatory_touched: bool
    confirmatory_completed: bool
    new_study_protocol_accepted: bool = False
    replay_event_count: int = 0

    @property
    def resumable(self) -> bool:
        return self.action in {
            ResumeAction.START_FRESH,
            ResumeAction.RESUME_FROM_LEDGER,
            ResumeAction.RESUME_FROM_CHECKPOINT,
            ResumeAction.START_NEW_STUDY,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "reasons": list(self.reasons),
            "ledger_valid": self.ledger_valid,
            "ledger_event_count": self.ledger_event_count,
            "ledger_head_hash": self.ledger_head_hash,
            "artifacts_valid": self.artifacts_valid,
            "artifact_issues": [asdict(issue) for issue in self.artifact_issues],
            "quarantined": [asdict(record) for record in self.quarantined],
            "checkpoint": (
                {
                    "path": self.checkpoint.path,
                    "ledger_event_index": self.checkpoint.ledger_event_index,
                    "checkpoint": dict(self.checkpoint.checkpoint),
                }
                if self.checkpoint
                else None
            ),
            "derived_state": self.derived_state,
            "confirmatory_touched": self.confirmatory_touched,
            "confirmatory_completed": self.confirmatory_completed,
            "new_study_protocol_accepted": self.new_study_protocol_accepted,
            "replay_event_count": self.replay_event_count,
        }


class RecoveryManager:
    """Validate, quarantine, and derive a safe resume plan within one root."""

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        maximum_ledger_bytes: int = 64 * 1024**2,
        maximum_metadata_bytes: int = 16 * 1024**2,
        maximum_artifact_bytes: int = MAX_ARTIFACT_OBJECT_BYTES,
        maximum_scan_entries: int = 100_000,
        maximum_quarantine_candidates: int = 10_000,
        maximum_checkpoint_entries: int = MAX_CHECKPOINT_ENTRIES,
        maximum_checkpoint_selection_bytes: int = MAX_CHECKPOINT_SELECTION_BYTES,
        ledger_validator: Callable[[Path], LedgerValidationResult] | None = None,
        artifact_validator: Callable[[object], ArtifactValidationResult] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        root = Path(project_root)
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise RecoveryError("project_root must be an existing non-symlink directory")
        self.project_root = root.resolve()
        if self.project_root == Path(self.project_root.anchor):
            raise RecoveryError("project_root cannot be a filesystem root")
        home = Path.home().resolve()
        if self.project_root in {home, home / "dev", Path("/Users")}:
            raise RecoveryError("project_root cannot be a home or broad development directory")
        if isinstance(maximum_ledger_bytes, bool) or not isinstance(maximum_ledger_bytes, int):
            raise RecoveryError("maximum_ledger_bytes must be an integer")
        if maximum_ledger_bytes <= 0:
            raise RecoveryError("maximum_ledger_bytes must be positive")
        self.maximum_ledger_bytes = maximum_ledger_bytes
        if isinstance(maximum_metadata_bytes, bool) or not isinstance(maximum_metadata_bytes, int):
            raise RecoveryError("maximum_metadata_bytes must be an integer")
        if maximum_metadata_bytes <= 0:
            raise RecoveryError("maximum_metadata_bytes must be positive")
        self.maximum_metadata_bytes = maximum_metadata_bytes
        if isinstance(maximum_artifact_bytes, bool) or not isinstance(
            maximum_artifact_bytes, int
        ):
            raise RecoveryError("maximum_artifact_bytes must be an integer")
        if not 0 < maximum_artifact_bytes <= MAX_ARTIFACT_OBJECT_BYTES:
            raise RecoveryError("maximum_artifact_bytes exceeds the bounded registry contract")
        self.maximum_artifact_bytes = maximum_artifact_bytes
        for name, value in (
            ("maximum_scan_entries", maximum_scan_entries),
            ("maximum_quarantine_candidates", maximum_quarantine_candidates),
            ("maximum_checkpoint_entries", maximum_checkpoint_entries),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise RecoveryError(f"{name} must be a positive integer")
        self.maximum_scan_entries = maximum_scan_entries
        self.maximum_quarantine_candidates = maximum_quarantine_candidates
        self.maximum_checkpoint_entries = maximum_checkpoint_entries
        if (
            isinstance(maximum_checkpoint_selection_bytes, bool)
            or not isinstance(maximum_checkpoint_selection_bytes, int)
            or not 0
            < maximum_checkpoint_selection_bytes
            <= MAX_CHECKPOINT_SELECTION_BYTES
        ):
            raise RecoveryError(
                "maximum_checkpoint_selection_bytes must be a positive integer "
                f"no greater than {MAX_CHECKPOINT_SELECTION_BYTES}"
            )
        self.maximum_checkpoint_selection_bytes = maximum_checkpoint_selection_bytes
        self._ledger_validator = ledger_validator
        self._artifact_validator = artifact_validator
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _relative_path(self, raw_path: str | os.PathLike[str]) -> Path:
        raw = Path(raw_path)
        if any(part in {"", ".."} for part in raw.parts) or "\x00" in os.fspath(raw):
            raise RecoveryError("path traversal or malformed path is prohibited")
        if raw.is_absolute():
            try:
                relative = raw.relative_to(self.project_root)
            except ValueError as exc:
                raise RecoveryError("path escapes project_root") from exc
        else:
            relative = raw
        if not relative.parts or relative.name in {"", ".", ".."}:
            raise RecoveryError("recovery path is empty or malformed")
        return relative

    def _read_regular_bytes(
        self, path: Path, *, maximum_bytes: int
    ) -> tuple[bytes, os.stat_result]:
        """Read one immutable file identity without following links."""

        relative = self._relative_path(path)
        directory_fd: int | None = None
        descriptor: int | None = None
        try:
            directory_fd = open_confined_directory_fd(
                self.project_root, relative.parent, create=False
            )
            descriptor = os.open(
                relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise RecoveryError(f"recovery input is not a private regular file: {path}")
            if opened.st_size > maximum_bytes:
                raise RecoveryError(f"recovery input exceeds size limit: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(maximum_bytes + 1)
            after = os.fstat(descriptor)
            if len(data) > maximum_bytes:
                raise RecoveryError(f"recovery input exceeds size limit: {path}")
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RecoveryError(f"recovery input changed while being read: {path}")
            return data, opened
        except (OSError, PathSecurityError) as exc:
            raise RecoveryError(f"cannot read recovery input safely {path}: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_fd is not None:
                os.close(directory_fd)

    def validate_ledger(
        self,
        ledger_path: str | os.PathLike[str],
        *,
        _bypass_injected_validator: bool = False,
    ) -> LedgerValidationResult:
        path = self.project_root / self._relative_path(ledger_path)
        if self._ledger_validator is not None and not _bypass_injected_validator:
            result = self._ledger_validator(path)
            if not isinstance(result, LedgerValidationResult):
                raise LedgerValidationError(
                    "injected ledger validator returned an invalid result"
                )
            return result
        try:
            data, opened_info = self._read_regular_bytes(
                path, maximum_bytes=self.maximum_ledger_bytes
            )
        except RecoveryError as exc:
            return LedgerValidationResult(False, (), None, None, f"LEDGER_READ_FAILED:{exc}")
        source_sha256 = hashlib.sha256(data).hexdigest()
        if not data:
            return LedgerValidationResult(True, (), None, None, valid_prefix_bytes=0)

        lines = data.splitlines(keepends=True)
        events: list[Mapping[str, object]] = []
        event_ids: set[str] = set()
        event_hashes: set[str] = set()
        run_id: str | None = None
        previous_hash: str | None = None
        offset = 0
        for line_number, encoded in enumerate(lines, start=1):
            line_start = offset
            offset += len(encoded)
            has_terminator = encoded.endswith((b"\n", b"\r"))
            payload = encoded.rstrip(b"\r\n")
            if not payload:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "EMPTY_LEDGER_LINE",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            if len(encoded) > self.maximum_metadata_bytes:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "LEDGER_EVENT_SIZE_LIMIT_EXCEEDED",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            try:
                parsed = safe_json_loads(payload, max_bytes=self.maximum_metadata_bytes)
            except (UnicodeDecodeError, UnsafeSerializationError, ValueError, RecursionError) as exc:
                recoverable = line_number == len(lines) and not has_terminator and bool(events)
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"MALFORMED_LEDGER_JSON:{exc}",
                    line_number,
                    recoverable_truncated_tail=recoverable,
                    valid_prefix_bytes=line_start,
                    tail_bytes=len(data) - line_start,
                    source_sha256=source_sha256,
                    source_size=opened_info.st_size,
                    source_device=opened_info.st_dev,
                    source_inode=opened_info.st_ino,
                )
            if line_number == len(lines) and not has_terminator:
                # A fully parseable event without its trailing newline is
                # ambiguous, not an unambiguously partial append.  Never erase
                # a potentially irreversible confirmatory-start event.
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "AMBIGUOUS_FINAL_EVENT_WITHOUT_NEWLINE",
                    line_number,
                    recoverable_truncated_tail=False,
                    valid_prefix_bytes=line_start,
                    tail_bytes=len(data) - line_start,
                    source_sha256=source_sha256,
                    source_size=opened_info.st_size,
                    source_device=opened_info.st_dev,
                    source_inode=opened_info.st_ino,
                )
            if not isinstance(parsed, dict):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "LEDGER_EVENT_NOT_OBJECT",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            raw_claimed_hash = parsed.get("event_hash")
            if not isinstance(raw_claimed_hash, str) or not SHA256_PATTERN.fullmatch(
                raw_claimed_hash
            ):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "INVALID_EVENT_HASH",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            try:
                raw_actual_hash = event_digest(parsed)
            except (TypeError, ValueError) as exc:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"UNCANONICALIZABLE_EVENT:{exc}",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            if not hmac.compare_digest(raw_actual_hash, raw_claimed_hash):
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    "EVENT_HASH_MISMATCH",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            # The authoritative ledger model is the versioned schema contract;
            # recovery must not accept a weaker event than normal execution.
            try:
                from .ledger import LedgerEvent

                typed_event = LedgerEvent.from_dict(parsed)
                parsed = typed_event.to_dict()
            except Exception as exc:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    f"INVALID_EVENT_SCHEMA:{type(exc).__name__}",
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            event_id = typed_event.event_id
            current_run_id = typed_event.run_id
            claimed_hash = typed_event.event_hash
            prior_hash = typed_event.prior_event_hash
            if not isinstance(event_id, str) or not event_id:
                error = "MISSING_EVENT_ID"
            elif event_id in event_ids:
                error = "DUPLICATE_EVENT_ID"
            elif claimed_hash in event_hashes:
                error = "DUPLICATE_EVENT_HASH"
            elif not isinstance(current_run_id, str) or not current_run_id:
                error = "MISSING_RUN_ID"
            elif run_id is not None and current_run_id != run_id:
                error = "RUN_ID_CHANGED"
            elif not isinstance(claimed_hash, str) or not SHA256_PATTERN.fullmatch(claimed_hash):
                error = "INVALID_EVENT_HASH"
            elif line_number == 1 and prior_hash not in GENESIS_HASHES:
                error = "INVALID_GENESIS_PRIOR_HASH"
            elif line_number > 1 and prior_hash != previous_hash:
                error = "BROKEN_HASH_CHAIN"
            elif (
                typed_event.event_type == "CORRECTION"
                and typed_event.supersedes_event_id not in event_ids
            ):
                error = "INVALID_SUPERSEDED_EVENT"
            else:
                try:
                    actual_hash = event_digest(parsed)
                except (TypeError, ValueError) as exc:
                    error = f"UNCANONICALIZABLE_EVENT:{exc}"
                else:
                    error = None if hmac.compare_digest(actual_hash, claimed_hash) else "EVENT_HASH_MISMATCH"
            if error:
                return LedgerValidationResult(
                    False,
                    tuple(events),
                    previous_hash,
                    run_id,
                    error,
                    line_number,
                    valid_prefix_bytes=line_start,
                )
            event_ids.add(event_id)
            event_hashes.add(claimed_hash)
            run_id = current_run_id
            previous_hash = claimed_hash
            events.append(parsed)
        return LedgerValidationResult(
            True,
            tuple(events),
            previous_hash,
            run_id,
            valid_prefix_bytes=len(data),
        )

    def _write_sidecar(
        self,
        target: Path,
        *,
        original: str,
        reason: str,
        size: int,
        digest: str,
    ) -> Path:
        target_relative = self._relative_path(target)
        sidecar_relative = target_relative.with_name(target_relative.name + ".metadata.json")
        sidecar = self.project_root / sidecar_relative
        payload = {
            "schema_version": "1.0",
            "timestamp": self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "original_relative_path": original,
            "quarantine_relative_path": target_relative.as_posix(),
            "reason": reason,
            "size_bytes": size,
            "sha256": digest,
        }
        try:
            existing = read_confined_bytes(
                self.project_root,
                sidecar_relative,
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
                missing_ok=True,
            )
            if existing is not None:
                parsed = safe_json_loads(existing, max_bytes=self.maximum_metadata_bytes)
                if not isinstance(parsed, Mapping):
                    raise RecoveryError("quarantine sidecar is not an object")
                old_semantic = dict(parsed)
                new_semantic = dict(payload)
                old_semantic.pop("timestamp", None)
                new_semantic.pop("timestamp", None)
                if old_semantic != new_semantic:
                    raise RecoveryError("quarantine sidecar collision")
                return sidecar
            serialized = (
                json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            return atomic_write_bytes(
                self.project_root,
                sidecar_relative,
                serialized,
                immutable=True,
                create_parents=True,
            )
        except (PathSecurityError, UnsafeSerializationError) as exc:
            raise RecoveryError(f"cannot write quarantine sidecar safely: {exc}") from exc

    def _quarantine_move(
        self,
        source: Path,
        *,
        category: str,
        reason: str,
        expected_source: tuple[str, int, int, int] | None = None,
    ) -> QuarantineRecord:
        """Durably copy-verify-unlink one source using pinned directory fds.

        The immutable copy and sidecar name are content/path deterministic.
        A retry verifies an existing copy before removing the still-pinned
        source, so every crash point is fail-closed and idempotent.
        """

        source_relative = self._relative_path(source)
        destination_relative = Path(".scientist-one-build") / "quarantine" / category
        secure_directory(self.project_root, destination_relative, create=True)
        try:
            source_fd = open_confined_directory_fd(
                self.project_root, source_relative.parent, create=False
            )
            destination_fd = open_confined_directory_fd(
                self.project_root, destination_relative, create=False
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"confined quarantine path is unsafe: {exc}") from exc
        file_descriptor: int | None = None
        try:
            file_descriptor = os.open(
                source_relative.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            info = os.fstat(file_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RecoveryError("incomplete source is not a recoverable regular file")
            if info.st_size > self.maximum_artifact_bytes:
                raise RecoveryError("incomplete source exceeds the bounded quarantine contract")
            digest_state = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                digest_state.update(chunk)
            digest = digest_state.hexdigest()
            if expected_source is not None and (
                digest,
                info.st_size,
                info.st_dev,
                info.st_ino,
            ) != expected_source:
                raise RecoveryError(
                    "incomplete source differs from the validated repair input"
                )
            source_key = hashlib.sha256(source_relative.as_posix().encode("utf-8")).hexdigest()
            destination_name = (
                f"{source_relative.name}.{source_key[:12]}.{digest[:16]}.quarantine"
            )
            target_relative = destination_relative / destination_name
            try:
                target_info = os.stat(
                    destination_name, dir_fd=destination_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                target_info = None
            if target_info is not None and (
                not stat.S_ISREG(target_info.st_mode)
                or target_info.st_nlink != 1
                or target_info.st_size != info.st_size
            ):
                raise RecoveryError("quarantine destination collision")
            sidecar = self._write_sidecar(
                self.project_root / target_relative,
                original=source_relative.as_posix(),
                reason=reason,
                size=info.st_size,
                digest=digest,
            )
            current = os.stat(source_relative.name, dir_fd=source_fd, follow_symlinks=False)
            if (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            ) != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ):
                raise RecoveryError("incomplete source changed before quarantine")
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            final_digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                final_digest.update(chunk)
            final_info = os.fstat(file_descriptor)
            if (
                final_digest.hexdigest() != digest
                or final_info.st_size != info.st_size
                or final_info.st_mtime_ns != info.st_mtime_ns
                or final_info.st_ctime_ns != info.st_ctime_ns
            ):
                raise RecoveryError("incomplete source changed while quarantine was prepared")
            target_descriptor: int | None = None
            try:
                if target_info is None:
                    target_descriptor = os.open(
                        destination_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=destination_fd,
                    )
                    os.lseek(file_descriptor, 0, os.SEEK_SET)
                    copied_digest = hashlib.sha256()
                    copied_size = 0
                    while chunk := os.read(file_descriptor, 1024 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_descriptor, view)
                            if written <= 0:
                                raise OSError("short quarantine copy")
                            view = view[written:]
                        copied_digest.update(chunk)
                        copied_size += len(chunk)
                    os.fsync(target_descriptor)
                    if copied_size != info.st_size or copied_digest.hexdigest() != digest:
                        raise RecoveryError("source changed during quarantine copy")
                else:
                    target_descriptor = os.open(
                        destination_name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=destination_fd,
                    )
                    copied_digest = hashlib.sha256()
                    copied_size = 0
                    while chunk := os.read(target_descriptor, 1024 * 1024):
                        copied_digest.update(chunk)
                        copied_size += len(chunk)
                    if copied_size != info.st_size or copied_digest.hexdigest() != digest:
                        raise RecoveryError("existing quarantine copy is corrupt")
            finally:
                if target_descriptor is not None:
                    os.close(target_descriptor)
            os.fsync(destination_fd)
            current = os.stat(source_relative.name, dir_fd=source_fd, follow_symlinks=False)
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            source_digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, 1024 * 1024):
                source_digest.update(chunk)
            if (
                (current.st_dev, current.st_ino, current.st_size)
                != (info.st_dev, info.st_ino, info.st_size)
                or source_digest.hexdigest() != digest
            ):
                raise RecoveryError("incomplete source changed before final unlink")
            os.unlink(source_relative.name, dir_fd=source_fd)
            os.fsync(source_fd)
            os.fsync(destination_fd)
            return QuarantineRecord(
                source_relative.as_posix(),
                target_relative.as_posix(),
                reason,
                info.st_size,
                digest,
                self._relative_path(sidecar).as_posix(),
            )
        except (OSError, PathSecurityError) as exc:
            if isinstance(exc, RecoveryError):
                raise
            raise RecoveryError(f"confined quarantine move failed: {exc}") from exc
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(source_fd)
            os.close(destination_fd)

    def _open_ledger_lock(self, path: Path) -> int:
        if fcntl is None:
            raise LedgerValidationError("safe ledger locking is unavailable")
        relative = self._relative_path(path)
        directory_descriptor: int | None = None
        lock_descriptor: int | None = None
        try:
            directory_descriptor = open_confined_directory_fd(
                self.project_root,
                relative.parent,
                create=False,
            )
            lock_name = f".{relative.name}.lock"
            lock_descriptor = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            info = os.fstat(lock_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LedgerValidationError("ledger lock is not a private regular file")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            return lock_descriptor
        except (OSError, LedgerValidationError) as exc:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            if isinstance(exc, LedgerValidationError):
                raise
            raise LedgerValidationError(f"cannot acquire ledger repair lock: {exc}") from exc
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)

    @staticmethod
    def _close_ledger_lock(descriptor: int) -> None:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    def repair_truncated_ledger(
        self, ledger_path: str | os.PathLike[str], result: LedgerValidationResult | None = None
    ) -> tuple[LedgerValidationResult, QuarantineRecord]:
        path = self.project_root / self._relative_path(ledger_path)
        # An injected validator may itself use EventLedger and therefore the
        # same per-ledger flock.  Invoke it before taking the repair lock, then
        # compare its complete observation with an intrinsic validation made
        # under the lock.  Any intervening write changes that intrinsic
        # signature and fails closed without recursively acquiring the lock.
        reported = self.validate_ledger(path)
        lock_descriptor = self._open_ledger_lock(path)
        try:
            intrinsic = self.validate_ledger(
                path, _bypass_injected_validator=True
            )
            if (
                not reported.recoverable_truncated_tail
                or not intrinsic.recoverable_truncated_tail
            ):
                raise LedgerValidationError(
                    "ledger no longer has an unambiguously truncated final append"
                )
            if result is not None:
                expected_signature = (
                    result.event_count,
                    result.head_hash,
                    result.run_id,
                    result.error,
                    result.error_line,
                    result.recoverable_truncated_tail,
                    result.valid_prefix_bytes,
                    result.tail_bytes,
                )
                reported_signature = (
                    reported.event_count,
                    reported.head_hash,
                    reported.run_id,
                    reported.error,
                    reported.error_line,
                    reported.recoverable_truncated_tail,
                    reported.valid_prefix_bytes,
                    reported.tail_bytes,
                )
                if expected_signature != reported_signature:
                    raise LedgerValidationError(
                        "ledger changed after validation; stale repair result rejected"
                    )
            if (
                reported.event_count,
                reported.head_hash,
                reported.run_id,
                reported.valid_prefix_bytes,
            ) != (
                intrinsic.event_count,
                intrinsic.head_hash,
                intrinsic.run_id,
                intrinsic.valid_prefix_bytes,
            ) or tuple(reported.events) != tuple(intrinsic.events):
                raise LedgerValidationError(
                    "ledger validators disagree on the recoverable prefix"
                )
            # The injected validator is authoritative only for ledger-event
            # semantics.  Some adapters intentionally do not materialize raw
            # tail bytes or source identity.  The intrinsic validation and
            # descriptor-bound read made under this repair lock remain the
            # sole authority for those file-level facts.
            validation = intrinsic
            data, info = self._read_regular_bytes(
                path, maximum_bytes=self.maximum_ledger_bytes
            )
            digest = hashlib.sha256(data).hexdigest()
            intrinsic_source = (
                intrinsic.source_sha256,
                intrinsic.source_size,
                intrinsic.source_device,
                intrinsic.source_inode,
            )
            if any(value is None for value in intrinsic_source):
                raise LedgerValidationError(
                    "intrinsic ledger validation omitted source identity"
                )
            if (digest, len(data), info.st_dev, info.st_ino) != intrinsic_source:
                raise LedgerValidationError(
                    "ledger identity or content changed after intrinsic validation"
                )
            if result is not None and result.source_sha256 is not None:
                if (
                    digest != result.source_sha256
                    or len(data) != result.source_size
                    or info.st_dev != result.source_device
                    or info.st_ino != result.source_inode
                ):
                    raise LedgerValidationError(
                        "ledger identity or content changed after validation"
                    )
            if validation.valid_prefix_bytes <= 0:
                raise LedgerValidationError("cannot repair a ledger with no valid event prefix")
            record = self._quarantine_move(
                path,
                category="ledger",
                reason="TRUNCATED_FINAL_LEDGER_APPEND",
                expected_source=(digest, len(data), info.st_dev, info.st_ino),
            )
            try:
                atomic_write_bytes(
                    self.project_root,
                    self._relative_path(path),
                    data[: validation.valid_prefix_bytes],
                    immutable=True,
                    create_parents=False,
                )
            except PathSecurityError as exc:
                raise LedgerValidationError(
                    f"cannot restore validated ledger prefix safely: {exc}"
                ) from exc
            repaired_intrinsic = self.validate_ledger(
                path, _bypass_injected_validator=True
            )
            if not repaired_intrinsic.valid:
                raise LedgerValidationError(
                    "repaired ledger prefix is invalid: "
                    f"{repaired_intrinsic.error}"
                )
        finally:
            self._close_ledger_lock(lock_descriptor)
        # Reapply any injected semantic validator only after releasing the
        # repair lock.  A legitimate concurrent append may extend the repaired
        # prefix, but it may not replace or alter that prefix.
        repaired = self.validate_ledger(path)
        if (
            not repaired.valid
            or repaired.run_id != repaired_intrinsic.run_id
            or repaired.event_count < repaired_intrinsic.event_count
            or tuple(repaired.events[: repaired_intrinsic.event_count])
            != tuple(repaired_intrinsic.events)
        ):
            raise LedgerValidationError(
                f"repaired ledger failed final validation: {repaired.error}"
            )
        return repaired, record

    def _load_artifact_records(self, registry: object) -> list[Mapping[str, object]]:
        try:
            from .artifacts import ArtifactRegistry
        except ImportError:  # pragma: no cover - package-internal dependency
            ArtifactRegistry = ()  # type: ignore[assignment,misc]
        if isinstance(registry, ArtifactRegistry):
            try:
                raw = [record.to_dict() for record in registry.list_records()]
            except Exception as exc:
                raise ArtifactValidationError(
                    f"artifact registry verification failed: {exc}"
                ) from exc
        elif isinstance(registry, (str, os.PathLike)):
            try:
                encoded = read_confined_bytes(
                    self.project_root,
                    self._relative_path(registry),
                    reject_hardlinks=True,
                    max_bytes=self.maximum_metadata_bytes,
                )
                if encoded is None:
                    raise PathSecurityError("artifact registry is absent")
                text = encoded.decode("utf-8")
            except (PathSecurityError, UnicodeDecodeError) as exc:
                raise ArtifactValidationError(f"cannot read artifact registry: {exc}") from exc
            try:
                raw = safe_json_loads(text, max_bytes=self.maximum_metadata_bytes)
            except (UnsafeSerializationError, ValueError, RecursionError):
                raw = []
                for number, line in enumerate(text.splitlines(), start=1):
                    if not line.strip():
                        raise ArtifactValidationError(f"empty artifact registry line {number}")
                    try:
                        raw.append(
                            safe_json_loads(line, max_bytes=self.maximum_metadata_bytes)
                        )
                    except (UnsafeSerializationError, ValueError, RecursionError) as exc:
                        raise ArtifactValidationError(
                            f"malformed artifact registry line {number}: {exc}"
                        ) from exc
        else:
            raw = registry
        if isinstance(raw, Mapping) and "artifacts" in raw:
            raw = raw["artifacts"]
        elif isinstance(raw, Mapping):
            raw = [raw]
        if (
            not isinstance(raw, list)
            or len(raw) > MAX_REGISTRY_RECORDS
            or any(not isinstance(item, Mapping) for item in raw)
        ):
            raise ArtifactValidationError("artifact registry must contain object records")
        return list(raw)

    def validate_artifacts(self, registry: object) -> ArtifactValidationResult:
        if self._artifact_validator is not None:
            result = self._artifact_validator(registry)
            if not isinstance(result, ArtifactValidationResult):
                issue = ArtifactIssue(
                    -1,
                    None,
                    "ARTIFACT_VALIDATOR_INVALID_RESULT",
                    "injected artifact validator returned an invalid result",
                    True,
                )
                return ArtifactValidationResult(False, 0, (), (issue,))
            return result
        try:
            records = self._load_artifact_records(registry)
        except (ArtifactValidationError, RecoveryError) as exc:
            issue = ArtifactIssue(-1, None, "REGISTRY_INVALID", str(exc), True)
            return ArtifactValidationResult(False, 0, (), (issue,))
        issues: list[ArtifactIssue] = []
        validated = 0
        seen_paths: set[Path] = set()
        for index, record in enumerate(records):
            if (
                "path" in record
                and "relative_path" in record
                and record.get("path") != record.get("relative_path")
            ):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(record.get("path")),
                        "AMBIGUOUS_PATH_FIELDS",
                        "path and relative_path disagree",
                        True,
                    )
                )
                continue
            if (
                "sha256" in record
                and "hash" in record
                and record.get("sha256") != record.get("hash")
            ):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(record.get("path", record.get("relative_path"))),
                        "AMBIGUOUS_HASH_FIELDS",
                        "sha256 and hash disagree",
                        True,
                    )
                )
                continue
            raw_path = record.get("path", record.get("relative_path"))
            expected = record.get("sha256", record.get("hash"))
            raw_frozen = record.get("frozen", False)
            if not isinstance(raw_frozen, bool):
                issues.append(
                    ArtifactIssue(
                        index,
                        str(raw_path) if raw_path is not None else None,
                        "INVALID_FROZEN_FLAG",
                        "frozen must be boolean",
                        True,
                    )
                )
                continue
            frozen = raw_frozen
            display = str(raw_path) if raw_path is not None else None
            if not isinstance(raw_path, str) or not raw_path:
                issues.append(ArtifactIssue(index, display, "MISSING_PATH", "path is required", frozen))
                continue
            if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
                issues.append(
                    ArtifactIssue(index, display, "INVALID_SHA256", "sha256 is required", frozen)
                )
                continue
            try:
                relative = self._relative_path(raw_path)
                content = read_confined_bytes(
                    self.project_root,
                    relative,
                    reject_hardlinks=True,
                    max_bytes=self.maximum_artifact_bytes,
                )
                if content is None:
                    raise PathSecurityError("artifact is absent")
            except (RecoveryError, PathSecurityError) as exc:
                issues.append(ArtifactIssue(index, display, "UNSAFE_OR_MISSING_PATH", str(exc), frozen))
                continue
            if relative in seen_paths:
                issues.append(
                    ArtifactIssue(
                        index,
                        display,
                        "DUPLICATE_ARTIFACT_PATH",
                        "artifact path appears more than once",
                        frozen,
                    )
                )
                continue
            seen_paths.add(relative)
            declared_size = record.get("size", record.get("size_bytes"))
            if declared_size is not None:
                if isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size < 0:
                    issues.append(
                        ArtifactIssue(index, display, "INVALID_SIZE", "declared size is invalid", frozen)
                    )
                    continue
                if len(content) != declared_size:
                    issues.append(
                        ArtifactIssue(
                            index,
                            display,
                            "SIZE_MISMATCH",
                            f"expected {declared_size}, found {len(content)}",
                            frozen,
                        )
                    )
                    continue
            actual = hashlib.sha256(content).hexdigest()
            if not hmac.compare_digest(actual, expected):
                issues.append(
                    ArtifactIssue(index, display, "HASH_MISMATCH", f"expected {expected}, found {actual}", frozen)
                )
                continue
            validated += 1
        return ArtifactValidationResult(not issues, validated, tuple(records), tuple(issues))

    def _scan_incomplete(self, roots: Sequence[str | os.PathLike[str]]) -> list[Path]:
        found: list[Path] = []
        scanned_entries = 0
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        quarantine_relative = Path(".scientist-one-build/quarantine")
        for raw_root in roots:
            relative_root = self._relative_path(raw_root)
            try:
                current_fd = os.open(self.project_root, flags)
            except OSError as exc:
                raise RecoveryError("cannot pin project root for incomplete scan") from exc
            missing = False
            try:
                for component in relative_root.parts:
                    try:
                        next_fd = os.open(component, flags, dir_fd=current_fd)
                    except FileNotFoundError:
                        missing = True
                        break
                    except OSError as exc:
                        raise RecoveryError(
                            "incomplete-write scan root contains a link or non-directory"
                        ) from exc
                    os.close(current_fd)
                    current_fd = next_fd
                if missing:
                    continue
                stack: list[tuple[int, Path]] = [(current_fd, relative_root)]
                current_fd = -1
                try:
                    while stack:
                        directory_fd, directory_relative = stack.pop()
                        try:
                            try:
                                directory_relative.relative_to(quarantine_relative)
                            except ValueError:
                                pass
                            else:
                                continue
                            with os.scandir(directory_fd) as entries:
                                names = (entry.name for entry in entries)
                                for name in names:
                                    scanned_entries += 1
                                    if scanned_entries > self.maximum_scan_entries:
                                        raise RecoveryError(
                                            "incomplete-write scan entry limit exceeded"
                                        )
                                    if name in {"", ".", ".."} or "/" in name:
                                        raise RecoveryError(
                                            "incomplete-write tree contains an unsafe name"
                                        )
                                    try:
                                        info = os.stat(
                                            name, dir_fd=directory_fd, follow_symlinks=False
                                        )
                                    except OSError as exc:
                                        raise RecoveryError(
                                            f"cannot inspect incomplete-write entry: {exc}"
                                        ) from exc
                                    child_relative = directory_relative / name
                                    if stat.S_ISDIR(info.st_mode):
                                        try:
                                            child_fd = os.open(name, flags, dir_fd=directory_fd)
                                        except OSError as exc:
                                            raise RecoveryError(
                                                "incomplete-write directory changed or is unsafe"
                                            ) from exc
                                        stack.append((child_fd, child_relative))
                                    elif stat.S_ISREG(info.st_mode):
                                        if name.endswith(INCOMPLETE_SUFFIXES) or ".tmp." in name:
                                            found.append(self.project_root / child_relative)
                                            if len(found) > self.maximum_quarantine_candidates:
                                                raise RecoveryError(
                                                    "incomplete-write candidate limit exceeded"
                                                )
                                    elif stat.S_ISLNK(info.st_mode):
                                        continue
                                    else:
                                        raise RecoveryError(
                                            "incomplete-write tree contains a special file"
                                        )
                        finally:
                            os.close(directory_fd)
                finally:
                    for pending_fd, _ in stack:
                        os.close(pending_fd)
            finally:
                if current_fd >= 0:
                    os.close(current_fd)
        return found

    def quarantine_incomplete(
        self,
        candidates: Sequence[str | os.PathLike[str]] | None = None,
        *,
        scan_roots: Sequence[str | os.PathLike[str]] = (
            "artifacts",
            "runs",
            ".scientist-one-build/checkpoints",
        ),
        protected_paths: Iterable[str | os.PathLike[str]] = (),
    ) -> tuple[QuarantineRecord, ...]:
        paths = (
            [self.project_root / self._relative_path(item) for item in candidates]
            if candidates is not None
            else self._scan_incomplete(scan_roots)
        )
        if len(paths) > self.maximum_quarantine_candidates:
            raise RecoveryError("incomplete-write candidate limit exceeded")
        protected = {self._relative_path(item) for item in protected_paths}
        records: list[QuarantineRecord] = []
        for path in paths:
            relative_path = self._relative_path(path)
            name = relative_path.name
            if not (name.endswith(INCOMPLETE_SUFFIXES) or ".tmp." in name):
                raise RecoveryError(
                    "explicit quarantine candidates require a recognized incomplete-write name"
                )
            if relative_path in protected:
                # A registered, hash-valid artifact is authoritative evidence,
                # even if its producer chose an unfortunate temporary suffix.
                if candidates is not None:
                    raise RecoveryError(
                        "authoritative recovery input cannot be quarantined explicitly"
                    )
                continue
            try:
                records.append(
                    self._quarantine_move(
                        self.project_root / relative_path,
                        category="partial",
                        reason="INCOMPLETE_WRITE",
                    )
                )
            except RecoveryError as exc:
                # Missing auto-discovered files are an ordinary concurrent
                # cleanup.  Explicit candidates are authoritative requests and
                # must fail closed when absent or unsafe.
                if candidates is None and "No such file" in str(exc):
                    continue
                raise
        return tuple(records)

    def create_checkpoint(
        self,
        payload: Mapping[str, object],
        *,
        checkpoint_dir: str | os.PathLike[str] = ".scientist-one-build/checkpoints",
    ) -> Path:
        required = ("run_id", "event_id", "ledger_head_hash", "state")
        if any(not isinstance(payload.get(key), str) or not payload.get(key) for key in required):
            raise RecoveryError(f"checkpoint requires non-empty fields: {', '.join(required)}")
        allowed_payload = {
            "schema_version",
            "checkpoint_id",
            "run_id",
            "event_id",
            "ledger_head_hash",
            "state",
            "artifact_hashes",
            "artifact_record_hashes",
            "resource_runtime_artifact",
            "created_at",
            "checkpoint_hash",
        }
        if any(not isinstance(key, str) or key not in allowed_payload for key in payload):
            raise RecoveryError("checkpoint contains unsupported or inline mutable state")
        if not SHA256_PATTERN.fullmatch(str(payload["ledger_head_hash"])):
            raise RecoveryError("checkpoint ledger_head_hash must be SHA-256")
        data = dict(payload)
        data.setdefault("schema_version", CURRENT_CHECKPOINT_SCHEMA)
        if data["schema_version"] != CURRENT_CHECKPOINT_SCHEMA:
            raise RecoveryError("unsupported checkpoint schema_version")
        data.setdefault("checkpoint_id", f"{payload['event_id']}-{str(payload['ledger_head_hash'])[:12]}")
        data.setdefault("artifact_hashes", {})
        data.setdefault("artifact_record_hashes", {})
        data.setdefault("resource_runtime_artifact", None)
        artifact_hashes = data["artifact_hashes"]
        artifact_record_hashes = data["artifact_record_hashes"]
        if not isinstance(artifact_hashes, Mapping) or not isinstance(
            artifact_record_hashes, Mapping
        ):
            raise RecoveryError("checkpoint artifact bindings must be logical-type maps")
        if set(artifact_hashes) != set(artifact_record_hashes):
            raise RecoveryError("checkpoint artifact binding keysets disagree")
        for logical_type, digest in artifact_hashes.items():
            if (
                not isinstance(logical_type, str)
                or not logical_type
                or not isinstance(digest, str)
                or not SHA256_PATTERN.fullmatch(digest)
                or not isinstance(artifact_record_hashes[logical_type], str)
                or not SHA256_PATTERN.fullmatch(str(artifact_record_hashes[logical_type]))
            ):
                raise RecoveryError("checkpoint artifact bindings are malformed")
        resource_name = data["resource_runtime_artifact"]
        if resource_name is not None and (
            not isinstance(resource_name, str)
            or not resource_name.startswith("resource_runtime_")
            or resource_name not in artifact_hashes
        ):
            raise RecoveryError("checkpoint resource runtime pointer is not artifact-bound")
        data.pop("checkpoint_hash", None)
        directory_relative = self._relative_path(checkpoint_dir)
        try:
            secure_directory(self.project_root, directory_relative, create=True)
        except PathSecurityError as exc:
            raise RecoveryError(f"checkpoint directory is unsafe: {exc}") from exc
        name = str(data["checkpoint_id"])
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise RecoveryError("checkpoint_id contains unsafe characters")
        destination_relative = directory_relative / f"{name}.json"
        destination = self.project_root / destination_relative
        try:
            existing_bytes = read_confined_bytes(
                self.project_root,
                destination_relative,
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
                missing_ok=True,
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"existing checkpoint cannot be read safely: {exc}") from exc
        if existing_bytes is not None:
            try:
                existing = safe_json_loads(
                    existing_bytes, max_bytes=self.maximum_metadata_bytes
                )
            except (UnsafeSerializationError, ValueError) as exc:
                raise RecoveryError(f"existing checkpoint is invalid: {exc}") from exc
            if not isinstance(existing, Mapping):
                raise RecoveryError("existing checkpoint is not a JSON object")
            existing_hash = existing.get("checkpoint_hash")
            if (
                not isinstance(existing_hash, str)
                or not SHA256_PATTERN.fullmatch(existing_hash)
                or not hmac.compare_digest(checkpoint_digest(existing), existing_hash)
            ):
                raise RecoveryError("existing checkpoint hash is invalid")
            semantic_existing = dict(existing)
            semantic_existing.pop("checkpoint_hash", None)
            if "created_at" not in data:
                semantic_existing.pop("created_at", None)
            if semantic_existing == data:
                return destination
            raise RecoveryError("checkpoint is immutable and already exists with different content")
        data.setdefault(
            "created_at", self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        try:
            data["checkpoint_hash"] = checkpoint_digest(data)
        except (TypeError, ValueError) as exc:
            raise RecoveryError(f"checkpoint is not canonical JSON data: {exc}") from exc
        try:
            serialized = (
                json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            return atomic_write_bytes(
                self.project_root,
                destination_relative,
                serialized,
                immutable=True,
                create_parents=False,
            )
        except PathSecurityError as exc:
            raise RecoveryError(f"checkpoint cannot be published safely: {exc}") from exc

    def select_checkpoint(
        self,
        checkpoint_dir: str | os.PathLike[str],
        ledger: LedgerValidationResult,
        artifacts: ArtifactValidationResult | None = None,
    ) -> CheckpointSelection | None:
        if not ledger.valid:
            raise LedgerValidationError("cannot select a checkpoint before ledger validation")
        directory_relative = self._relative_path(checkpoint_dir)
        event_index = {
            str(event["event_id"]): (index, str(event["event_hash"]), event)
            for index, event in enumerate(ledger.events)
        }
        known_artifact_hashes = {
            str(record.get("sha256", record.get("hash")))
            for record in (artifacts.records if artifacts else ())
            if isinstance(record.get("sha256", record.get("hash")), str)
        }
        known_record_hashes = {
            str(record.get("sha256", record.get("hash"))): record.get(
                "record_hash", record.get("registry_record_hash")
            )
            for record in (artifacts.records if artifacts else ())
            if isinstance(record.get("sha256", record.get("hash")), str)
        }
        selected: CheckpointSelection | None = None
        selected_semantic: Mapping[str, object] | None = None
        selected_conflict = False
        def checkpoint_stream():
            try:
                directory_fd = open_confined_directory_fd(
                    self.project_root, directory_relative, create=False
                )
            except PathSecurityError:
                return
            try:
                try:
                    checkpoint_names_list: list[str] = []
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            if len(checkpoint_names_list) >= self.maximum_checkpoint_entries:
                                raise RecoveryError(
                                    "checkpoint directory entry count exceeds safety limit"
                                )
                            checkpoint_names_list.append(entry.name)
                    checkpoint_names = tuple(sorted(checkpoint_names_list))
                except RecoveryError:
                    raise
                except OSError as exc:
                    raise RecoveryError(f"cannot enumerate checkpoints: {exc}") from exc

                # Admit the complete bounded workload before reading or retaining
                # any checkpoint body.  Metadata is small and the name count is
                # independently capped; checkpoint bytes are then streamed one
                # held descriptor at a time.
                checkpoint_entries: list[tuple[str, os.stat_result]] = []
                aggregate_bytes = 0
                for name in checkpoint_names:
                    if Path(name).suffix != ".json":
                        continue
                    try:
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        raise RecoveryError(
                            "checkpoint entry cannot be inspected safely"
                        ) from exc
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RecoveryError(
                            "checkpoint directory contains an unsafe JSON entry"
                        )
                    if info.st_size > self.maximum_metadata_bytes:
                        raise RecoveryError("checkpoint entry exceeds its per-file bound")
                    if (
                        aggregate_bytes
                        > self.maximum_checkpoint_selection_bytes - info.st_size
                    ):
                        raise RecoveryError(
                            "checkpoint selection exceeds its aggregate byte bound"
                        )
                    aggregate_bytes += info.st_size
                    checkpoint_entries.append((name, info))

                for name, info in checkpoint_entries:
                    descriptor: int | None = None
                    try:
                        descriptor = os.open(
                            name,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                        opened = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or (opened.st_dev, opened.st_ino)
                            != (info.st_dev, info.st_ino)
                            or opened.st_size != info.st_size
                        ):
                            raise RecoveryError("checkpoint entry changed after admission")
                        chunks: list[bytes] = []
                        total = 0
                        while True:
                            chunk = os.read(
                                descriptor,
                                min(
                                    1024 * 1024,
                                    self.maximum_metadata_bytes - total + 1,
                                ),
                            )
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > self.maximum_metadata_bytes:
                                raise RecoveryError(
                                    "checkpoint exceeds metadata size limit"
                                )
                            chunks.append(chunk)
                        after = os.fstat(descriptor)
                        if (
                            total != opened.st_size
                            or (
                                opened.st_size,
                                opened.st_mtime_ns,
                                opened.st_ctime_ns,
                            )
                            != (
                                after.st_size,
                                after.st_mtime_ns,
                                after.st_ctime_ns,
                            )
                        ):
                            raise RecoveryError("checkpoint changed while being read")
                        yield name, b"".join(chunks)
                    except OSError as exc:
                        raise RecoveryError("checkpoint cannot be opened safely") from exc
                    finally:
                        if descriptor is not None:
                            os.close(descriptor)
            finally:
                os.close(directory_fd)

        expected_schema_fields = {
            "schema_version",
            "checkpoint_id",
            "run_id",
            "event_id",
            "ledger_head_hash",
            "state",
            "artifact_hashes",
            "artifact_record_hashes",
            "resource_runtime_artifact",
            "created_at",
            "checkpoint_hash",
        }
        stream = checkpoint_stream()
        try:
            for name, encoded in stream:
                if Path(name).suffix != ".json":
                    continue
                try:
                    checkpoint = safe_json_loads(
                        encoded, max_bytes=self.maximum_metadata_bytes
                    )
                    if not isinstance(checkpoint, dict):
                        continue
                    checkpoint_fields = set(checkpoint)
                    if checkpoint_fields != expected_schema_fields:
                        continue
                    if checkpoint.get("schema_version") != CURRENT_CHECKPOINT_SCHEMA:
                        continue
                    claimed = checkpoint.get("checkpoint_hash")
                    if not isinstance(claimed, str) or not SHA256_PATTERN.fullmatch(claimed):
                        continue
                    if not hmac.compare_digest(checkpoint_digest(checkpoint), claimed):
                        continue
                    event_id = checkpoint.get("event_id", checkpoint.get("ledger_event_id"))
                    head_hash = checkpoint.get("ledger_head_hash", checkpoint.get("ledger_event_hash"))
                    if checkpoint.get("run_id") != ledger.run_id:
                        continue
                    if not isinstance(event_id, str) or not event_id:
                        continue
                    if not isinstance(head_hash, str) or not SHA256_PATTERN.fullmatch(head_hash):
                        continue
                    if not isinstance(checkpoint.get("state"), str) or not checkpoint.get("state"):
                        continue
                    hash_fields_valid = True
                    for key, value in checkpoint.items():
                        if key.endswith("_hash") and key not in {"checkpoint_hash"}:
                            if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                                hash_fields_valid = False
                                break
                    if not hash_fields_valid:
                        continue
                    references = checkpoint.get("artifact_hashes")
                    checkpoint_record_hashes = checkpoint.get("artifact_record_hashes")
                    if not isinstance(references, Mapping) or not isinstance(
                        checkpoint_record_hashes, Mapping
                    ):
                        continue
                    if set(references) != set(checkpoint_record_hashes):
                        continue
                    if any(
                        not isinstance(key, str)
                        or not key
                        or not isinstance(value, str)
                        or not SHA256_PATTERN.fullmatch(value)
                        or not isinstance(checkpoint_record_hashes[key], str)
                        or not SHA256_PATTERN.fullmatch(str(checkpoint_record_hashes[key]))
                        for key, value in references.items()
                    ):
                        continue
                    resource_name = checkpoint.get("resource_runtime_artifact")
                    if resource_name is not None and (
                        not isinstance(resource_name, str)
                        or not resource_name.startswith("resource_runtime_")
                        or resource_name not in references
                    ):
                        continue
                    if event_id not in event_index:
                        raise LedgerValidationError(
                            "a valid same-run checkpoint references an event absent from the "
                            "validated ledger; refusing a possible ledger rollback"
                        )
                    index, actual_hash, bound_event = event_index[event_id]
                    if not hmac.compare_digest(head_hash, actual_hash):
                        raise LedgerValidationError(
                            "a valid same-run checkpoint conflicts with the validated ledger "
                            "head; refusing a possible ledger rewrite"
                        )
                    expected_state = self._derived_state((bound_event,))
                    if expected_state is None or checkpoint.get("state") != expected_state:
                        continue
                    referenced_hashes = tuple(references.values())
                    if artifacts is not None and any(
                        value not in known_artifact_hashes for value in referenced_hashes
                    ):
                        continue
                    projected_hashes: dict[str, str] = {}
                    projected_record_hashes: dict[str, str] = {}
                    projection_valid = True
                    for event in ledger.events[: index + 1]:
                        event_hashes = event.get("artifact_hashes")
                        if not isinstance(event_hashes, (list, tuple)):
                            projection_valid = False
                            break
                        if not event_hashes:
                            continue
                        metadata = event.get("metadata")
                        artifact_types = (
                            metadata.get("artifact_types")
                            if isinstance(metadata, Mapping)
                            else None
                        )
                        record_hashes = (
                            metadata.get("artifact_record_hashes")
                            if isinstance(metadata, Mapping)
                            else None
                        )
                        if (
                            not isinstance(artifact_types, (list, tuple))
                            or not isinstance(record_hashes, (list, tuple))
                            or len(artifact_types) != len(event_hashes)
                            or len(record_hashes) != len(event_hashes)
                            or len(set(artifact_types)) != len(artifact_types)
                        ):
                            projection_valid = False
                            break
                        for logical_type, digest, record_hash in zip(
                            artifact_types, event_hashes, record_hashes, strict=True
                        ):
                            if (
                                not isinstance(logical_type, str)
                                or not logical_type
                                or not isinstance(digest, str)
                                or not SHA256_PATTERN.fullmatch(digest)
                                or not isinstance(record_hash, str)
                                or not SHA256_PATTERN.fullmatch(record_hash)
                                or artifacts is None
                                or known_record_hashes.get(digest) != record_hash
                            ):
                                projection_valid = False
                                break
                            projected_hashes[logical_type] = digest
                            projected_record_hashes[logical_type] = record_hash
                        if not projection_valid:
                            break
                    if (
                        not projection_valid
                        or dict(references) != projected_hashes
                        or dict(checkpoint_record_hashes) != projected_record_hashes
                    ):
                        continue
                    candidate = CheckpointSelection(
                        (directory_relative / name).as_posix(), checkpoint, index
                    )
                    semantic = dict(checkpoint)
                    for key in ("checkpoint_id", "checkpoint_hash", "created_at"):
                        semantic.pop(key, None)
                    if selected is None or index > selected.ledger_event_index:
                        selected = candidate
                        selected_semantic = semantic
                        selected_conflict = False
                    elif index == selected.ledger_event_index:
                        if semantic != selected_semantic:
                            selected_conflict = True
                except (
                    OSError,
                    PathSecurityError,
                    UnsafeSerializationError,
                    UnicodeDecodeError,
                    TypeError,
                    ValueError,
                ):
                    continue
        finally:
            stream.close()
        if selected is None:
            return None
        if selected_conflict:
            raise RecoveryError("multiple checkpoints ambiguously bind the same ledger event")
        return selected

    @staticmethod
    def _event_labels(event: Mapping[str, object]) -> set[str]:
        labels: set[str] = set()
        for key in (
            "stage",
            "state",
            "state_before",
            "state_after",
            "requested_state_after",
            "source_state",
            "destination_state",
            "event_type",
            "action",
            "status",
        ):
            value = event.get(key)
            if isinstance(value, str):
                labels.add(value.upper())
        return labels

    @staticmethod
    def _validate_custody_mapping(custody: Mapping[str, object] | None) -> None:
        if custody is None:
            return
        for key in ("access_count", "authorized_access_count", "holdout_access_count"):
            if key in custody:
                value = custody[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise RecoveryError(f"custody {key} must be a non-negative integer")
        for key in (
            "released",
            "revealed",
            "invalidated",
            "confirmatory_claims_valid",
            "confirmatory_completed",
        ):
            if key in custody and not isinstance(custody[key], bool):
                raise RecoveryError(f"custody {key} must be boolean")
        for key in (
            "protocol_hash",
            "holdout_identity_hash",
            "split_manifest_hash",
            "seal_hash",
            "journal_head_hash",
            "journal_identity_sha256",
        ):
            if key in custody:
                value = custody[key]
                if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
                    raise RecoveryError(f"custody {key} must be SHA-256")

    def _confirmatory_status(
        self,
        events: Sequence[Mapping[str, object]],
        custody: Mapping[str, object] | None,
    ) -> tuple[bool, bool]:
        touched = False
        completed = False
        for event in events:
            labels = self._event_labels(event)
            if any(
                label == "CONFIRMATORY_RUN"
                or label.startswith("CONFIRMATORY_")
                or label in {"HOLDOUT_RELEASE", "HOLDOUT_ACCESSED", "UNBLINDED"}
                for label in labels
            ):
                touched = True
            if any(
                ("HOLDOUT" in label and ("ACCESS" in label or "RELEASE" in label))
                or "ACCESS_VIOLATION" in label
                for label in labels
            ):
                touched = True
            downstream = any(
                label
                in {
                    "CONFIRMATORY_COMPLETED",
                    "CONFIRMATORY_RUN_COMPLETED",
                    "CLAIMS",
                    "VERIFY",
                    "WRITE",
                    "AUDIT",
                    "REPRODUCE",
                    "RELEASE",
                    "READY_FOR_HUMAN_REVIEW",
                    "NEGATIVE_RESULT",
                    "INCONCLUSIVE",
                }
                for label in labels
            ) or any(
                label.startswith("CONFIRMATORY_")
                and label.endswith(("COMPLETED", "SUCCEEDED", "FINISHED", "RESULT_RECORDED"))
                for label in labels
            )
            if downstream:
                touched = True
                completed = True
            for key in ("holdout_access_count", "authorized_access_count", "access_count"):
                access = event.get(key)
                if isinstance(access, int) and not isinstance(access, bool) and access > 0:
                    touched = True
            if event.get("release_event") is not None or event.get("unblinded") is True:
                touched = True
        if custody:
            for key in ("access_count", "authorized_access_count", "holdout_access_count"):
                access = custody.get(key, 0)
                if isinstance(access, int) and not isinstance(access, bool) and access > 0:
                    touched = True
            if custody.get("released") is True or custody.get("release_event") is not None:
                touched = True
            if custody.get("revealed") is True or custody.get("confirmatory_claims_valid") is True:
                touched = True
            if custody.get("invalidated") is True:
                touched = True
            if custody.get("confirmatory_completed") is True:
                touched = completed = True
        return touched, completed

    @staticmethod
    def _derived_state(events: Sequence[Mapping[str, object]]) -> str | None:
        for event in reversed(events):
            for key in ("state_after", "requested_state_after", "destination_state", "state"):
                value = event.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    @staticmethod
    def _valid_new_study_protocol(
        protocol: object | None,
        custody: Mapping[str, object] | None,
    ) -> bool:
        try:
            from .protocol import StudyVersion, validate_protocol

            if not isinstance(protocol, StudyVersion):
                return False
            validate_protocol(protocol.protocol)
        except Exception:
            return False
        if protocol.version < 2 or protocol.reveal is not None:
            return False
        if protocol.requires_fresh_confirmatory_reserve is not True:
            return False
        parent_hash = protocol.protocol.parent_protocol_hash
        if (
            not isinstance(parent_hash, str)
            or not SHA256_PATTERN.fullmatch(parent_hash)
            or not protocol.protocol.revision_reason
            or protocol.protocol_hash == parent_hash
        ):
            return False
        if custody is None:
            return False
        old_protocol = custody.get("protocol_hash")
        if not isinstance(old_protocol, str) or parent_hash != old_protocol:
            return False
        old_study = custody.get("study_id")
        old_version = custody.get("study_version")
        if not isinstance(old_study, str) or old_study != protocol.study_id:
            return False
        if (
            isinstance(old_version, bool)
            or not isinstance(old_version, int)
            or old_version < 1
            or protocol.version != old_version + 1
        ):
            return False
        return True

    @staticmethod
    def _valid_fresh_custody_evidence(
        evidence: object | None,
        protocol: object | None,
        events: Sequence[Mapping[str, object]],
        old_custody: Mapping[str, object] | None,
        artifact_registry: object | None,
        custody_provider: object | None,
        project_root: Path,
        ledger_supplier: Callable[[], LedgerValidationResult] | None = None,
        admission_callback: Callable[[], object] | None = None,
    ) -> bool:
        """Validate frozen receipt and current provider state under its guard.

        Caller-constructed snapshots are deliberately not accepted: the
        provider must reload and lock its durable journal for this check.
        """

        try:
            from .artifacts import ArtifactRecord, ArtifactRegistry
            from .holdout import (
                CustodyIndependence,
                CustodyStatus,
                HoldoutAdmissionSnapshot,
                HoldoutCustody,
                HoldoutSeal,
            )
            from .protocol import StudyVersion
            from .roles import Role

            if not isinstance(evidence, FreshCustodyEvidence):
                return False
            if not isinstance(protocol, StudyVersion):
                return False
            if not isinstance(artifact_registry, ArtifactRegistry):
                return False
            if artifact_registry.policy.root != project_root:
                return False
            if not isinstance(custody_provider, HoldoutCustody):
                return False
            record = artifact_registry.get_metadata(evidence.receipt_artifact_sha256)
            if not isinstance(record, ArtifactRecord):
                return False
            if (
                record.record_hash != evidence.artifact_record_hash
                or record.logical_type != "fresh_custody_receipt"
                or record.schema_version != "1.0"
                or record.mime_type != "application/json"
                or record.creator_role is not Role.HOLDOUT_CUSTODIAN
                or record.validation_result != "PASS"
                or record.frozen is not True
                or not record.parent_artifacts
                or artifact_registry.verify(evidence.receipt_artifact_sha256) is not True
            ):
                return False
            receipt_bytes = artifact_registry.get_bytes(evidence.receipt_artifact_sha256)
            if not isinstance(receipt_bytes, bytes):
                return False
            receipt = safe_json_loads(
                receipt_bytes, max_bytes=MAX_ARTIFACT_OBJECT_BYTES
            )
            if not isinstance(receipt, Mapping) or set(receipt) != {
                "schema_version",
                "study_id",
                "study_version",
                "seal",
                "status",
                "journal_head_hash",
                "journal_identity_sha256",
            }:
                return False
            if receipt.get("schema_version") != "1.0":
                return False
            receipt_head = receipt.get("journal_head_hash")
            receipt_identity = receipt.get("journal_identity_sha256")
            if (
                not isinstance(receipt_head, str)
                or not SHA256_PATTERN.fullmatch(receipt_head)
                or not isinstance(receipt_identity, str)
                or not SHA256_PATTERN.fullmatch(receipt_identity)
            ):
                return False
            raw_seal = receipt.get("seal")
            raw_status = receipt.get("status")
            if not isinstance(raw_seal, Mapping) or not isinstance(raw_status, Mapping):
                return False
            seal = HoldoutSeal(**dict(raw_seal))
            expected_status_keys = {
                "custody_independence",
                "sealed",
                "revealed",
                "invalidated",
                "confirmatory_claims_valid",
                "authorized_access_count",
                "violation_reasons",
                "release_event",
                "durable_journal",
                "journal_head_hash",
            }
            if set(raw_status) != expected_status_keys:
                return False
            status_value = dict(raw_status)
            status_value["custody_independence"] = CustodyIndependence(
                status_value["custody_independence"]
            )
            status_value["violation_reasons"] = tuple(
                status_value["violation_reasons"]
            )
            if status_value["release_event"] is not None:
                return False
            status = CustodyStatus(**status_value)
            with custody_provider.admission_guard(
                expected_journal_head_hash=receipt_head,
                expected_journal_identity_sha256=receipt_identity,
            ) as live:
                if not isinstance(live, HoldoutAdmissionSnapshot):
                    return False
                if receipt.get("study_id") != protocol.study_id or receipt.get(
                    "study_version"
                ) != protocol.version:
                    return False
                if (
                    receipt_head != live.journal_head_hash
                    or receipt_identity != live.journal_identity_sha256
                ):
                    return False
                if seal != live.seal or status != live.status:
                    return False
                if seal.protocol_hash != protocol.protocol_hash:
                    return False
                if not (
                    live.sealed is True
                    and live.revealed is False
                    and live.invalidated is False
                    and live.confirmatory_claims_valid is False
                    and isinstance(live.authorized_access_count, int)
                    and not isinstance(live.authorized_access_count, bool)
                    and live.authorized_access_count == 0
                    and live.durable_journal
                    and status.release_event is None
                ):
                    return False
                if old_custody is not None:
                    for key, fresh_value in (
                        ("holdout_identity_hash", live.holdout_identity_hash),
                        ("split_manifest_hash", live.split_manifest_hash),
                        ("seal_hash", live.seal_hash),
                    ):
                        old_value = old_custody.get(key)
                        if (
                            not isinstance(old_value, str)
                            or not SHA256_PATTERN.fullmatch(old_value)
                            or old_value == fresh_value
                        ):
                            return False
                bound_event = next(
                    (
                        event
                        for event in events
                        if event.get("event_id") == evidence.ledger_event_id
                    ),
                    None,
                )
                if bound_event is None:
                    return False
                if bound_event is not events[-1]:
                    return False
                if (
                    bound_event.get("actor_role") != "holdout_custodian"
                    or bound_event.get("event_type") != "CHECKPOINT"
                    or bound_event.get("configuration_hash")
                    != live.configuration_hash
                ):
                    return False
                if bound_event.get("code_version") != live.code_hash:
                    return False
                artifact_hashes = bound_event.get("artifact_hashes")
                if (
                    not isinstance(artifact_hashes, (list, tuple))
                    or evidence.receipt_artifact_sha256 not in artifact_hashes
                ):
                    return False
                metadata = bound_event.get("metadata")
                if not isinstance(metadata, Mapping):
                    return False
                artifact_types = metadata.get("artifact_types")
                record_hashes = metadata.get("artifact_record_hashes")
                if (
                    not isinstance(artifact_types, (list, tuple))
                    or not isinstance(record_hashes, (list, tuple))
                    or len(artifact_types) != len(artifact_hashes)
                    or len(record_hashes) != len(artifact_hashes)
                ):
                    return False
                receipt_index = artifact_hashes.index(evidence.receipt_artifact_sha256)
                if (
                    artifact_types[receipt_index] != "fresh_custody_receipt"
                    or record_hashes[receipt_index] != evidence.artifact_record_hash
                ):
                    return False
                binding = metadata.get("fresh_custody")
                if not isinstance(binding, Mapping):
                    return False
                expected_binding = {
                    "artifact_sha256": evidence.receipt_artifact_sha256,
                    "artifact_record_hash": evidence.artifact_record_hash,
                    "journal_head_hash": live.journal_head_hash,
                    "journal_identity_sha256": live.journal_identity_sha256,
                    "protocol_hash": protocol.protocol_hash,
                    "seal_hash": live.seal_hash,
                    "study_version": protocol.version,
                }
                if dict(binding) != expected_binding:
                    return False
                if ledger_supplier is None:
                    return admission_callback is None
                current = ledger_supplier()
                expected_head = (
                    str(events[-1].get("event_hash")) if events else None
                )
                if (
                    not current.valid
                    or current.head_hash != expected_head
                    or current.event_count != len(events)
                ):
                    return False
                if admission_callback is None:
                    return True
                admission_callback()
                admitted = ledger_supplier()
                if (
                    not admitted.valid
                    or admitted.event_count != current.event_count + 1
                    or not admitted.events
                ):
                    return False
                final_event = admitted.events[-1]
                final_hashes = final_event.get("artifact_hashes")
                final_metadata = final_event.get("metadata")
                final_types = (
                    final_metadata.get("artifact_types")
                    if isinstance(final_metadata, Mapping)
                    else None
                )
                final_records = (
                    final_metadata.get("artifact_record_hashes")
                    if isinstance(final_metadata, Mapping)
                    else None
                )
                receipt_bound = False
                if (
                    isinstance(final_hashes, (list, tuple))
                    and isinstance(final_types, (list, tuple))
                    and isinstance(final_records, (list, tuple))
                    and len(final_hashes) == len(final_types) == len(final_records)
                    and evidence.receipt_artifact_sha256 in final_hashes
                ):
                    final_index = final_hashes.index(evidence.receipt_artifact_sha256)
                    receipt_bound = (
                        final_types[final_index] == "fresh_custody_receipt"
                        and final_records[final_index] == evidence.artifact_record_hash
                    )
                return (
                    final_event.get("prior_event_hash") == current.head_hash
                    and final_event.get("event_type") == "CONFIRMATORY_STARTED"
                    and final_event.get("actor_role") == "orchestrator"
                    and final_event.get("requested_state_after") == "CONFIRM"
                    and final_event.get("configuration_hash")
                    == live.configuration_hash
                    and final_event.get("code_version") == live.code_hash
                    and receipt_bound
                )
        except Exception:
            return False

    def _read_optional_mapping(
        self, value: object | None
    ) -> Mapping[str, object] | None:
        if value is None or isinstance(value, Mapping):
            return value
        if is_dataclass(value) and not isinstance(value, type):
            converted = asdict(value)
            if isinstance(converted, Mapping):
                return converted
        if not isinstance(value, (str, os.PathLike)):
            raise RecoveryError("recovery metadata must be a mapping, dataclass, or path")
        try:
            encoded = read_confined_bytes(
                self.project_root,
                self._relative_path(value),
                reject_hardlinks=True,
                max_bytes=self.maximum_metadata_bytes,
            )
            if encoded is None:
                raise PathSecurityError("recovery metadata is absent")
            parsed = safe_json_loads(encoded, max_bytes=self.maximum_metadata_bytes)
        except (PathSecurityError, UnsafeSerializationError) as exc:
            raise RecoveryError(f"cannot parse recovery metadata safely: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise RecoveryError("recovery metadata must be a JSON object")
        return parsed

    def recover(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        artifact_registry: object | None = None,
        checkpoint_dir: str | os.PathLike[str] = ".scientist-one-build/checkpoints",
        custody_record: object | None = None,
        incomplete_paths: Sequence[str | os.PathLike[str]] | None = None,
        new_study_protocol: object | None = None,
        fresh_custody_evidence: FreshCustodyEvidence | None = None,
        custody_provider: object | None = None,
        repair_truncated_tail: bool = True,
    ) -> RecoveryReport:
        quarantined: list[QuarantineRecord] = []
        try:
            ledger = self.validate_ledger(ledger_path)
        except RecoveryError as exc:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (f"LEDGER_VALIDATION_FAILED:{exc}",),
                False,
                0,
                None,
                False,
                (),
                (),
                None,
                None,
                False,
                False,
            )
        if not ledger.valid and ledger.recoverable_truncated_tail and repair_truncated_tail:
            try:
                ledger, record = self.repair_truncated_ledger(ledger_path, ledger)
                quarantined.append(record)
            except RecoveryError as exc:
                return RecoveryReport(
                    ResumeAction.STOP_SECURITY,
                    (f"LEDGER_REPAIR_FAILED:{exc}",),
                    False,
                    ledger.event_count,
                    ledger.head_hash,
                    False,
                    (),
                    tuple(quarantined),
                    None,
                    self._derived_state(ledger.events),
                    False,
                    False,
                )
        if not ledger.valid:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (ledger.error or "LEDGER_INVALID",),
                False,
                ledger.event_count,
                ledger.head_hash,
                False,
                (),
                tuple(quarantined),
                None,
                self._derived_state(ledger.events),
                False,
                False,
            )

        if artifact_registry is None:
            artifacts = ArtifactValidationResult(True, 0, ())
        else:
            artifacts = self.validate_artifacts(artifact_registry)
        if not artifacts.valid:
            action = (
                ResumeAction.STOP_SECURITY
                if artifacts.has_frozen_failure
                else ResumeAction.STOP_SCIENTIFIC_INVALIDITY
            )
            return RecoveryReport(
                action,
                tuple(issue.code for issue in artifacts.issues),
                True,
                ledger.event_count,
                ledger.head_hash,
                False,
                artifacts.issues,
                tuple(quarantined),
                None,
                self._derived_state(ledger.events),
                False,
                False,
            )

        protected = [self._relative_path(ledger_path).as_posix()]
        if isinstance(artifact_registry, (str, os.PathLike)):
            protected.append(self._relative_path(artifact_registry).as_posix())
        for record in artifacts.records:
            raw = record.get("path", record.get("relative_path"))
            if isinstance(raw, str):
                protected.append(raw)
        try:
            quarantined.extend(
                self.quarantine_incomplete(incomplete_paths, protected_paths=protected)
            )
            checkpoint = self.select_checkpoint(
                checkpoint_dir, ledger, artifacts if artifact_registry is not None else None
            )
            custody = self._read_optional_mapping(custody_record)
            self._validate_custody_mapping(custody)
            revalidated = self.validate_ledger(ledger_path)
            if (
                not revalidated.valid
                or revalidated.head_hash != ledger.head_hash
                or revalidated.event_count != ledger.event_count
            ):
                raise RecoveryError("ledger changed during recovery planning")
            ledger = revalidated
            # New-study authorization is accepted only as the typed, validated
            # StudyVersion object; lossy provider-neutral mappings cannot grant
            # confirmatory execution authority.
            new_protocol = new_study_protocol
        except RecoveryError as exc:
            return RecoveryReport(
                ResumeAction.STOP_SECURITY,
                (f"RECOVERY_VALIDATION_FAILED:{exc}",),
                True,
                ledger.event_count,
                ledger.head_hash,
                True,
                (),
                tuple(quarantined),
                None,
                self._derived_state(ledger.events),
                False,
                False,
            )

        touched, completed = self._confirmatory_status(ledger.events, custody)
        derived = self._derived_state(ledger.events)
        if touched:
            if self._valid_new_study_protocol(
                new_protocol, custody
            ) and self._valid_fresh_custody_evidence(
                fresh_custody_evidence,
                new_protocol,
                ledger.events,
                custody,
                artifact_registry,
                custody_provider,
                self.project_root,
            ):
                return RecoveryReport(
                    ResumeAction.START_NEW_STUDY,
                    ("DISTINCT_FROZEN_NEW_STUDY_PROTOCOL_ACCEPTED",),
                    True,
                    ledger.event_count,
                    ledger.head_hash,
                    True,
                    (),
                    tuple(quarantined),
                    None,
                    derived,
                    True,
                    completed,
                    True,
                )
            if completed:
                return RecoveryReport(
                    ResumeAction.SKIP_COMPLETED,
                    ("CONFIRMATORY_EVALUATION_ALREADY_COMPLETED", "CONFIRMATORY_RERUN_PROHIBITED"),
                    True,
                    ledger.event_count,
                    ledger.head_hash,
                    True,
                    (),
                    tuple(quarantined),
                    checkpoint,
                    derived,
                    True,
                    True,
                )
            return RecoveryReport(
                ResumeAction.NEW_STUDY_REQUIRED,
                ("CONFIRMATORY_OR_HOLDOUT_ACCESS_ALREADY_RECORDED", "CONFIRMATORY_RERUN_PROHIBITED"),
                True,
                ledger.event_count,
                ledger.head_hash,
                True,
                (),
                tuple(quarantined),
                checkpoint,
                derived,
                True,
                False,
            )

        if not ledger.events:
            action = ResumeAction.START_FRESH
            reasons = ("EMPTY_VALID_LEDGER",)
        elif checkpoint is not None:
            action = ResumeAction.RESUME_FROM_CHECKPOINT
            reasons = ("LAST_VALID_CHECKPOINT_SELECTED_BY_LEDGER_POSITION",)
        else:
            action = ResumeAction.RESUME_FROM_LEDGER
            reasons = ("NO_VALID_CHECKPOINT_REPLAY_LEDGER",)
        return RecoveryReport(
            action,
            reasons,
            True,
            ledger.event_count,
            ledger.head_hash,
            True,
            (),
            tuple(quarantined),
            checkpoint,
            derived,
            False,
            False,
            replay_event_count=(
                ledger.event_count - checkpoint.ledger_event_index - 1 if checkpoint else ledger.event_count
            ),
        )

    def assert_confirmatory_run_allowed(
        self,
        *,
        ledger_path: str | os.PathLike[str],
        custody_record: object | None = None,
        new_study_protocol: object | None = None,
        fresh_custody_evidence: FreshCustodyEvidence | None = None,
        artifact_registry: object | None = None,
        custody_provider: object | None = None,
        admission_callback: Callable[[], object] | None = None,
    ) -> None:
        """Fail unless the ledger proves no prior access or a fresh study exists."""

        ledger = self.validate_ledger(ledger_path)
        if not ledger.valid:
            raise LedgerValidationError(ledger.error or "ledger is invalid")
        custody = self._read_optional_mapping(custody_record)
        self._validate_custody_mapping(custody)
        if admission_callback is None or not callable(admission_callback):
            raise ConfirmatoryRerunError(
                "confirmatory admission requires an irreversible ledger-start callback"
            )
        protocol = new_study_protocol
        touched, _ = self._confirmatory_status(ledger.events, custody)
        if touched:
            if not self._valid_new_study_protocol(protocol, custody):
                raise ConfirmatoryRerunError(
                    "confirmatory evidence or holdout access already exists; an exact next "
                    "frozen StudyVersion is required"
                )
            if not self._valid_fresh_custody_evidence(
                fresh_custody_evidence,
                protocol,
                ledger.events,
                custody,
                artifact_registry,
                custody_provider,
                self.project_root,
                ledger_supplier=lambda: self.validate_ledger(ledger_path),
                admission_callback=admission_callback,
            ):
                raise ConfirmatoryRerunError(
                    "child-study confirmatory admission requires a distinct sealed, untouched, "
                    "durable, ledger-bound custody reserve"
                )
            return
        if not touched:
            if not self._valid_fresh_custody_evidence(
                fresh_custody_evidence,
                protocol,
                ledger.events,
                None,
                artifact_registry,
                custody_provider,
                self.project_root,
                ledger_supplier=lambda: self.validate_ledger(ledger_path),
                admission_callback=admission_callback,
            ):
                raise ConfirmatoryRerunError(
                    "typed custody receipt and live guarded evidence are required before confirmatory admission"
                )
        if custody is not None and not touched:
            counts = (
                custody.get("access_count", 0),
                custody.get("authorized_access_count", 0),
                custody.get("holdout_access_count", 0),
            )
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value != 0
                for value in counts
            ):
                raise ConfirmatoryRerunError("custody access status is invalid or nonzero")

    # Names used by orchestration code and external callers.
    resume = recover
    validate_resume = recover


__all__ = [
    "ArtifactIssue",
    "ArtifactValidationError",
    "ArtifactValidationResult",
    "CheckpointSelection",
    "ConfirmatoryRerunError",
    "CustodyAdmissionSnapshot",
    "FreshCustodyEvidence",
    "LedgerValidationError",
    "LedgerValidationResult",
    "QuarantineRecord",
    "RecoveryError",
    "RecoveryManager",
    "RecoveryReport",
    "ResumeAction",
    "canonical_json_bytes",
    "checkpoint_digest",
    "event_digest",
]
