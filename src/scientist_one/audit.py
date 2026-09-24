"""Deterministic project-boundary and release-candidate auditing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterable

from .errors import PathSecurityError, UnsafeSerializationError
from .security import (
    INVALID_UTF8_SECRET_SCAN_LABEL,
    canonical_json_bytes,
    detect_secret_patterns_in_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
)


SNAPSHOT_PREFIX = "codex-security-snapshot/v1:sha256:"
DEFAULT_EXCLUDES = (".scientist-one-build",)
DEFAULT_EXCLUDED_FILES = ("reports/final_audit.json",)
MAX_AUDIT_FILE_BYTES = 64 * 1024 * 1024
MAX_AUDIT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_AUDIT_FILES = 100_000
MAX_AUDIT_REPORT_BYTES = 8 * 1024 * 1024
BINARY_SECRET_SCAN_SUFFIXES = frozenset({".zip"})
LOCKFILE_NAMES = {
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "conda-lock.yml",
}

@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class AuditFinding:
    check: str
    path: str
    detail: str


@dataclass
class _InventoryState:
    records: list[FileRecord]
    findings: list[AuditFinding]
    file_identities: dict[str, tuple[int, ...]]
    directory_identities: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class ProjectAudit:
    project_root: str
    snapshot_digest: str
    file_count: int
    total_bytes: int
    files: tuple[FileRecord, ...]
    findings: tuple[AuditFinding, ...]
    lockfiles: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.findings and not self.lockfiles

    def as_json(self) -> str:
        value = asdict(self)
        value["passed"] = self.passed
        payload = canonical_json_bytes(value)
        if len(payload) > MAX_AUDIT_REPORT_BYTES:
            raise UnsafeSerializationError("audit report exceeds output size limit")
        return payload.decode("utf-8") + "\n"


def canonical_root(root: Path) -> Path:
    root = root.resolve(strict=True)
    if not root.is_dir() or root == Path(root.anchor) or root == Path.home():
        raise ValueError("unsafe project root")
    return root


def _is_excluded(relative: Path, excludes: Iterable[str]) -> bool:
    return bool(relative.parts and relative.parts[0] in set(excludes))


def _inventory_before_descend(relative: Path) -> None:
    """Deterministic test seam immediately before a child directory is pinned."""


def _inventory_before_directory_reopen(relative: Path) -> None:
    """Deterministic test seam before a queued directory is revalidated."""


def _stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_label(relative: Path) -> str:
    return relative.as_posix() if relative != Path(".") else "."


def _bounded_directory_names(
    directory_fd: int,
    *,
    relative_directory: Path,
    excludes: frozenset[str],
    remaining_entries: int,
) -> tuple[list[str], bool]:
    """Collect at most the remaining entry budget before sorting.

    The extra entry that proves overflow is observed but never retained.  This
    keeps allocation bounded even for a directory much larger than the audit
    contract.
    """

    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            relative = (
                Path(entry.name)
                if relative_directory == Path(".")
                else relative_directory / entry.name
            )
            if _is_excluded(relative, excludes):
                continue
            if len(names) >= remaining_entries:
                return names, True
            names.append(entry.name)
    return names, False


def _read_inventory_file(directory_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PathSecurityError("inventory entry changed to a non-regular file")
        if metadata.st_nlink != 1:
            raise PathSecurityError("inventory entry is hard linked")
        if metadata.st_size > MAX_AUDIT_FILE_BYTES:
            raise OverflowError("inventory entry exceeds the per-file bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_AUDIT_FILE_BYTES + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AUDIT_FILE_BYTES:
                raise OverflowError("inventory entry exceeds the per-file bound")
            chunks.append(chunk)
        final_metadata = os.fstat(descriptor)
        if _stable_file_metadata(final_metadata) != _stable_file_metadata(metadata):
            raise PathSecurityError("inventory entry changed while it was being read")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _inventory_state(
    root: Path,
    *,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    excluded_files: Iterable[str] = DEFAULT_EXCLUDED_FILES,
) -> _InventoryState:
    root = canonical_root(root)
    records: list[FileRecord] = []
    findings: list[AuditFinding] = []
    file_identities: dict[str, tuple[int, ...]] = {}
    directory_identities: dict[str, tuple[int, ...]] = {}
    total_bytes = 0
    exclude_set = frozenset(excludes)
    excluded_file_set = set(excluded_files)
    entries_seen = 0
    entry_limit_exceeded = False
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        initial_root_fd = open_confined_directory_fd(root, Path("."), create=False)
    except PathSecurityError:
        findings.append(
            AuditFinding(
                "unsafe_directory",
                ".",
                "project root cannot be pinned without following links",
            )
        )
        return _InventoryState(records, findings, file_identities, directory_identities)
    try:
        initial_root_metadata = os.fstat(initial_root_fd)
    finally:
        os.close(initial_root_fd)
    pending = [(Path("."), _stable_file_metadata(initial_root_metadata))]
    while pending and not entry_limit_exceeded:
        relative_directory, expected_directory_identity = pending.pop()
        _inventory_before_directory_reopen(relative_directory)
        try:
            directory_fd = open_confined_directory_fd(
                root, relative_directory, create=False
            )
        except PathSecurityError:
            path_label = (
                relative_directory.as_posix()
                if relative_directory != Path(".")
                else "."
            )
            findings.append(
                AuditFinding(
                    "unsafe_directory",
                    path_label,
                    "directory changed or cannot be pinned without following links",
                )
            )
            continue
        child_directories: list[tuple[Path, tuple[int, ...]]] = []
        try:
            directory_metadata = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or _stable_file_metadata(directory_metadata)
                != expected_directory_identity
            ):
                findings.append(
                    AuditFinding(
                        "unsafe_directory",
                        _directory_label(relative_directory),
                        "directory identity changed before enumeration",
                    )
                )
                continue
            directory_identities[_directory_label(relative_directory)] = (
                expected_directory_identity
            )
            try:
                names, exceeded = _bounded_directory_names(
                    directory_fd,
                    relative_directory=relative_directory,
                    excludes=exclude_set,
                    remaining_entries=max(0, MAX_AUDIT_FILES - entries_seen),
                )
            except OSError:
                findings.append(
                    AuditFinding(
                        "unsafe_directory",
                        relative_directory.as_posix(),
                        "directory cannot be enumerated through its pinned descriptor",
                    )
                )
                continue
            entries_seen += len(names)
            if exceeded:
                findings.append(
                    AuditFinding(
                        "audit_file_count_limit",
                        _directory_label(relative_directory),
                        f"inventory exceeds {MAX_AUDIT_FILES} entries",
                    )
                )
                entry_limit_exceeded = True
                continue
            for name in sorted(names):
                if name in {"", ".", ".."} or "/" in name:
                    findings.append(
                        AuditFinding(
                            "unsafe_entry_name",
                            (relative_directory / name).as_posix(),
                            "directory contains an unsafe entry name",
                        )
                    )
                    continue
                relative = (
                    Path(name)
                    if relative_directory == Path(".")
                    else relative_directory / name
                )
                try:
                    metadata = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                except OSError:
                    findings.append(
                        AuditFinding(
                            "unsafe_entry",
                            relative.as_posix(),
                            "entry disappeared or could not be inspected",
                        )
                    )
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    findings.append(
                        AuditFinding(
                            "symlink_rejected",
                            relative.as_posix(),
                            "linked inventory entry",
                        )
                    )
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    _inventory_before_descend(relative)
                    try:
                        child_fd = os.open(
                            name, directory_flags, dir_fd=directory_fd
                        )
                    except OSError:
                        findings.append(
                            AuditFinding(
                                "unsafe_directory",
                                relative.as_posix(),
                                "directory changed before it could be pinned",
                            )
                        )
                        continue
                    try:
                        child_metadata = os.fstat(child_fd)
                        if (
                            not stat.S_ISDIR(child_metadata.st_mode)
                            or _stable_file_metadata(child_metadata)
                            != _stable_file_metadata(metadata)
                        ):
                            findings.append(
                                AuditFinding(
                                    "unsafe_directory",
                                    relative.as_posix(),
                                    "directory identity changed before it could be pinned",
                                )
                            )
                            continue
                    finally:
                        os.close(child_fd)
                    child_directories.append(
                        (relative, _stable_file_metadata(child_metadata))
                    )
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    findings.append(
                        AuditFinding(
                            "non_regular_file",
                            relative.as_posix(),
                            "not a regular file or directory",
                        )
                    )
                    continue
                if relative.as_posix() in excluded_file_set:
                    continue
                if metadata.st_nlink != 1:
                    findings.append(
                        AuditFinding(
                            "hardlink_rejected",
                            relative.as_posix(),
                            "file has multiple links",
                        )
                    )
                    continue
                if metadata.st_size > MAX_AUDIT_FILE_BYTES:
                    findings.append(
                        AuditFinding(
                            "audit_file_size_limit",
                            relative.as_posix(),
                            f"file exceeds {MAX_AUDIT_FILE_BYTES} bytes",
                        )
                    )
                    continue
                if total_bytes + metadata.st_size > MAX_AUDIT_TOTAL_BYTES:
                    findings.append(
                        AuditFinding(
                            "audit_total_size_limit",
                            relative.as_posix(),
                            f"inventory exceeds {MAX_AUDIT_TOTAL_BYTES} bytes",
                        )
                    )
                    continue
                try:
                    content, pinned_metadata = _read_inventory_file(
                        directory_fd, name
                    )
                except OverflowError:
                    findings.append(
                        AuditFinding(
                            "audit_file_size_limit",
                            relative.as_posix(),
                            f"file exceeds {MAX_AUDIT_FILE_BYTES} bytes",
                        )
                    )
                    continue
                except (OSError, PathSecurityError) as exc:
                    findings.append(
                        AuditFinding(
                            "unsafe_file_read",
                            relative.as_posix(),
                            type(exc).__name__,
                        )
                    )
                    continue
                if total_bytes + len(content) > MAX_AUDIT_TOTAL_BYTES:
                    findings.append(
                        AuditFinding(
                            "audit_total_size_limit",
                            relative.as_posix(),
                            f"inventory exceeds {MAX_AUDIT_TOTAL_BYTES} bytes",
                        )
                    )
                    continue
                if _stable_file_metadata(pinned_metadata) != _stable_file_metadata(metadata):
                    findings.append(
                        AuditFinding(
                            "unsafe_file_read",
                            relative.as_posix(),
                            "entry changed before it could be read",
                        )
                    )
                    continue
                records.append(
                    FileRecord(
                        relative.as_posix(),
                        len(content),
                        hashlib.sha256(content).hexdigest(),
                    )
                )
                file_identities[relative.as_posix()] = _stable_file_metadata(
                    pinned_metadata
                )
                total_bytes += len(content)
            final_directory_metadata = os.fstat(directory_fd)
            if (
                _stable_file_metadata(final_directory_metadata)
                != expected_directory_identity
            ):
                findings.append(
                    AuditFinding(
                        "unsafe_directory",
                        _directory_label(relative_directory),
                        "directory changed while it was being inventoried",
                    )
                )
        finally:
            os.close(directory_fd)
        if not entry_limit_exceeded:
            pending.extend(reversed(child_directories))
    for relative_directory in sorted(directory_identities):
        try:
            directory_fd = _open_bound_directory_fd(
                root,
                Path(relative_directory),
                directory_identities,
            )
        except PathSecurityError as exc:
            findings.append(
                AuditFinding(
                    "unsafe_directory",
                    relative_directory,
                    type(exc).__name__,
                )
            )
        else:
            os.close(directory_fd)
    return _InventoryState(records, findings, file_identities, directory_identities)


def inventory(
    root: Path,
    *,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    excluded_files: Iterable[str] = DEFAULT_EXCLUDED_FILES,
) -> tuple[list[FileRecord], list[AuditFinding]]:
    state = _inventory_state(root, excludes=excludes, excluded_files=excluded_files)
    return state.records, state.findings


def snapshot_digest(records: Iterable[FileRecord]) -> str:
    payload = b"".join(
        f"{record.path}\0{record.size}\0{record.sha256}\n".encode()
        for record in sorted(records, key=lambda item: item.path)
    )
    return SNAPSHOT_PREFIX + hashlib.sha256(payload).hexdigest()


def _open_bound_directory_fd(
    root: Path,
    relative: Path,
    directory_identities: dict[str, tuple[int, ...]],
) -> int:
    """Open a directory only if every component has its inventoried identity."""

    current_fd = open_confined_directory_fd(root, Path("."), create=False)
    try:
        root_metadata = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or _stable_file_metadata(root_metadata) != directory_identities.get(".")
        ):
            raise PathSecurityError("project root identity changed during audit")
        current_relative = Path(".")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise PathSecurityError("unsafe inventoried directory component")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise PathSecurityError("inventoried directory cannot be reopened") from exc
            try:
                metadata = os.fstat(next_fd)
                current_relative = (
                    Path(component)
                    if current_relative == Path(".")
                    else current_relative / component
                )
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or _stable_file_metadata(metadata)
                    != directory_identities.get(current_relative.as_posix())
                ):
                    raise PathSecurityError("inventoried directory identity changed")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _read_bound_inventory_file(
    root: Path,
    relative: str,
    *,
    file_identities: dict[str, tuple[int, ...]],
    directory_identities: dict[str, tuple[int, ...]],
) -> bytes:
    relative_path = Path(relative)
    directory_fd = _open_bound_directory_fd(
        root, relative_path.parent, directory_identities
    )
    try:
        try:
            payload, metadata = _read_inventory_file(directory_fd, relative_path.name)
        except (OSError, OverflowError) as exc:
            raise PathSecurityError("inventoried file cannot be reread safely") from exc
    finally:
        os.close(directory_fd)
    if _stable_file_metadata(metadata) != file_identities.get(relative):
        raise PathSecurityError("inventoried file identity changed")
    return payload


def _scan_text_secrets(root: Path, relative: str) -> list[AuditFinding]:
    try:
        payload = read_confined_bytes(
            root,
            relative,
            reject_hardlinks=True,
            max_bytes=MAX_AUDIT_FILE_BYTES,
        )
        if payload is None:
            return [AuditFinding("unsafe_file_read", relative, "file disappeared")]
        return _scan_text_secret_payload(relative, payload)
    except PathSecurityError as exc:
        return [AuditFinding("unsafe_file_read", relative, type(exc).__name__)]


def _scan_text_secret_payload(relative: str, payload: bytes) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    binary_payload = Path(relative).suffix.lower() in BINARY_SECRET_SCAN_SUFFIXES
    for name in detect_secret_patterns_in_bytes(payload):
        if name == INVALID_UTF8_SECRET_SCAN_LABEL and binary_payload:
            continue
        check = (
            "invalid_text_encoding"
            if name == INVALID_UTF8_SECRET_SCAN_LABEL
            else "secret_pattern"
        )
        findings.append(AuditFinding(check, relative, name))
    return findings


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _strings(key)
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _outside_root_paths_in_payload(payload: bytes, root: Path) -> list[str]:
    data = safe_json_loads(payload)
    outside: list[str] = []
    for value in _strings(data):
        candidate = Path(value)
        if not candidate.is_absolute():
            continue
        try:
            candidate.resolve(strict=False).relative_to(root)
        except ValueError:
            outside.append(value)
    return sorted(set(outside))


def outside_root_paths_in_json(path: Path, root: Path) -> list[str]:
    root = canonical_root(root)
    try:
        relative = path.relative_to(root) if path.is_absolute() else path
    except ValueError as exc:
        raise PathSecurityError("manifest is outside the project root") from exc
    payload = read_confined_bytes(
        root,
        relative,
        reject_hardlinks=True,
        max_bytes=MAX_AUDIT_FILE_BYTES,
    )
    if payload is None:
        raise PathSecurityError("manifest disappeared during audit")
    return _outside_root_paths_in_payload(payload, root)


def _audit_before_record_validation(record: FileRecord) -> None:
    """Deterministic test seam before an inventoried file is revalidated."""


def audit_project(
    root: Path,
    *,
    manifest_directories: Iterable[str] = ("runs", "artifacts", "reports"),
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    excluded_files: Iterable[str] = DEFAULT_EXCLUDED_FILES,
) -> ProjectAudit:
    root = canonical_root(root)
    state = _inventory_state(
        root, excludes=excludes, excluded_files=excluded_files
    )
    records = state.records
    findings = state.findings
    record_paths = {record.path for record in records}
    for record in records:
        _audit_before_record_validation(record)
        try:
            payload = _read_bound_inventory_file(
                root,
                record.path,
                file_identities=state.file_identities,
                directory_identities=state.directory_identities,
            )
        except PathSecurityError as exc:
            findings.append(
                AuditFinding(
                    "changed_during_audit", record.path, type(exc).__name__
                )
            )
            continue
        if (
            payload is None
            or len(payload) != record.size
            or hashlib.sha256(payload).hexdigest() != record.sha256
        ):
            findings.append(
                AuditFinding(
                    "changed_during_audit",
                    record.path,
                    "current bytes differ from the inventoried snapshot",
                )
            )
            continue
        findings.extend(_scan_text_secret_payload(record.path, payload))
        if Path(record.path).suffix == ".json" and record.path.split("/", 1)[0] in set(manifest_directories):
            try:
                outside = _outside_root_paths_in_payload(payload, root)
            except (UnsafeSerializationError, UnicodeDecodeError) as exc:
                findings.append(AuditFinding("invalid_manifest_json", record.path, type(exc).__name__))
            else:
                findings.extend(
                    AuditFinding("outside_root_manifest_path", record.path, value) for value in outside
                )
    for relative_directory in sorted(state.directory_identities):
        try:
            directory_fd = _open_bound_directory_fd(
                root,
                Path(relative_directory),
                state.directory_identities,
            )
        except PathSecurityError as exc:
            findings.append(
                AuditFinding(
                    "changed_during_audit",
                    relative_directory,
                    type(exc).__name__,
                )
            )
        else:
            os.close(directory_fd)
    lockfiles = sorted(
        relative for relative in record_paths if Path(relative).name in LOCKFILE_NAMES
    )
    return ProjectAudit(
        str(root),
        snapshot_digest(records),
        len(records),
        sum(record.size for record in records),
        tuple(records),
        tuple(findings),
        tuple(lockfiles),
    )


def write_audit(audit: ProjectAudit, target: Path, root: Path) -> Path:
    root = canonical_root(root)
    try:
        relative = target.relative_to(root) if target.is_absolute() else target
    except ValueError as exc:
        raise ValueError("audit target escapes project root") from exc
    # Reuse the control plane's descriptor-pinned writer so every parent
    # component is opened with no-follow semantics and replacement never
    # dereferences a destination link.
    from .security import atomic_write_bytes

    try:
        return atomic_write_bytes(
            root,
            relative,
            audit.as_json().encode(),
            overwrite=True,
            create_parents=False,
        )
    except PathSecurityError as exc:
        raise ValueError("audit target is not a confined regular file") from exc
