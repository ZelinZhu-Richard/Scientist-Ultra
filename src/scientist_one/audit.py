"""Deterministic project-boundary and release-candidate auditing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable

from .errors import PathSecurityError, UnsafeSerializationError
from .git_audit import (
    GIT_AUDIT_PROFILE,
    GIT_AUDIT_SCHEMA,
    GitAuditCoverage,
    GitAuditFile,
    GitAuditFinding,
    GitAuditSession,
    is_reviewed_synthetic_fixture,
)
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
# Runtime trust roots are never audit evidence.  Assemble the private basename
# from fragments so the audited source snapshot does not disclose its path.
_PRIVATE_AUDIT_BASENAMES = frozenset(
    {
        "." + "gateway-execution-" + "authority.key",
        ".scientific-domain-generic-ml-observations-" + "authority.key",
    }
)
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GATEWAY_TRUST_ROOT_BYTES = 32
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


@dataclass(frozen=True)
class ReviewedDisposition:
    """One exact observation; never a caller-configurable scanning exemption."""

    finding: AuditFinding
    classification: str
    content_sha256: str
    field_pointer: str | None = None
    blob_oid: str | None = None
    target_access: str = "NOT_PERMITTED"


@dataclass
class _InventoryState:
    records: list[FileRecord]
    findings: list[AuditFinding]
    file_identities: dict[str, tuple[int, ...]]
    directory_identities: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class _AuditBinding:
    """In-memory identity seal, never serialized as public audit evidence."""

    records: tuple[FileRecord, ...]
    findings: tuple[AuditFinding, ...]
    file_identities: tuple[tuple[str, tuple[int, ...]], ...]
    directory_identities: tuple[tuple[str, tuple[int, ...]], ...]
    excludes: tuple[str, ...]
    excluded_files: tuple[str, ...]
    report_sha256: str = ""


@dataclass(frozen=True)
class ProjectAudit:
    project_root: str
    snapshot_digest: str
    file_count: int
    total_bytes: int
    files: tuple[FileRecord, ...]
    findings: tuple[AuditFinding, ...]
    lockfiles: tuple[str, ...]
    git: GitAuditCoverage | None = None
    _binding: _AuditBinding | None = field(default=None, repr=False, compare=False)
    reviewed_dispositions: tuple[ReviewedDisposition, ...] = ()

    def _dispositions_eligible(self) -> bool:
        return bool(
            self.git is not None and self.git.passed and self._binding is not None
            and self.reviewed_dispositions
            and not any(item.check == "changed_during_audit" for item in self.findings)
            and all(self.findings.count(item.finding) == 1 for item in self.reviewed_dispositions)
            and len({item.finding for item in self.reviewed_dispositions}) == len(self.reviewed_dispositions)
        )

    def _dispositions_effective(self) -> bool:
        if not self._dispositions_eligible():
            return False
        assert self._binding is not None
        # The proposed classification participates in the *existing* report
        # seal. Dataclass replacement or a deserialized report is not authority.
        return hashlib.sha256(self._report_json(True).encode("utf-8")).hexdigest() == self._binding.report_sha256

    def _unresolved(self, effective: bool) -> tuple[AuditFinding, ...]:
        classified = {item.finding for item in self.reviewed_dispositions} if effective else set()
        return tuple(item for item in self.findings if item not in classified)

    @property
    def unresolved_finding_count(self) -> int:
        return len(self._unresolved(self._dispositions_effective()))

    @property
    def passed(self) -> bool:
        return (
            not self._unresolved(self._dispositions_effective()) and not self.lockfiles
            and (self.git is None or self.git.passed)
        )

    def as_json(self) -> str:
        return self._report_json(self._dispositions_effective())

    def _report_json(self, effective: bool) -> str:
        # Preserve the exact historical wire format when no Git exists. The
        # private live-identity seal is not a second provenance inventory.
        value = {
            "project_root": self.project_root,
            "snapshot_digest": self.snapshot_digest,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "files": [asdict(item) for item in self.files],
            "findings": [asdict(item) for item in self.findings],
            "lockfiles": self.lockfiles,
        }
        if self.git is not None:
            value["git"] = self.git.to_dict()
            if self.reviewed_dispositions:
                value["disposition_policy"] = "AUDIT001_REVIEWED_DISPOSITIONS_V1"
                value["reviewed_dispositions"] = [
                    {**asdict(item), "nonblocking": effective}
                    for item in self.reviewed_dispositions
                ]
                value["unresolved_finding_count"] = len(self._unresolved(effective))
        value["passed"] = bool(
            not self._unresolved(effective) and not self.lockfiles
            and (self.git is None or self.git.passed)
        )
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


def _is_runtime_registry_private_file(relative: Path) -> bool:
    """Recognize only the repository's exact supported registry locations."""

    if relative.name not in _PRIVATE_AUDIT_BASENAMES:
        return False
    parent_parts = relative.parent.parts
    if parent_parts == ("artifacts", "registry"):
        return True
    return bool(
        len(parent_parts) == 3
        and parent_parts[0] == "runs"
        and _RUN_ID_PATTERN.fullmatch(parent_parts[1])
        and parent_parts[2] == "registry"
    )


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
                if name in _PRIVATE_AUDIT_BASENAMES:
                    finding_path = _directory_label(relative.parent)
                    if not _is_runtime_registry_private_file(relative):
                        findings.append(
                            AuditFinding(
                                "private_runtime_secret_outside_registry",
                                finding_path,
                                "private runtime trust material exists outside a supported registry",
                            )
                        )
                    elif (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or (metadata.st_mode & 0o777) != 0o600
                        or metadata.st_size != _GATEWAY_TRUST_ROOT_BYTES
                    ):
                        findings.append(
                            AuditFinding(
                                "unsafe_private_runtime_secret",
                                finding_path,
                                "private runtime trust material has unsafe metadata",
                            )
                        )
                    # Never read, hash, inventory, or descend through private
                    # runtime trust material, including malformed instances.
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
    binary_payload = (
        not relative.startswith(".git/")
        and Path(relative).suffix.lower() in BINARY_SECRET_SCAN_SUFFIXES
    )
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


_REVIEWED_MANIFEST_PATH = "reports/final_functional_source_inventory.json"
_REVIEWED_MANIFEST_SHA256 = "912835d3dc91f4e9cab26b46d7aeb7e55b5f2a049284632e68fdc5351b205abe"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _reviewed_interpreter_provenance(relative: str, payload: bytes, data: Any) -> str | None:
    """Classify only reviewed bytes; never resolve or access the recorded target."""
    if relative != _REVIEWED_MANIFEST_PATH or hashlib.sha256(payload).hexdigest() != _REVIEWED_MANIFEST_SHA256:
        return None
    keys = {
        "schema_version", "generated_at", "interpreter_path", "interpreter_version",
        "selection_rule", "file_count", "total_bytes", "aggregate_sha256", "entries",
    }
    if type(data) is not dict or data.keys() != keys:
        return None
    if data["schema_version"] != "scientist-one-functional-source-inventory/v1":
        return None
    for key in ("generated_at", "interpreter_path", "interpreter_version", "selection_rule", "aggregate_sha256"):
        value = data[key]
        if type(value) is not str or not 1 <= len(value) <= 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            return None
    target = data["interpreter_path"]
    if not Path(target).is_absolute() or not _SHA256.fullmatch(data["aggregate_sha256"]):
        return None
    if any(type(data[key]) is not int or data[key] < 0 for key in ("file_count", "total_bytes")):
        return None
    entries = data["entries"]
    if type(entries) is not list or len(entries) > MAX_AUDIT_FILES or len(entries) != data["file_count"]:
        return None
    paths: set[str] = set()
    total = 0
    for entry in entries:
        if type(entry) is not dict or entry.keys() != {"path", "size", "sha256"}:
            return None
        path = entry["path"]
        if (
            type(path) is not str or not 1 <= len(path) <= 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/"))
            or path in paths
            or type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_AUDIT_FILE_BYTES
            or type(entry["sha256"]) is not str or not _SHA256.fullmatch(entry["sha256"])
        ):
            return None
        paths.add(path)
        total += entry["size"]
        if total > MAX_AUDIT_TOTAL_BYTES:
            return None
    return target if total == data["total_bytes"] else None


def _outside_root_paths_in_payload(payload: bytes, root: Path, *, relative: str = "") -> list[str]:
    data = safe_json_loads(payload)
    outside: list[str] = []
    provenance = _reviewed_interpreter_provenance(relative, payload, data)
    if provenance is not None:
        # Keep the raw observation (also in strict no-Git reports), but do not
        # follow the recorded target. Only this root field changes treatment.
        outside.append(provenance)
        data = {key: value for key, value in data.items() if key != "interpreter_path"}
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
    return _outside_root_paths_in_payload(payload, root, relative=relative.as_posix())


def _audit_before_record_validation(record: FileRecord) -> None:
    """Deterministic test seam before an inventoried file is revalidated."""


def _git_failure(records: Iterable[FileRecord], code: str) -> GitAuditCoverage:
    raw = sorted(
        (item for item in records if item.path.startswith(".git/")),
        key=lambda item: item.path,
    )
    return GitAuditCoverage(
        schema_version=GIT_AUDIT_SCHEMA,
        profile=GIT_AUDIT_PROFILE,
        raw_inventory_sha256=hashlib.sha256(
            canonical_json_bytes([asdict(item) for item in raw])
        ).hexdigest(),
        raw_file_count=len(raw), raw_total_bytes=sum(item.size for item in raw),
        tool_path=None, tool_sha256=None, tool_version=None,
        decoded_inventory_sha256=None, decoded_object_count=0,
        decoded_total_bytes=0, index_inventory_sha256=None, index_entry_count=0,
        binary_waiver_paths=(), findings=(GitAuditFinding(code),),
    )


def _start_git_audit(
    root: Path, state: _InventoryState,
    *, excludes: tuple[str, ...], excluded_files: tuple[str, ...],
) -> tuple[GitAuditSession | None, GitAuditCoverage | None]:
    """Distinguish absent Git from empty, excluded, linked or partial Git."""

    observed = any(
        path == ".git" or path.startswith(".git/")
        for path in (
            *state.directory_identities,
            *(item.path for item in state.records),
            *(item.path for item in state.findings),
        )
    )
    try:
        descriptor = _open_bound_directory_fd(root, Path("."), state.directory_identities)
        try:
            metadata = os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return (None, _git_failure(state.records, "git_disappeared")) if observed else (None, None)
    except (OSError, PathSecurityError):
        return None, _git_failure(state.records, "git_presence_unresolved")
    if ".git" in excludes or any(
        path == ".git" or path.startswith(".git/") for path in excluded_files
    ):
        return None, _git_failure(state.records, "git_inventory_exclusion_refused")
    if not stat.S_ISDIR(metadata.st_mode) or ".git" not in state.directory_identities:
        return None, _git_failure(state.records, "git_directory_missing_unsafe_or_excluded")
    if any(
        item.path == "." or item.path == ".git" or item.path.startswith(".git/")
        for item in state.findings
    ):
        return None, _git_failure(state.records, "unsafe_or_incomplete_git_inventory")
    try:
        return GitAuditSession(tuple(
            GitAuditFile(item.path, item.size, item.sha256)
            for item in state.records if item.path.startswith(".git/")
        )), None
    except Exception:
        # No untrusted path/content or native diagnostic is included here.
        return None, _git_failure(state.records, "git_parser_setup_failure")


def _same_audit_inventory(
    binding: _AuditBinding, current: _InventoryState, *, staged_report: bool = False,
) -> bool:
    if (
        tuple(current.records) != binding.records
        or tuple(current.findings) != binding.findings
        or tuple(sorted(current.file_identities.items())) != binding.file_identities
    ):
        return False
    directories = dict(binding.directory_identities)
    if current.directory_identities.keys() != directories.keys():
        return False
    for path, identity in current.directory_identities.items():
        expected = directories[path]
        # Creating our one verified scratch file changes reports' timestamps
        # and size. APFS also increases the directory link count by one;
        # filesystems counting only subdirectories leave it unchanged.
        # The directory inode/mode stay exact. All other entries are
        # fully inventoried and all other directory identities remain exact.
        if staged_report and path == "reports":
            if identity[:3] != expected[:3] or identity[3] not in {expected[3], expected[3] + 1}:
                return False
        elif identity != expected:
            return False
    return True


def _require_current_inventory_metadata(root: Path, state: _InventoryState) -> None:
    """Close the late-file-read window of a complete inventory pass.

    Content was read and hashed through held descriptors. Recheck every live
    file identity after the last such read, then every directory identity.
    This is bounded change detection, not an atomic filesystem transaction or
    protection against arbitrary changes after an individual final check.
    """

    for path, expected in sorted(state.file_identities.items()):
        relative = Path(path)
        directory = _open_bound_directory_fd(
            root, relative.parent, state.directory_identities,
        )
        try:
            current = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise PathSecurityError("inventoried file disappeared after final read") from exc
        finally:
            os.close(directory)
        if _stable_file_metadata(current) != expected:
            raise PathSecurityError("inventoried file changed after final read")
    for path in sorted(state.directory_identities):
        descriptor = _open_bound_directory_fd(root, Path(path), state.directory_identities)
        os.close(descriptor)


def require_current_audit(
    audit: ProjectAudit, root: Path, *, staged_report_path: str | None = None,
) -> None:
    """Reattest a Git-bearing audit adjacent to report publication.

    The only extra inventory omission is an exact, verified copy of this
    report in the captured launcher's supported atomic-publication slot.
    This does not authorize arbitrary exclusions or attest an absent Git tree.
    """

    root = canonical_root(root)
    try:
        descriptor = open_confined_directory_fd(root, Path("."), create=False)
        try:
            os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        live_git = False
    except OSError as exc:
        raise PathSecurityError("Git presence cannot be verified before publication") from exc
    else:
        live_git = True
    if (
        audit.git is None and audit._binding is None and not live_git
        and not any(item.path == ".git" or item.path.startswith(".git/") for item in audit.files)
    ):
        return  # Historical non-Git publication behavior stays unchanged.
    binding = audit._binding
    if binding is None or audit.git is None or str(root) != audit.project_root:
        raise PathSecurityError("audit lacks its live inventory binding")
    report_payload = audit.as_json().encode("utf-8")
    if hashlib.sha256(report_payload).hexdigest() != binding.report_sha256:
        raise PathSecurityError("audit report differs from its publication binding")
    excluded = binding.excluded_files
    staged_identity = None
    if staged_report_path is not None:
        if (
            type(staged_report_path) is not str
            or re.fullmatch(r"reports/\.final_audit\.json\.[0-9a-f]{32}\.partial", staged_report_path) is None
            or staged_report_path in excluded
            or staged_report_path in dict(binding.file_identities)
        ):
            raise PathSecurityError("unsupported audit publication scratch path")
        directory = open_confined_directory_fd(root, Path("reports"), create=False)
        try:
            payload, metadata = _read_inventory_file(directory, Path(staged_report_path).name)
        except (OSError, OverflowError) as exc:
            raise PathSecurityError("audit publication scratch cannot be verified") from exc
        finally:
            os.close(directory)
        if (metadata.st_mode & 0o777) != 0o600 or payload != report_payload:
            raise PathSecurityError("audit publication scratch differs from report")
        staged_identity = _stable_file_metadata(metadata)
        excluded = (*excluded, staged_report_path)
    current = _inventory_state(root, excludes=binding.excludes, excluded_files=excluded)
    if not _same_audit_inventory(binding, current, staged_report=staged_report_path is not None):
        raise PathSecurityError("project or Git inventory changed after audit")
    if staged_report_path is not None:
        # Rebind the omitted file after the potentially long reinventory.
        payload = _read_bound_inventory_file(
            root, staged_report_path,
            file_identities={staged_report_path: staged_identity},
            directory_identities=current.directory_identities,
        )
        if payload != report_payload:
            raise PathSecurityError("audit publication scratch changed")
    _require_current_inventory_metadata(root, current)


def audit_project(
    root: Path,
    *,
    manifest_directories: Iterable[str] = ("runs", "artifacts", "reports"),
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
    excluded_files: Iterable[str] = DEFAULT_EXCLUDED_FILES,
) -> ProjectAudit:
    root = canonical_root(root)
    excludes, excluded_files = tuple(excludes), tuple(excluded_files)
    state = _inventory_state(
        root, excludes=excludes, excluded_files=excluded_files
    )
    records = state.records
    findings = list(state.findings)
    dispositions: list[ReviewedDisposition] = []
    session, git = _start_git_audit(root, state, excludes=excludes, excluded_files=excluded_files)
    binding = _AuditBinding(
        tuple(state.records), tuple(state.findings),
        tuple(sorted(state.file_identities.items())),
        tuple(sorted(state.directory_identities.items())),
        excludes, excluded_files,
    ) if session is not None or git is not None else None
    owned_session = session
    try:
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
            if is_reviewed_synthetic_fixture(record.path, payload):
                dispositions.append(ReviewedDisposition(
                    AuditFinding("secret_pattern", record.path, "secret_assignment"),
                    "REVIEWED_SYNTHETIC_REJECTION_FIXTURE", record.sha256,
                ))
            if session is not None and record.path.startswith(".git/"):
                try:
                    session.observe(record.path, payload)
                except Exception:
                    try:
                        session.close()
                    except Exception:
                        pass
                    session = None
                    git = _git_failure(records, "git_parser_observation_failure")
            if Path(record.path).suffix == ".json" and record.path.split("/", 1)[0] in set(manifest_directories):
                try:
                    outside = _outside_root_paths_in_payload(payload, root, relative=record.path)
                    provenance = _reviewed_interpreter_provenance(record.path, payload, safe_json_loads(payload))
                except (UnsafeSerializationError, UnicodeDecodeError) as exc:
                    findings.append(AuditFinding("invalid_manifest_json", record.path, type(exc).__name__))
                else:
                    findings.extend(
                        AuditFinding("outside_root_manifest_path", record.path, value) for value in outside
                    )
                    if provenance is not None:
                        dispositions.append(ReviewedDisposition(
                            AuditFinding("outside_root_manifest_path", record.path, provenance),
                            "RECORDED_INTERPRETER_PROVENANCE", record.sha256,
                            field_pointer="/interpreter_path",
                        ))
        if session is not None:
            try:
                git = session.finalize()
            except Exception:
                git = _git_failure(records, "git_parser_validation_failure")
            finally:
                try:
                    session.close()
                except Exception:
                    git = _git_failure(records, "git_parser_cleanup_failure")
    finally:
        if owned_session is not None:
            try:
                owned_session.close()
            except Exception:
                git = _git_failure(records, "git_parser_cleanup_failure")
    if binding is not None:
        current = _inventory_state(root, excludes=excludes, excluded_files=excluded_files)
        unchanged = _same_audit_inventory(binding, current)
        if unchanged:
            try:
                _require_current_inventory_metadata(root, current)
            except PathSecurityError:
                unchanged = False
        if not unchanged:
            findings.append(AuditFinding("changed_during_audit", ".", "full inventory changed during Git validation"))
            assert git is not None
            git = replace(
                git, binary_waiver_paths=(),
                findings=(*git.findings, GitAuditFinding("live_inventory_drift")),
            )
    if git is not None:
        if git.passed:
            waivers = frozenset(git.binary_waiver_paths)
            findings = [item for item in findings if not (
                item.check == "invalid_text_encoding"
                and item.detail == INVALID_UTF8_SECRET_SCAN_LABEL
                and item.path in waivers
            )]
        findings.extend(AuditFinding("git_validation", item.path, item.code) for item in git.findings)
        for item in git.reviewed_findings:
            finding = AuditFinding("git_validation", item.path, item.code)
            findings.append(finding)
            dispositions.append(ReviewedDisposition(
                finding, "REVIEWED_SYNTHETIC_REJECTION_FIXTURE",
                "d0e59a5f285498633b98c7c152e62b0ae1e0ed856b9d3f910af997e6ffdfceab",
                blob_oid=item.path.removeprefix(".git/decoded-objects/"),
            ))
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
    result = ProjectAudit(
        str(root),
        snapshot_digest(records),
        len(records),
        sum(record.size for record in records),
        tuple(records),
        tuple(findings),
        tuple(lockfiles),
        git,
        binding,
        tuple(dispositions) if git is not None else (),
    )
    if binding is not None:
        result = replace(result, _binding=replace(
            binding, report_sha256=hashlib.sha256(result._report_json(result._dispositions_eligible()).encode("utf-8")).hexdigest(),
        ))
    return result


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
        require_current_audit(audit, root)
        return atomic_write_bytes(
            root,
            relative,
            audit.as_json().encode(),
            overwrite=True,
            create_parents=False,
        )
    except PathSecurityError as exc:
        raise ValueError("audit target is not a confined regular file") from exc
