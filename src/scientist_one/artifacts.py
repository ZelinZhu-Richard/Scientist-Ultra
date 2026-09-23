"""Content-addressed, immutable Scientist-One artifact registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Iterable, Mapping, Sequence

try:  # Scientist-One's supported runtime is POSIX/macOS.
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported platforms
    fcntl = None  # type: ignore[assignment]

from .errors import (
    ArtifactCollisionError,
    ArtifactCorruptionError,
    ArtifactError,
    FrozenArtifactError,
    PathSecurityError,
    ValidationError,
)
from .models import ArtifactRef, LOGICAL_TYPE_RE, utc_now, validate_sha256
from .roles import Role
from .security import (
    PathPolicy,
    canonical_json_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
    sha256_bytes,
)


MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")
VALIDATION_RESULTS = frozenset({"PASS", "FAIL", "PENDING", "NOT_APPLICABLE"})

# Registry APIs return artifact content as bytes, so impose a per-object
# allocation ceiling independently of the resource controller's larger total
# storage quota.  Large scientific payloads belong behind a streaming provider
# with its own reviewed contract rather than this control-plane byte API.
MAX_ARTIFACT_OBJECT_BYTES = 64 * 1024 * 1024
MAX_REGISTRY_RECORDS = 10_000
# A full object-store walk includes one regular file per record plus at most
# 256 digest-prefix directories.  Leave additional room for bounded recovery
# inspection without permitting an attacker-controlled directory fan-out to
# grow the descriptor stack or name retention without limit.
MAX_REGISTRY_SCAN_ENTRIES = MAX_REGISTRY_RECORDS + 1_024
MAX_REGISTRY_VERIFICATION_CACHE_ENTRIES = 2_048
MAX_ARTIFACT_PARENTS = 256
MAX_PROVENANCE_DEPTH = 2_048
MAX_PROVENANCE_EDGES = 250_000
LOGICAL_QUARANTINE_SCHEMA_VERSION = "artifact-logical-quarantine/v1"
LOGICAL_QUARANTINE_METADATA_SUFFIX = ".metadata.json"


def artifact_record_hash(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes({key: item for key, item in value.items() if key != "record_hash"}))


@dataclass(frozen=True)
class ArtifactRecord:
    sha256: str
    path: str
    relative_path: str
    metadata_path: str
    logical_type: str
    schema_version: str
    mime_type: str
    size: int
    origin: str
    creator_role: Role
    creation_command: tuple[str, ...]
    parent_artifacts: tuple[str, ...]
    validation_result: str
    frozen: bool
    created_at: str
    record_hash: str | None = None

    def __post_init__(self) -> None:
        validate_sha256(self.sha256, "artifact SHA-256")
        for label, value in (("path", self.path), ("relative path", self.relative_path), ("metadata path", self.metadata_path)):
            if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
                raise ValidationError(f"artifact {label} must be safe and project-relative")
        if self.path != self.relative_path:
            raise ValidationError("artifact path aliases disagree")
        if not isinstance(self.logical_type, str) or not LOGICAL_TYPE_RE.fullmatch(self.logical_type):
            raise ValidationError("invalid artifact logical type")
        if not isinstance(self.schema_version, str) or not self.schema_version or len(self.schema_version) > 32:
            raise ValidationError("invalid artifact schema version")
        if not isinstance(self.mime_type, str) or not MIME_RE.fullmatch(self.mime_type):
            raise ValidationError("invalid artifact MIME type")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
            or self.size > MAX_ARTIFACT_OBJECT_BYTES
        ):
            raise ValidationError("artifact size exceeds the bounded byte-registry contract")
        if not isinstance(self.origin, str) or not self.origin.strip() or len(self.origin) > 1024:
            raise ValidationError("artifact origin must be non-empty bounded text")
        if not isinstance(self.creator_role, Role):
            raise ValidationError("artifact creator role must be a Role")
        if not isinstance(self.creation_command, tuple) or not self.creation_command or any(
            not isinstance(item, str) or not item or "\x00" in item or "\n" in item or "\r" in item
            for item in self.creation_command
        ):
            raise ValidationError("creation command must be a non-empty inert argv tuple")
        if not isinstance(self.parent_artifacts, tuple):
            raise ValidationError("parent artifact hashes must be a tuple")
        for digest in self.parent_artifacts:
            validate_sha256(digest, "parent artifact SHA-256")
        if len(set(self.parent_artifacts)) != len(self.parent_artifacts):
            raise ValidationError("parent artifact hashes must be unique")
        if len(self.parent_artifacts) > MAX_ARTIFACT_PARENTS:
            raise ValidationError("artifact has too many parent records")
        if self.sha256 in self.parent_artifacts:
            raise ValidationError("artifact cannot be its own parent")
        if self.validation_result not in VALIDATION_RESULTS:
            raise ValidationError("unknown artifact validation result")
        if not isinstance(self.frozen, bool):
            raise ValidationError("artifact frozen flag must be boolean")
        if self.frozen and self.validation_result != "PASS":
            raise ValidationError("only validated artifacts may be frozen")
        if not isinstance(self.created_at, str) or not self.created_at.endswith("Z"):
            raise ValidationError("artifact creation time must be UTC")
        try:
            parsed_created_at = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("artifact creation time is malformed") from exc
        if parsed_created_at.utcoffset() is None or parsed_created_at.utcoffset().total_seconds() != 0:
            raise ValidationError("artifact creation time must be UTC")
        computed = artifact_record_hash(self.to_dict(include_record_hash=False))
        if self.record_hash is None:
            object.__setattr__(self, "record_hash", computed)
        else:
            validate_sha256(self.record_hash, "artifact metadata SHA-256")
            if self.record_hash != computed:
                raise ArtifactCorruptionError("artifact metadata hash mismatch")

    def to_dict(self, *, include_record_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "sha256": self.sha256,
            "path": self.path,
            "relative_path": self.relative_path,
            "metadata_path": self.metadata_path,
            "logical_type": self.logical_type,
            "schema_version": self.schema_version,
            "mime_type": self.mime_type,
            "size": self.size,
            "origin": self.origin,
            "creator_role": self.creator_role.value,
            "creation_command": list(self.creation_command),
            "parent_artifacts": list(self.parent_artifacts),
            "validation_result": self.validation_result,
            "frozen": self.frozen,
            "created_at": self.created_at,
        }
        if include_record_hash:
            result["record_hash"] = self.record_hash
        return result

    def to_ref(self) -> ArtifactRef:
        return ArtifactRef(
            sha256=self.sha256,
            logical_type=self.logical_type,
            schema_version=self.schema_version,
            size=self.size,
            frozen=self.frozen,
            path=self.path,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRecord":
        if not isinstance(value, Mapping):
            raise ArtifactCorruptionError("artifact metadata must be an object")
        required = {
            "sha256",
            "path",
            "relative_path",
            "metadata_path",
            "logical_type",
            "schema_version",
            "mime_type",
            "size",
            "origin",
            "creator_role",
            "creation_command",
            "parent_artifacts",
            "validation_result",
            "frozen",
            "created_at",
            "record_hash",
        }
        if set(value) != required:
            raise ArtifactCorruptionError("artifact metadata schema is incomplete or has unknown fields")
        try:
            return cls(
                sha256=value["sha256"],
                path=value["path"],
                relative_path=value["relative_path"],
                metadata_path=value["metadata_path"],
                logical_type=value["logical_type"],
                schema_version=value["schema_version"],
                mime_type=value["mime_type"],
                size=value["size"],
                origin=value["origin"],
                creator_role=Role(value["creator_role"]),
                creation_command=tuple(value["creation_command"]),
                parent_artifacts=tuple(value["parent_artifacts"]),
                validation_result=value["validation_result"],
                frozen=value["frozen"],
                created_at=value["created_at"],
                record_hash=value["record_hash"],
            )
        except ArtifactCorruptionError:
            raise
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ArtifactCorruptionError("malformed artifact metadata") from exc


@dataclass(frozen=True)
class RegistryValidationResult:
    valid: bool
    records: tuple[ArtifactRecord, ...]
    errors: tuple[str, ...] = ()
    orphan_paths: tuple[str, ...] = ()

    @property
    def count(self) -> int:
        return len(self.records)

    def __bool__(self) -> bool:
        return self.valid


@dataclass(frozen=True)
class _RegistryMutationLock:
    root_fd: int
    namespace_fds: tuple[int, ...]
    parent_versions: tuple[tuple[int, int], ...]
    parent_change_times: tuple[int, ...]
    base_change_time: list[int]
    root_lock_fd: int
    root_lock_identity: tuple[int, int]
    mutation_lock_fd: int
    mutation_lock_identity: tuple[int, int]
    directory_fds: dict[tuple[str, ...], int]
    directory_identities: dict[tuple[str, ...], tuple[int, int]]
    directory_change_times: dict[tuple[str, ...], int]


@dataclass(frozen=True)
class _RegistryDirectorySnapshot:
    key: tuple[str, ...]
    change_time: int
    entries: tuple[tuple[str, int, int, int], ...]


class ArtifactRegistry:
    """Store bytes and immutable metadata beneath a project-local base path."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        base_path: str | os.PathLike[str] = "artifacts/registry",
    ) -> None:
        self.policy = PathPolicy(root)
        raw = Path(base_path)
        if raw.is_absolute():
            try:
                raw = raw.relative_to(self.policy.root)
            except ValueError as exc:
                raise ArtifactError("artifact registry is outside the project root") from exc
        if ".." in raw.parts or not raw.parts:
            raise ArtifactError("invalid artifact registry path")
        self.base_path = raw
        self.objects_path = raw / "objects"
        self.metadata_path = raw / "metadata"
        self.quarantine_path = raw / "quarantine"
        secure_directory(self.policy.root, self.objects_path, create=True)
        secure_directory(self.policy.root, self.metadata_path, create=True)
        root_metadata = os.stat(self.policy.root, follow_symlinks=False)
        self._root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        base_fd = open_confined_directory_fd(
            self.policy.root, self.base_path, create=False
        )
        try:
            base_metadata = os.fstat(base_fd)
            self._base_identity = (base_metadata.st_dev, base_metadata.st_ino)
        finally:
            os.close(base_fd)
        self._metadata_verification_cache: dict[
            str,
            tuple[tuple[int, int, int, int, int, int, int], ArtifactRecord],
        ] = {}
        self._content_verification_cache: dict[
            str,
            tuple[int, int, int, int, int, int, int],
        ] = {}
        self._object_relative_cache: dict[str, Path] = {}
        self._metadata_relative_cache: dict[str, Path] = {}
        self._directory_key_cache: dict[Path, tuple[str, ...]] = {}

    @staticmethod
    def _bounded_cache_store(
        cache: dict[Any, Any],
        key: Any,
        value: Any,
    ) -> None:
        if (
            key not in cache
            and len(cache) >= MAX_REGISTRY_VERIFICATION_CACHE_ENTRIES
        ):
            cache.clear()
        cache[key] = value

    @staticmethod
    def _directory_version(metadata: os.stat_result) -> tuple[int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
        )

    def _open_mutation_lock(self) -> _RegistryMutationLock:
        if fcntl is None:
            raise ArtifactError("registry mutation locking is unavailable")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        root_fd: int | None = None
        namespace_fds: list[int] = []
        directory_fds: dict[tuple[str, ...], int] = {}
        root_lock_fd: int | None = None
        mutation_lock_fd: int | None = None
        root_locked = False
        mutation_locked = False
        try:
            root_fd = os.open(self.policy.root, directory_flags)
            root_metadata = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != self._root_identity
            ):
                raise ArtifactError("artifact registry project root identity changed")

            lock_flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            root_lock_name = ".scientist-one-artifact-registry.lock"
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
                raise ArtifactError("registry namespace lock is not a private regular file")
            fcntl.flock(root_lock_fd, fcntl.LOCK_EX)
            root_locked = True
            root_lock_named = os.stat(
                root_lock_name, dir_fd=root_fd, follow_symlinks=False
            )
            if root_lock_identity != (
                root_lock_named.st_dev,
                root_lock_named.st_ino,
            ):
                raise ArtifactError("registry namespace lock identity changed")

            parent_versions: list[tuple[int, int]] = []
            parent_change_times: list[int] = []
            parent_fd = root_fd
            for component in self.base_path.parts:
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
                    raise ArtifactError("artifact registry namespace is unsafe")
                namespace_fds.append(child_fd)
                parent_fd = child_fd
            base_metadata = os.fstat(namespace_fds[-1])
            if (base_metadata.st_dev, base_metadata.st_ino) != self._base_identity:
                raise ArtifactError("artifact registry namespace identity changed")

            mutation_lock_fd = os.open(
                ".registry.lock", lock_flags, 0o600, dir_fd=namespace_fds[-1]
            )
            mutation_metadata = os.fstat(mutation_lock_fd)
            mutation_named = os.stat(
                ".registry.lock",
                dir_fd=namespace_fds[-1],
                follow_symlinks=False,
            )
            mutation_lock_identity = (
                mutation_metadata.st_dev,
                mutation_metadata.st_ino,
            )
            if (
                not stat.S_ISREG(mutation_metadata.st_mode)
                or mutation_metadata.st_nlink != 1
                or (mutation_metadata.st_mode & 0o077) != 0
                or mutation_lock_identity
                != (mutation_named.st_dev, mutation_named.st_ino)
            ):
                raise ArtifactError("registry lock is not a private regular file")
            fcntl.flock(mutation_lock_fd, fcntl.LOCK_EX)
            mutation_locked = True
            directory_identities: dict[tuple[str, ...], tuple[int, int]] = {}
            directory_change_times: dict[tuple[str, ...], int] = {}
            for name in ("objects", "metadata"):
                child_fd = os.open(name, directory_flags, dir_fd=namespace_fds[-1])
                child_metadata = os.fstat(child_fd)
                named_child = os.stat(
                    name,
                    dir_fd=namespace_fds[-1],
                    follow_symlinks=False,
                )
                identity = (child_metadata.st_dev, child_metadata.st_ino)
                if (
                    not stat.S_ISDIR(child_metadata.st_mode)
                    or identity != (named_child.st_dev, named_child.st_ino)
                ):
                    os.close(child_fd)
                    raise ArtifactError(
                        "artifact registry child namespace is unsafe"
                    )
                key = (name,)
                directory_fds[key] = child_fd
                directory_identities[key] = identity
                directory_change_times[key] = child_metadata.st_ctime_ns
            guard = _RegistryMutationLock(
                root_fd=root_fd,
                namespace_fds=tuple(namespace_fds),
                parent_versions=tuple(parent_versions),
                parent_change_times=tuple(parent_change_times),
                base_change_time=[os.fstat(namespace_fds[-1]).st_ctime_ns],
                root_lock_fd=root_lock_fd,
                root_lock_identity=root_lock_identity,
                mutation_lock_fd=mutation_lock_fd,
                mutation_lock_identity=mutation_lock_identity,
                directory_fds=directory_fds,
                directory_identities=directory_identities,
                directory_change_times=directory_change_times,
            )
            self._verify_mutation_namespace(guard)
            return guard
        except Exception as exc:
            for descriptor in directory_fds.values():
                os.close(descriptor)
            if mutation_lock_fd is not None:
                if mutation_locked:
                    fcntl.flock(mutation_lock_fd, fcntl.LOCK_UN)
                os.close(mutation_lock_fd)
            for descriptor in reversed(namespace_fds):
                os.close(descriptor)
            if root_lock_fd is not None:
                if root_locked:
                    fcntl.flock(root_lock_fd, fcntl.LOCK_UN)
                os.close(root_lock_fd)
            if root_fd is not None:
                os.close(root_fd)
            if isinstance(exc, ArtifactError):
                raise
            raise ArtifactError("registry mutation lock cannot be acquired") from exc

    def _registry_directory_key(self, relative: Path) -> tuple[str, ...]:
        cached = self._directory_key_cache.get(relative)
        if cached is not None:
            return cached
        try:
            tail = relative.relative_to(self.base_path)
        except ValueError as exc:
            raise ArtifactError(
                "registry path is outside its pinned namespace"
            ) from exc
        if any(component in {"", ".", ".."} for component in tail.parts):
            raise ArtifactError("registry path contains an unsafe component")
        key = tuple(tail.parts)
        self._bounded_cache_store(
            self._directory_key_cache,
            relative,
            key,
        )
        return key

    def _verify_pinned_directory(
        self,
        guard: _RegistryMutationLock,
        key: tuple[str, ...],
        *,
        check_change_time: bool = True,
    ) -> None:
        if not key:
            metadata = os.fstat(guard.namespace_fds[-1])
            if (
                (metadata.st_dev, metadata.st_ino) != self._base_identity
                or (
                    check_change_time
                    and metadata.st_ctime_ns != guard.base_change_time[0]
                )
            ):
                raise ArtifactError(
                    "artifact registry base namespace changed during operation"
                )
            return
        descriptor = guard.directory_fds.get(key)
        identity = guard.directory_identities.get(key)
        if descriptor is None or identity is None:
            raise ArtifactError("artifact registry directory is not pinned")
        parent_fd = (
            guard.namespace_fds[-1]
            if len(key) == 1
            else guard.directory_fds.get(key[:-1])
        )
        if parent_fd is None:
            raise ArtifactError("artifact registry directory parent is not pinned")
        try:
            metadata = os.fstat(descriptor)
            named = os.stat(
                key[-1], dir_fd=parent_fd, follow_symlinks=False
            )
        except OSError as exc:
            raise ArtifactError(
                "artifact registry directory name changed"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != identity
            or identity != (named.st_dev, named.st_ino)
            or (
                check_change_time
                and metadata.st_ctime_ns
                != guard.directory_change_times.get(key)
            )
        ):
            raise ArtifactError(
                "artifact registry child namespace changed during operation"
            )

    def _verify_pinned_directories(
        self, guard: _RegistryMutationLock
    ) -> None:
        self._verify_pinned_directory(guard, ())
        for key in sorted(guard.directory_fds, key=lambda item: (len(item), item)):
            self._verify_pinned_directory(guard, key)

    def _prepare_registry_directory_mutation(
        self,
        guard: _RegistryMutationLock,
        key: tuple[str, ...],
    ) -> _RegistryDirectorySnapshot:
        self._verify_pinned_directory(guard, ())
        for depth in range(1, len(key) + 1):
            self._verify_pinned_directory(guard, key[:depth])
        return self._snapshot_registry_directory(guard, key)

    def _snapshot_registry_directory(
        self,
        guard: _RegistryMutationLock,
        key: tuple[str, ...],
        *,
        check_change_time: bool = True,
    ) -> _RegistryDirectorySnapshot:
        self._verify_pinned_directory(
            guard,
            key,
            check_change_time=check_change_time,
        )
        descriptor = (
            guard.namespace_fds[-1]
            if not key
            else guard.directory_fds[key]
        )
        before = os.fstat(descriptor)
        entries: list[tuple[str, int, int, int]] = []
        try:
            with os.scandir(descriptor) as names:
                for entry in names:
                    if len(entries) >= MAX_REGISTRY_SCAN_ENTRIES:
                        raise ArtifactError(
                            "registry mutation namespace exceeds its safety limit"
                        )
                    name = entry.name
                    if name in {"", ".", ".."} or "/" in name:
                        raise ArtifactError(
                            "registry mutation namespace contains an unsafe name"
                        )
                    metadata = os.stat(
                        name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    entries.append(
                        (
                            name,
                            metadata.st_dev,
                            metadata.st_ino,
                            stat.S_IFMT(metadata.st_mode),
                        )
                    )
        except OSError as exc:
            raise ArtifactError(
                "registry mutation namespace cannot be inspected"
            ) from exc
        after = os.fstat(descriptor)
        if (
            before.st_ctime_ns != after.st_ctime_ns
            or (before.st_dev, before.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise ArtifactError(
                "registry mutation namespace changed while inspected"
            )
        entries.sort()
        if len({entry[0] for entry in entries}) != len(entries):
            raise ArtifactError("registry mutation namespace is ambiguous")
        return _RegistryDirectorySnapshot(
            key=key,
            change_time=after.st_ctime_ns,
            entries=tuple(entries),
        )

    def _finish_registry_directory_mutation(
        self,
        guard: _RegistryMutationLock,
        snapshot: _RegistryDirectorySnapshot,
        *,
        added: tuple[tuple[str, tuple[int, int, int]], ...] = (),
        removed: tuple[str, ...] = (),
    ) -> None:
        key = snapshot.key
        if len({name for name, _identity in added}) != len(added):
            raise ArtifactError("registry mutation additions are ambiguous")
        if len(set(removed)) != len(removed):
            raise ArtifactError("registry mutation removals are ambiguous")
        if {name for name, _identity in added} & set(removed):
            raise ArtifactError("registry mutation delta is contradictory")
        before = {
            name: (device, inode, mode)
            for name, device, inode, mode in snapshot.entries
        }
        expected = dict(before)
        for name in removed:
            if name not in expected:
                raise ArtifactError(
                    "registry mutation removed an unadmitted entry"
                )
            expected.pop(name)
        for name, identity in added:
            if name in expected:
                raise ArtifactError(
                    "registry mutation replaced an admitted entry"
                )
            expected[name] = identity
        observed = self._snapshot_registry_directory(
            guard,
            key,
            check_change_time=False,
        )
        observed_entries = {
            name: (device, inode, mode)
            for name, device, inode, mode in observed.entries
        }
        if observed_entries != expected:
            raise ArtifactError(
                "registry mutation changed more than its exact admitted namespace delta"
            )
        if key:
            guard.directory_change_times[key] = observed.change_time
        else:
            guard.base_change_time[0] = observed.change_time
        self._verify_pinned_directory(guard, key)

    def _verify_mutation_namespace(self, guard: _RegistryMutationLock) -> None:
        root_metadata = os.fstat(guard.root_fd)
        try:
            named_root = os.stat(self.policy.root, follow_symlinks=False)
        except OSError as exc:
            raise ArtifactError("artifact registry project root name changed") from exc
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_dev, root_metadata.st_ino) != self._root_identity
            or (named_root.st_dev, named_root.st_ino) != self._root_identity
        ):
            raise ArtifactError("artifact registry project root identity changed")

        root_lock_metadata = os.fstat(guard.root_lock_fd)
        root_lock_named = os.stat(
            ".scientist-one-artifact-registry.lock",
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
            raise ArtifactError("registry namespace lock identity changed")

        parent_fds = (guard.root_fd,) + guard.namespace_fds[:-1]
        for component, parent_fd, child_fd, parent_version in zip(
            self.base_path.parts,
            parent_fds,
            guard.namespace_fds,
            guard.parent_versions,
        ):
            if self._directory_version(os.fstat(parent_fd)) != parent_version:
                raise ArtifactError("artifact registry parent namespace changed")
            child_metadata = os.fstat(child_fd)
            try:
                named_child = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise ArtifactError("artifact registry namespace name changed") from exc
            if (
                not stat.S_ISDIR(child_metadata.st_mode)
                or (child_metadata.st_dev, child_metadata.st_ino)
                != (named_child.st_dev, named_child.st_ino)
            ):
                raise ArtifactError("artifact registry namespace identity changed")
        base_metadata = os.fstat(guard.namespace_fds[-1])
        if (base_metadata.st_dev, base_metadata.st_ino) != self._base_identity:
            raise ArtifactError("artifact registry namespace identity changed")

        mutation_metadata = os.fstat(guard.mutation_lock_fd)
        try:
            mutation_named = os.stat(
                ".registry.lock",
                dir_fd=guard.namespace_fds[-1],
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ArtifactError("registry lock name changed") from exc
        if (
            not stat.S_ISREG(mutation_metadata.st_mode)
            or mutation_metadata.st_nlink != 1
            or (mutation_metadata.st_dev, mutation_metadata.st_ino)
            != guard.mutation_lock_identity
            or guard.mutation_lock_identity
            != (mutation_named.st_dev, mutation_named.st_ino)
        ):
            raise ArtifactError("registry lock identity changed")
        self._verify_pinned_directories(guard)

    def _verify_no_parent_namespace_aba(
        self, guard: _RegistryMutationLock
    ) -> None:
        parent_fds = (guard.root_fd,) + guard.namespace_fds[:-1]
        for parent_fd, admitted_ctime in zip(
            parent_fds, guard.parent_change_times
        ):
            if os.fstat(parent_fd).st_ctime_ns != admitted_ctime:
                raise ArtifactError(
                    "artifact registry parent namespace changed during operation"
                )

    def _unlock_mutation(self, guard: _RegistryMutationLock) -> None:
        error: BaseException | None = None
        try:
            self._verify_no_parent_namespace_aba(guard)
            self._verify_mutation_namespace(guard)
        except BaseException as exc:
            error = exc
        finally:
            if fcntl is not None:
                fcntl.flock(guard.mutation_lock_fd, fcntl.LOCK_UN)
            os.close(guard.mutation_lock_fd)
            for key in sorted(
                guard.directory_fds,
                key=lambda item: (len(item), item),
                reverse=True,
            ):
                os.close(guard.directory_fds[key])
            for descriptor in reversed(guard.namespace_fds):
                os.close(descriptor)
            if fcntl is not None:
                fcntl.flock(guard.root_lock_fd, fcntl.LOCK_UN)
            os.close(guard.root_lock_fd)
            os.close(guard.root_fd)
        if error is not None:
            raise error

    def _object_relative(self, digest: str) -> Path:
        validate_sha256(digest, "artifact SHA-256")
        cached = self._object_relative_cache.get(digest)
        if cached is None:
            cached = self.objects_path / digest[:2] / digest
            self._bounded_cache_store(
                self._object_relative_cache,
                digest,
                cached,
            )
        return cached

    def _metadata_relative(self, digest: str) -> Path:
        validate_sha256(digest, "artifact SHA-256")
        cached = self._metadata_relative_cache.get(digest)
        if cached is None:
            cached = self.metadata_path / digest[:2] / f"{digest}.json"
            self._bounded_cache_store(
                self._metadata_relative_cache,
                digest,
                cached,
            )
        return cached

    def _open_registry_directory(
        self,
        guard: _RegistryMutationLock,
        relative: Path,
        *,
        create: bool,
    ) -> int:
        target_key = self._registry_directory_key(relative)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        if target_key in guard.directory_fds:
            # The descriptor is already pinned for this serialized operation.
            # File reads bind held/name identity, mutation paths call the
            # explicit prepare check, and unlock reattests every cached
            # directory.  Rechecking the same directory before every cached
            # metadata/content stat is redundant and quadratic for dense
            # provenance replay.
            return os.dup(guard.directory_fds[target_key])
        self._verify_pinned_directory(guard, ())
        if not target_key:
            return os.dup(guard.namespace_fds[-1])
        for depth, component in enumerate(target_key, start=1):
            key = target_key[:depth]
            if key in guard.directory_fds:
                self._verify_pinned_directory(guard, key)
                continue
            parent_key = key[:-1]
            parent_fd = (
                guard.namespace_fds[-1]
                if not parent_key
                else guard.directory_fds[parent_key]
            )
            self._verify_pinned_directory(guard, parent_key)
            try:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                mutation = self._prepare_registry_directory_mutation(
                    guard, parent_key
                )
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                except FileExistsError as exc:
                    raise ArtifactError(
                        "registry directory appeared during creation"
                    ) from exc
                created = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                self._finish_registry_directory_mutation(
                    guard,
                    mutation,
                    added=(
                        (
                            component,
                            (
                                created.st_dev,
                                created.st_ino,
                                stat.S_IFMT(created.st_mode),
                            ),
                        ),
                    ),
                )
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            try:
                metadata = os.fstat(next_fd)
                named = os.stat(
                    component, dir_fd=parent_fd, follow_symlinks=False
                )
                identity = (metadata.st_dev, metadata.st_ino)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or identity != (named.st_dev, named.st_ino)
                ):
                    raise ArtifactError(
                        "registry directory changed or is unsafe"
                    )
                self._verify_pinned_directory(guard, parent_key)
                guard.directory_fds[key] = next_fd
                guard.directory_identities[key] = identity
                guard.directory_change_times[key] = metadata.st_ctime_ns
            except Exception:
                os.close(next_fd)
                raise
        self._verify_pinned_directory(guard, target_key)
        return os.dup(guard.directory_fds[target_key])

    def _open_registry_parent(
        self,
        guard: _RegistryMutationLock,
        relative: Path,
        *,
        create: bool,
    ) -> tuple[int, str]:
        if relative.name in {"", ".", ".."}:
            raise ArtifactError("registry filename is invalid")
        return (
            self._open_registry_directory(
                guard, relative.parent, create=create
            ),
            relative.name,
        )

    @staticmethod
    def _regular_file_fingerprint(
        metadata: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @classmethod
    def _stat_regular_at(
        cls,
        directory_fd: int,
        name: str,
        *,
        max_bytes: int,
    ) -> tuple[int, int, int, int, int, int, int]:
        try:
            metadata = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ArtifactCorruptionError(
                "registry entry cannot be inspected safely"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > max_bytes
        ):
            raise ArtifactCorruptionError(
                "registry entry is not a private bounded regular file"
            )
        return cls._regular_file_fingerprint(metadata)

    @classmethod
    def _read_regular_at_with_fingerprint(
        cls,
        directory_fd: int,
        name: str,
        *,
        max_bytes: int,
        read_bytes: bool = True,
    ) -> tuple[bytes | None, tuple[int, int, int, int, int, int, int]]:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            before = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or before.st_size > max_bytes
            ):
                raise ArtifactCorruptionError(
                    "registry entry is not a private bounded regular file"
                )
            chunks: list[bytes] | None = [] if read_bytes else None
            total = 0
            if chunks is not None:
                while True:
                    chunk = os.read(
                        descriptor,
                        min(1024 * 1024, max_bytes - total + 1),
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        raise ArtifactCorruptionError(
                            "registry entry exceeds its size limit"
                        )
            after = os.fstat(descriptor)
            final_named = os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                cls._regular_file_fingerprint(before)
                != cls._regular_file_fingerprint(after)
                or (after.st_dev, after.st_ino)
                != (final_named.st_dev, final_named.st_ino)
            ):
                raise ArtifactCorruptionError("registry entry changed while read")
            return (
                None if chunks is None else b"".join(chunks),
                cls._regular_file_fingerprint(after),
            )
        finally:
            os.close(descriptor)

    @classmethod
    def _read_regular_at(
        cls,
        directory_fd: int,
        name: str,
        *,
        max_bytes: int,
    ) -> bytes:
        content, _fingerprint = cls._read_regular_at_with_fingerprint(
            directory_fd,
            name,
            max_bytes=max_bytes,
        )
        if content is None:  # pragma: no cover - read_bytes defaults true
            raise ArtifactCorruptionError("registry entry bytes were not read")
        return content

    def _read_registry_bytes(
        self,
        guard: _RegistryMutationLock,
        relative: Path,
        *,
        max_bytes: int = MAX_ARTIFACT_OBJECT_BYTES,
    ) -> bytes:
        directory_fd, name = self._open_registry_parent(
            guard, relative, create=False
        )
        try:
            return self._read_regular_at(
                directory_fd, name, max_bytes=max_bytes
            )
        finally:
            os.close(directory_fd)

    def _registry_entry_exists(
        self, guard: _RegistryMutationLock, relative: Path
    ) -> bool:
        directory_fd, name = self._open_registry_parent(
            guard, relative, create=False
        )
        try:
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return True
        finally:
            os.close(directory_fd)

    def _publish_immutable(
        self,
        guard: _RegistryMutationLock,
        relative: Path,
        data: bytes,
    ) -> None:
        directory_key = self._registry_directory_key(relative.parent)
        directory_fd, name = self._open_registry_parent(
            guard, relative, create=True
        )
        temporary_name = f".{name}.{secrets.token_hex(16)}.partial"
        descriptor: int | None = None
        temporary_exists = False
        try:
            try:
                existing = self._read_regular_at(
                    directory_fd, name, max_bytes=len(data)
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing == data:
                    return
                raise ArtifactCollisionError(
                    "immutable registry destination already contains different bytes"
                )
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            mutation = self._prepare_registry_directory_mutation(
                guard, directory_key
            )
            descriptor = os.open(
                temporary_name, flags, 0o600, dir_fd=directory_fd
            )
            temporary_exists = True
            temporary_metadata = os.fstat(descriptor)
            self._finish_registry_directory_mutation(
                guard,
                mutation,
                added=(
                    (
                        temporary_name,
                        (
                            temporary_metadata.st_dev,
                            temporary_metadata.st_ino,
                            stat.S_IFMT(temporary_metadata.st_mode),
                        ),
                    ),
                ),
            )
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("short registry write")
                written += count
            os.fsync(descriptor)
            held = os.fstat(descriptor)
            named = os.stat(
                temporary_name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_nlink != 1
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise ArtifactCollisionError(
                    "registry temporary identity changed before publication"
                )
            mutation = self._prepare_registry_directory_mutation(
                guard, directory_key
            )
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                self._finish_registry_directory_mutation(guard, mutation)
                raise ArtifactCollisionError(
                    "registry destination appeared during publication"
                )
            else:
                target = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                linked = os.fstat(descriptor)
                if (
                    linked.st_nlink != 2
                    or (linked.st_dev, linked.st_ino)
                    != (target.st_dev, target.st_ino)
                ):
                    raise ArtifactCollisionError(
                        "registry publication identity is inconsistent"
                    )
                self._finish_registry_directory_mutation(
                    guard,
                    mutation,
                    added=(
                        (
                            name,
                            (
                                target.st_dev,
                                target.st_ino,
                                stat.S_IFMT(target.st_mode),
                            ),
                        ),
                    ),
                )
            mutation = self._prepare_registry_directory_mutation(
                guard, directory_key
            )
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_exists = False
            self._finish_registry_directory_mutation(
                guard,
                mutation,
                removed=(temporary_name,),
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            held_bytes = bytearray()
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, len(data) + 1))
                if not chunk:
                    break
                held_bytes.extend(chunk)
                if len(held_bytes) > len(data):
                    raise ArtifactCollisionError(
                        "published registry entry changed size"
                    )
            if bytes(held_bytes) != data:
                raise ArtifactCollisionError(
                    "published registry entry differs from source bytes"
                )
            final = self._read_regular_at(
                directory_fd, name, max_bytes=len(data)
            )
            if final != data:
                raise ArtifactCollisionError(
                    "published registry entry cannot be verified"
                )
            os.fsync(directory_fd)
        except OSError as exc:
            raise ArtifactCollisionError("registry publication failed") from exc
        finally:
            if temporary_exists:
                try:
                    mutation = self._prepare_registry_directory_mutation(
                        guard, directory_key
                    )
                    os.unlink(temporary_name, dir_fd=directory_fd)
                    self._finish_registry_directory_mutation(
                        guard,
                        mutation,
                        removed=(temporary_name,),
                    )
                except (OSError, ArtifactError):
                    pass
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory_fd)

    def _read_content(
        self, guard: _RegistryMutationLock, relative: Path
    ) -> bytes:
        try:
            return self._read_registry_bytes(guard, relative)
        except (OSError, ArtifactError) as exc:
            if isinstance(exc, ArtifactCorruptionError):
                raise
            raise ArtifactCorruptionError(
                "artifact content cannot be opened safely"
            ) from exc

    def _semantic_match(
        self,
        record: ArtifactRecord,
        *,
        logical_type: str,
        schema_version: str,
        mime_type: str,
        origin: str,
        creator_role: Role,
        creation_command: tuple[str, ...],
        parents: tuple[str, ...],
        validation_result: str,
        frozen: bool,
    ) -> bool:
        return (
            record.logical_type == logical_type
            and record.schema_version == schema_version
            and record.mime_type == mime_type
            and record.origin == origin
            and record.creator_role is creator_role
            and record.creation_command == creation_command
            and record.parent_artifacts == parents
            and record.validation_result == validation_result
            and record.frozen is frozen
        )

    def put_bytes(
        self,
        data: bytes,
        *,
        logical_type: str,
        origin: str,
        creator_role: Role,
        creation_command: Sequence[str] = ("scientist-one", "internal"),
        parent_artifacts: Iterable[str] = (),
        schema_version: str = "1.0",
        mime_type: str = "application/octet-stream",
        validation_result: str = "PASS",
        frozen: bool = True,
        created_at: str | None = None,
    ) -> ArtifactRecord:
        lock = self._open_mutation_lock()
        try:
            record = self._put_bytes_locked(
                lock,
                data,
                logical_type=logical_type,
                origin=origin,
                creator_role=creator_role,
                creation_command=creation_command,
                parent_artifacts=parent_artifacts,
                schema_version=schema_version,
                mime_type=mime_type,
                validation_result=validation_result,
                frozen=frozen,
                created_at=created_at,
            )
            self._verify_mutation_namespace(lock)
            return record
        finally:
            self._unlock_mutation(lock)

    def _put_bytes_locked(
        self,
        guard: _RegistryMutationLock,
        data: bytes,
        *,
        logical_type: str,
        origin: str,
        creator_role: Role,
        creation_command: Sequence[str],
        parent_artifacts: Iterable[str],
        schema_version: str,
        mime_type: str,
        validation_result: str,
        frozen: bool,
        created_at: str | None,
    ) -> ArtifactRecord:
        if not isinstance(data, bytes):
            raise ArtifactError("artifact content must be bytes")
        if len(data) > MAX_ARTIFACT_OBJECT_BYTES:
            raise ArtifactError("artifact content exceeds the bounded byte-registry contract")
        digest = sha256_bytes(data)
        command = tuple(creation_command)
        parents = tuple(parent_artifacts)
        for parent in parents:
            validate_sha256(parent, "parent artifact SHA-256")
            try:
                self._verify_graph(guard, (parent,))
            except ArtifactError as exc:
                raise ArtifactError("parent artifact is absent or corrupt") from exc
        object_relative = self._object_relative(digest)
        metadata_relative = self._metadata_relative(digest)
        directory_fd = self._open_registry_directory(
            guard, object_relative.parent, create=True
        )
        os.close(directory_fd)
        directory_fd = self._open_registry_directory(
            guard, metadata_relative.parent, create=True
        )
        os.close(directory_fd)

        # An existing metadata record defines the immutable identity. Verify it
        # before accepting an idempotent registration.
        if self._registry_entry_exists(guard, metadata_relative):
            existing = self._get_metadata_locked(guard, digest)
            self._verify_graph(guard, (digest,))
            if self._semantic_match(
                existing,
                logical_type=logical_type,
                schema_version=schema_version,
                mime_type=mime_type,
                origin=origin,
                creator_role=creator_role,
                creation_command=command,
                parents=parents,
                validation_result=validation_result,
                frozen=frozen,
            ):
                return existing
            if existing.frozen:
                raise FrozenArtifactError("frozen artifact metadata cannot be changed")
            raise ArtifactCollisionError("content digest already has different metadata")

        try:
            current = self._verify_all_locked(guard, raise_on_error=True)
        except ArtifactCorruptionError as exc:
            raise ArtifactCollisionError(
                "artifact registry is corrupt before publication"
            ) from exc
        if current.count >= MAX_REGISTRY_RECORDS:
            raise ArtifactError("artifact registry record limit would be exceeded")

        try:
            self._publish_immutable(guard, object_relative, data)
        except ArtifactError as exc:
            # Inspecting a conflicting path is safe and distinguishes corruption
            # from an ordinary metadata conflict.
            try:
                existing_bytes = self._read_content(guard, object_relative)
            except ArtifactError:
                raise ArtifactCollisionError("artifact object path is unsafe or corrupt") from exc
            if sha256_bytes(existing_bytes) != digest or existing_bytes != data:
                raise ArtifactCollisionError("content-address collision or store corruption") from exc

        # Never trust caller-supplied size/hash: both are computed from bytes.
        record = ArtifactRecord(
            sha256=digest,
            path=object_relative.as_posix(),
            relative_path=object_relative.as_posix(),
            metadata_path=metadata_relative.as_posix(),
            logical_type=logical_type,
            schema_version=schema_version,
            mime_type=mime_type,
            size=len(data),
            origin=origin,
            creator_role=creator_role,
            creation_command=command,
            parent_artifacts=parents,
            validation_result=validation_result,
            frozen=frozen,
            created_at=created_at or utc_now(),
        )
        try:
            self._publish_immutable(
                guard,
                metadata_relative,
                canonical_json_bytes(record.to_dict()) + b"\n",
            )
        except ArtifactError as exc:
            raise ArtifactCollisionError("artifact metadata publication collided") from exc
        self._verify_graph(guard, (digest,))
        return record

    store = put_bytes
    register_bytes = put_bytes

    def put_json(self, value: Any, **metadata: Any) -> ArtifactRecord:
        return self.put_bytes(canonical_json_bytes(value) + b"\n", **metadata)

    register_json = put_json

    def register_file(
        self,
        source: str | os.PathLike[str],
        *,
        logical_type: str,
        creator_role: Role,
        origin: str | None = None,
        **metadata: Any,
    ) -> ArtifactRecord:
        try:
            content = read_confined_bytes(
                self.policy.root,
                source,
                reject_hardlinks=True,
                max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
            )
            path = self.policy.resolve(
                source,
                must_exist=True,
                expected_kind="file",
                reject_hardlinks=True,
            )
        except PathSecurityError:
            # Preserve the security exception contract so callers can
            # distinguish an unsafe input path from a content-store failure.
            raise
        relative_source = path.relative_to(self.policy.root).as_posix()
        return self.put_bytes(
            content,
            logical_type=logical_type,
            origin=origin or relative_source,
            creator_role=creator_role,
            **metadata,
        )

    register = register_file

    def get_metadata(self, digest: str) -> ArtifactRecord:
        guard = self._open_mutation_lock()
        try:
            return self._get_metadata_locked(guard, digest)
        finally:
            self._unlock_mutation(guard)

    def _get_metadata_locked(
        self, guard: _RegistryMutationLock, digest: str
    ) -> ArtifactRecord:
        relative = self._metadata_relative(digest)
        directory_fd: int | None = None
        try:
            directory_fd, name = self._open_registry_parent(
                guard,
                relative,
                create=False,
            )
            fingerprint = self._stat_regular_at(
                directory_fd,
                name,
                max_bytes=8 * 1024 * 1024,
            )
            cached = self._metadata_verification_cache.get(digest)
            if cached is not None and cached[0] == fingerprint:
                record = cached[1]
            else:
                encoded, read_fingerprint = (
                    self._read_regular_at_with_fingerprint(
                        directory_fd,
                        name,
                        max_bytes=8 * 1024 * 1024,
                    )
                )
                if encoded is None:  # pragma: no cover - bytes requested
                    raise ArtifactCorruptionError(
                        "artifact metadata bytes were not read"
                    )
                value = safe_json_loads(
                    encoded,
                    max_bytes=8 * 1024 * 1024,
                )
                record = ArtifactRecord.from_dict(value)
                self._bounded_cache_store(
                    self._metadata_verification_cache,
                    digest,
                    (read_fingerprint, record),
                )
        except (OSError, ValidationError, ArtifactCorruptionError) as exc:
            raise ArtifactCorruptionError("artifact metadata is absent, unsafe, or corrupt") from exc
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
        if (
            record.size > MAX_ARTIFACT_OBJECT_BYTES
            or len(record.parent_artifacts) > MAX_ARTIFACT_PARENTS
        ):
            raise ArtifactCorruptionError(
                "cached artifact metadata exceeds current safety limits"
            )
        if record.sha256 != digest or record.metadata_path != relative.as_posix():
            raise ArtifactCorruptionError("artifact metadata identity mismatch")
        expected_object = self._object_relative(digest).as_posix()
        if record.path != expected_object:
            raise ArtifactCorruptionError("artifact object path does not match its digest")
        return record

    metadata = get_metadata

    def get_bytes(self, digest: str) -> bytes:
        guard = self._open_mutation_lock()
        try:
            record = self._get_metadata_locked(guard, digest)
            content = self._read_content(guard, self._object_relative(digest))
            if len(content) != record.size or sha256_bytes(content) != digest:
                raise ArtifactCorruptionError("artifact content hash or size mismatch")
            return content
        finally:
            self._unlock_mutation(guard)

    read = get_bytes

    def _verify_content_locked(
        self,
        guard: _RegistryMutationLock,
        record: ArtifactRecord,
    ) -> None:
        relative = self._object_relative(record.sha256)
        directory_fd: int | None = None
        try:
            directory_fd, name = self._open_registry_parent(
                guard,
                relative,
                create=False,
            )
            fingerprint = self._stat_regular_at(
                directory_fd,
                name,
                max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
            )
            if fingerprint[4] != record.size:
                raise ArtifactCorruptionError(
                    "artifact content hash or size mismatch"
                )
            if self._content_verification_cache.get(record.sha256) == fingerprint:
                return
            content, read_fingerprint = self._read_regular_at_with_fingerprint(
                directory_fd,
                name,
                max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
            )
            if (
                content is None
                or len(content) != record.size
                or sha256_bytes(content) != record.sha256
            ):
                raise ArtifactCorruptionError(
                    "artifact content hash or size mismatch"
                )
            self._bounded_cache_store(
                self._content_verification_cache,
                record.sha256,
                read_fingerprint,
            )
        except (OSError, ArtifactError) as exc:
            if isinstance(exc, ArtifactCorruptionError):
                raise
            raise ArtifactCorruptionError(
                "artifact content is absent, unsafe, or corrupt"
            ) from exc
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def verify(self, digest: str, *, raise_on_error: bool = False) -> bool:
        validate_sha256(digest, "artifact SHA-256")
        guard: _RegistryMutationLock | None = None
        verified = True
        try:
            guard = self._open_mutation_lock()
            self._verify_graph(guard, (digest,))
        except (ArtifactError, PathSecurityError, ValidationError) as exc:
            if raise_on_error:
                if isinstance(exc, ArtifactError):
                    raise
                raise ArtifactCorruptionError("artifact verification failed") from exc
            verified = False
        finally:
            if guard is not None:
                try:
                    self._unlock_mutation(guard)
                except ArtifactError:
                    if raise_on_error:
                        raise
                    verified = False
        return verified

    def _verify_graph(
        self, guard: _RegistryMutationLock, roots: Iterable[str]
    ) -> None:
        """Iteratively verify content and provenance with global work bounds."""

        state: dict[str, int] = {}
        edge_count = 0
        for root in roots:
            validate_sha256(root, "artifact SHA-256")
            if state.get(root) == 2:
                continue
            stack: list[tuple[str, bool, int]] = [(root, False, 0)]
            while stack:
                current, expanded, depth = stack.pop()
                current_state = state.get(current, 0)
                if expanded:
                    state[current] = 2
                    continue
                if current_state == 2:
                    continue
                if current_state == 1:
                    raise ArtifactCorruptionError(
                        "artifact provenance cycle detected"
                    )
                if depth > MAX_PROVENANCE_DEPTH:
                    raise ArtifactCorruptionError(
                        "artifact provenance depth exceeds safety limit"
                    )
                record = self._get_metadata_locked(guard, current)
                self._verify_content_locked(guard, record)
                state[current] = 1
                stack.append((current, True, depth))
                for parent in reversed(record.parent_artifacts):
                    edge_count += 1
                    if edge_count > MAX_PROVENANCE_EDGES:
                        raise ArtifactCorruptionError(
                            "artifact provenance work exceeds safety limit"
                        )
                    parent_state = state.get(parent, 0)
                    if parent_state == 1:
                        raise ArtifactCorruptionError(
                            "artifact provenance cycle detected"
                        )
                    if parent_state != 2:
                        stack.append((parent, False, depth + 1))

    @staticmethod
    def _validate_loaded_provenance(
        records: Mapping[str, ArtifactRecord],
    ) -> None:
        state: dict[str, int] = {}
        depth_by_digest: dict[str, int] = {}
        edge_count = 0
        for record in records.values():
            edge_count += len(record.parent_artifacts)
            if edge_count > MAX_PROVENANCE_EDGES:
                raise ArtifactCorruptionError(
                    "artifact provenance work exceeds safety limit"
                )
            if any(parent not in records for parent in record.parent_artifacts):
                raise ArtifactCorruptionError(
                    "artifact provenance parent is absent"
                )
        for root in sorted(records):
            if state.get(root) == 2:
                continue
            stack: list[tuple[str, bool]] = [(root, False)]
            while stack:
                current, expanded = stack.pop()
                current_state = state.get(current, 0)
                if expanded:
                    record = records[current]
                    current_depth = 0
                    if record.parent_artifacts:
                        current_depth = 1 + max(
                            depth_by_digest[parent]
                            for parent in record.parent_artifacts
                        )
                    if current_depth > MAX_PROVENANCE_DEPTH:
                        raise ArtifactCorruptionError(
                            "artifact provenance depth exceeds safety limit"
                        )
                    depth_by_digest[current] = current_depth
                    state[current] = 2
                    continue
                if current_state == 2:
                    continue
                if current_state == 1:
                    raise ArtifactCorruptionError(
                        "artifact provenance cycle detected"
                    )
                record = records.get(current)
                if record is None:
                    raise ArtifactCorruptionError(
                        "artifact provenance parent is absent"
                    )
                state[current] = 1
                stack.append((current, True))
                for parent in reversed(record.parent_artifacts):
                    parent_state = state.get(parent, 0)
                    if parent_state == 1:
                        raise ArtifactCorruptionError(
                            "artifact provenance cycle detected"
                        )
                    if parent_state != 2:
                        stack.append((parent, False))

    def _walk_regular(
        self, guard: _RegistryMutationLock, relative_root: Path
    ) -> tuple[list[Path], list[str]]:
        files: list[Path] = []
        errors: list[str] = []
        root_fd = self._open_registry_directory(
            guard, relative_root, create=False
        )
        stack: list[tuple[int, Path]] = [(root_fd, relative_root)]
        limit_exceeded = False
        scanned_entries = 0
        while stack and not limit_exceeded:
            directory_fd, directory_relative = stack.pop()
            try:
                try:
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            scanned_entries += 1
                            if scanned_entries > MAX_REGISTRY_SCAN_ENTRIES:
                                errors.append("registry entry count exceeds safety limit")
                                limit_exceeded = True
                                break
                            name = entry.name
                            if name in {"", ".", ".."} or "/" in name:
                                errors.append("registry contains an unsafe entry name")
                                continue
                            try:
                                metadata = os.stat(
                                    name,
                                    dir_fd=directory_fd,
                                    follow_symlinks=False,
                                )
                            except OSError:
                                errors.append("unreadable registry entry")
                                continue
                            child_relative = directory_relative / name
                            if stat.S_ISDIR(metadata.st_mode):
                                try:
                                    child_fd = self._open_registry_directory(
                                        guard,
                                        child_relative,
                                        create=False,
                                    )
                                except OSError:
                                    errors.append("registry directory changed or is unsafe")
                                    continue
                                except ArtifactError:
                                    errors.append("registry directory changed or is unsafe")
                                    continue
                                stack.append((child_fd, child_relative))
                            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                                if len(files) >= MAX_REGISTRY_RECORDS:
                                    errors.append("registry entry count exceeds safety limit")
                                    limit_exceeded = True
                                    break
                                files.append(self.policy.root / child_relative)
                            else:
                                errors.append("registry contains a link, special file, or hard link")
                except OSError:
                    errors.append("unreadable registry directory")
                    continue
            finally:
                os.close(directory_fd)
        for descriptor, _ in stack:
            os.close(descriptor)
        if not limit_exceeded:
            files.sort()
        return files, errors

    def _logical_quarantine_sources_locked(
        self, guard: _RegistryMutationLock
    ) -> dict[str, tuple[int, str]]:
        """Return exact source fingerprints covered by immutable tombstones."""

        try:
            files, errors = self._walk_regular(guard, self.quarantine_path)
        except FileNotFoundError:
            return {}
        if errors:
            raise ArtifactCorruptionError(
                "artifact quarantine contains an unsafe entry"
            )
        by_relative = {
            path.relative_to(self.policy.root).as_posix(): path for path in files
        }
        sidecars = {
            relative: path
            for relative, path in by_relative.items()
            if path.name.endswith(LOGICAL_QUARANTINE_METADATA_SUFFIX)
        }
        copies = {
            relative for relative, path in by_relative.items()
            if path.name.endswith(".quarantine")
        }
        covered: dict[str, tuple[int, str]] = {}
        for sidecar_relative, sidecar_path in sidecars.items():
            try:
                raw = self._read_registry_bytes(
                    guard,
                    sidecar_path.relative_to(self.policy.root),
                    max_bytes=1024 * 1024,
                )
                value = safe_json_loads(raw, max_bytes=1024 * 1024)
            except (OSError, ValueError, ArtifactError) as exc:
                raise ArtifactCorruptionError(
                    "artifact quarantine tombstone is malformed"
                ) from exc
            if not isinstance(value, Mapping) or set(value) != {
                "schema_version",
                "original_relative_path",
                "quarantine_relative_path",
                "reason",
                "size_bytes",
                "sha256",
            }:
                raise ArtifactCorruptionError(
                    "artifact quarantine tombstone schema is invalid"
                )
            source_text = value.get("original_relative_path")
            copy_text = value.get("quarantine_relative_path")
            digest = value.get("sha256")
            size = value.get("size_bytes")
            if (
                value.get("schema_version")
                != LOGICAL_QUARANTINE_SCHEMA_VERSION
                or value.get("reason") != "INCOMPLETE_WRITE"
                or not isinstance(source_text, str)
                or not isinstance(copy_text, str)
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= MAX_ARTIFACT_OBJECT_BYTES
            ):
                raise ArtifactCorruptionError(
                    "artifact quarantine tombstone binding is invalid"
                )
            source_relative = Path(source_text)
            copy_relative = Path(copy_text)
            if (
                source_relative.is_absolute()
                or copy_relative.is_absolute()
                or ".." in source_relative.parts
                or ".." in copy_relative.parts
                or not source_relative.name.endswith(
                    (".partial", ".tmp", ".incomplete")
                )
                or (
                    self.objects_path not in source_relative.parents
                    and self.metadata_path not in source_relative.parents
                )
                or copy_relative.parent != self.quarantine_path
                or copy_relative.as_posix() not in copies
                or sidecar_relative
                != copy_relative.with_name(
                    copy_relative.name + LOGICAL_QUARANTINE_METADATA_SUFFIX
                ).as_posix()
            ):
                raise ArtifactCorruptionError(
                    "artifact quarantine tombstone path is invalid"
                )
            source_key = sha256_bytes(source_relative.as_posix().encode("utf-8"))
            expected_name = (
                f"{source_key[:16]}-{digest[:16]}-{source_relative.name}.quarantine"
            )
            if copy_relative.name != expected_name:
                raise ArtifactCorruptionError(
                    "artifact quarantine copy name is not deterministic"
                )
            copy_bytes = self._read_registry_bytes(
                guard, copy_relative, max_bytes=MAX_ARTIFACT_OBJECT_BYTES
            )
            if len(copy_bytes) != size or sha256_bytes(copy_bytes) != digest:
                raise ArtifactCorruptionError(
                    "artifact quarantine copy differs from its tombstone"
                )
            try:
                source_bytes = self._read_registry_bytes(
                    guard,
                    source_relative,
                    max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
                )
            except (FileNotFoundError, ArtifactError):
                continue
            if len(source_bytes) == size and sha256_bytes(source_bytes) == digest:
                covered[source_relative.as_posix()] = (size, digest)
        return covered

    def verify_all(self, *, raise_on_error: bool = False) -> RegistryValidationResult:
        guard = self._open_mutation_lock()
        try:
            return self._verify_all_locked(guard, raise_on_error=raise_on_error)
        finally:
            self._unlock_mutation(guard)

    def _verify_all_locked(
        self,
        guard: _RegistryMutationLock,
        *,
        raise_on_error: bool = False,
    ) -> RegistryValidationResult:
        try:
            logically_quarantined = self._logical_quarantine_sources_locked(
                guard
            )
        except ArtifactError:
            logically_quarantined = {}
            logical_quarantine_valid = False
            errors = ["artifact logical quarantine is invalid"]
        else:
            logical_quarantine_valid = True
            errors = []
        metadata_files, metadata_errors = self._walk_regular(
            guard, self.metadata_path
        )
        errors.extend(metadata_errors)
        metadata_files = [
            path
            for path in metadata_files
            if path.relative_to(self.policy.root).as_posix()
            not in logically_quarantined
        ]
        records: list[ArtifactRecord] = []
        records_by_digest: dict[str, ArtifactRecord] = {}
        known_objects: set[str] = set()
        for path in metadata_files:
            if len(records) >= MAX_REGISTRY_RECORDS:
                errors.append("artifact metadata count exceeds safety limit")
                break
            if not path.name.endswith(".json"):
                errors.append("unexpected file in artifact metadata store")
                continue
            digest = path.stem
            try:
                validate_sha256(digest, "metadata filename digest")
                record = self._get_metadata_locked(guard, digest)
                self._verify_content_locked(guard, record)
            except (ValidationError, ArtifactError, PathSecurityError):
                errors.append(f"artifact verification failed: {digest[:12]}")
                continue
            records.append(record)
            records_by_digest[digest] = record
            known_objects.add(record.path)
        try:
            self._validate_loaded_provenance(records_by_digest)
        except ArtifactError:
            errors.append("artifact provenance graph is invalid or exceeds limits")
        object_files, object_errors = self._walk_regular(
            guard, self.objects_path
        )
        errors.extend(object_errors)
        actual_objects = {
            path.relative_to(self.policy.root).as_posix()
            for path in object_files
            if path.relative_to(self.policy.root).as_posix()
            not in logically_quarantined
        }
        orphan_paths = tuple(sorted(actual_objects - known_objects))
        if orphan_paths:
            errors.append("content objects without metadata were detected")
        if logical_quarantine_valid:
            try:
                stable_quarantine = self._logical_quarantine_sources_locked(guard)
            except ArtifactError:
                errors.append("artifact logical quarantine changed during validation")
            else:
                if stable_quarantine != logically_quarantined:
                    errors.append("artifact logical quarantine changed during validation")
        result = RegistryValidationResult(
            valid=not errors,
            records=tuple(sorted(records, key=lambda item: item.sha256)),
            errors=tuple(errors),
            orphan_paths=orphan_paths,
        )
        if raise_on_error and not result.valid:
            raise ArtifactCorruptionError("artifact registry validation failed")
        return result

    def list_records(self) -> tuple[ArtifactRecord, ...]:
        return self.verify_all(raise_on_error=True).records

    def manifest(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for record in self.list_records():
            if record.logical_type in result:
                raise ArtifactCollisionError(
                    "multiple versions share a logical type; select an exact digest for the manifest"
                )
            result[record.logical_type] = record.to_dict()
        return result

    def incomplete_paths(self) -> tuple[Path, ...]:
        guard = self._open_mutation_lock()
        try:
            return self._incomplete_paths_locked(guard)
        finally:
            self._unlock_mutation(guard)

    def _incomplete_paths_locked(
        self, guard: _RegistryMutationLock
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []
        logically_quarantined = self._logical_quarantine_sources_locked(guard)
        for relative in (self.objects_path, self.metadata_path):
            files, errors = self._walk_regular(guard, relative)
            if errors:
                raise ArtifactCorruptionError("unsafe registry entry blocks partial recovery")
            candidates.extend(
                path
                for path in files
                if path.name.endswith((".partial", ".tmp", ".incomplete"))
                and path.relative_to(self.policy.root).as_posix()
                not in logically_quarantined
            )
        if self._logical_quarantine_sources_locked(guard) != logically_quarantined:
            raise ArtifactCorruptionError(
                "artifact logical quarantine changed during partial scan"
            )
        return tuple(sorted(candidates))

    def quarantine_incomplete(self) -> tuple[str, ...]:
        """Copy partial files and logically quarantine their exact contents."""

        lock = self._open_mutation_lock()
        try:
            return self._quarantine_incomplete_locked(lock)
        finally:
            self._unlock_mutation(lock)

    def _quarantine_incomplete_locked(
        self, guard: _RegistryMutationLock
    ) -> tuple[str, ...]:
        paths = self._incomplete_paths_locked(guard)
        if not paths:
            return ()
        directory_fd = self._open_registry_directory(
            guard, self.quarantine_path, create=True
        )
        os.close(directory_fd)
        quarantined: list[str] = []
        for path in paths:
            relative = path.relative_to(self.policy.root)
            content = self._read_registry_bytes(guard, relative)
            digest = sha256_bytes(content)
            source_key = sha256_bytes(relative.as_posix().encode("utf-8"))
            destination_name = (
                f"{source_key[:16]}-{digest[:16]}-{path.name}.quarantine"
            )
            destination_relative = self.quarantine_path / destination_name
            sidecar_relative = destination_relative.with_name(
                destination_name + LOGICAL_QUARANTINE_METADATA_SUFFIX
            )
            try:
                self._publish_immutable(guard, destination_relative, content)
                tombstone = canonical_json_bytes(
                    {
                        "schema_version": LOGICAL_QUARANTINE_SCHEMA_VERSION,
                        "original_relative_path": relative.as_posix(),
                        "quarantine_relative_path": destination_relative.as_posix(),
                        "reason": "INCOMPLETE_WRITE",
                        "size_bytes": len(content),
                        "sha256": digest,
                    }
                )
                self._publish_immutable(guard, sidecar_relative, tombstone)
                current = self._read_registry_bytes(guard, relative)
                if current != content:
                    raise ArtifactError(
                        "incomplete artifact changed during logical quarantine"
                    )
                if relative.as_posix() not in self._logical_quarantine_sources_locked(
                    guard
                ):
                    raise ArtifactError(
                        "logical artifact quarantine did not bind its source"
                    )
                quarantine_fd = self._open_registry_directory(
                    guard, self.quarantine_path, create=False
                )
                try:
                    os.fsync(quarantine_fd)
                finally:
                    os.close(quarantine_fd)
            except (OSError, ArtifactError) as exc:
                if isinstance(exc, ArtifactError):
                    raise
                raise ArtifactError("incomplete artifact quarantine failed") from exc
            quarantined.append(destination_relative.as_posix())
        return tuple(quarantined)


ContentAddressedArtifactRegistry = ArtifactRegistry
