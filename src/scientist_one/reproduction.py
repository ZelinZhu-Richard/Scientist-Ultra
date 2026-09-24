"""Deterministic, offline reproduction of frozen Scientist-One results.

The reproduction engine deliberately understands only the local synthetic
fixture format used by the built-in demonstration.  A real experiment runner
is an external provider behind an interface; this module never invokes one or
uses the network.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
from typing import Any, Mapping, Protocol, Sequence

from .artifacts import ArtifactRegistry
from .errors import ArtifactError, PathSecurityError, UnsafeSerializationError
from .ledger import EventLedger
from .security import (
    DEFAULT_MAX_JSON_BYTES,
    canonical_json_bytes,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
    open_confined_directory_fd,
)


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_INVENTORY_ENTRIES = 2_048
MAX_INVENTORY_TOTAL_BYTES = 64 * 1024 * 1024
FROZEN_RECORD_KEYS = {
    "run_id", "status", "reproduction_id", "expected", "observed",
    "absolute_difference", "tolerance", "manifest_path", "result_path",
    "source_result_sha256", "manifest_sha256", "manifest_record_hash",
    "result_sha256", "result_record_hash",
}
FROZEN_MANIFEST_KEYS = {
    "schema_version", "kind", "run_id", "reproduction_id", "created_at",
    "offline", "command", "algorithm", "source_artifacts", "source_ledger",
    "environment", "device_execution", "code_fingerprint",
    "configuration_sha256", "dataset_fixture_ids", "random_seeds",
    "input_hashes", "expected_source_output_hashes", "accepted_tolerance",
    "expected_primary_estimate", "provider", "external_integrations_used",
}
REPRODUCTION_RESULT_KEYS = {
    "schema_version", "kind", "run_id", "reproduction_id", "status",
    "expected_primary_estimate", "observed_primary_estimate",
    "absolute_difference", "accepted_tolerance", "numeric_comparison_passed",
    "reproduced_output_hashes", "expected_source_output_hashes", "input_hashes",
    "code_fingerprint", "configuration_sha256", "dataset_fixture_ids",
    "random_seeds", "source_result_sha256", "frozen_manifest_sha256",
    "discrepancies",
}


class ReproductionError(RuntimeError):
    """Raised when a frozen result cannot be safely reproduced."""


class ExperimentReplayProvider(Protocol):
    """Narrow interface for a future, separately authorized real runner."""

    def replay(self, frozen_manifest: Mapping[str, Any]) -> Mapping[str, Any]:
        """Replay a frozen manifest without changing its source evidence."""


@dataclass(frozen=True)
class ReproductionResult:
    run_id: str
    status: str
    reproduction_id: str
    expected: float
    observed: float
    absolute_difference: float
    tolerance: float
    manifest_path: str
    result_path: str
    source_result_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value) + b"\n"
    except UnsafeSerializationError as exc:
        raise ReproductionError("reproduction value is not safe canonical JSON") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path, root: Path | None = None) -> dict[str, Any]:
    trust_root = root or path.parent
    try:
        canonical_root = trust_root.resolve(strict=True)
        candidate = path if path.is_absolute() else canonical_root / path
        relative = candidate.relative_to(canonical_root)
        payload = read_confined_bytes(
            canonical_root,
            relative,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        if payload is None:
            raise ReproductionError("JSON evidence disappeared")
        value = safe_json_loads(payload)
    except (OSError, ValueError, PathSecurityError, UnsafeSerializationError) as exc:
        raise ReproductionError(f"cannot read JSON evidence {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"expected a JSON object in {path.name}")
    return value


def _secure_directory(root: Path, path: Path, *, create: bool) -> Path:
    """Resolve a directory beneath *root* without following directory links."""

    root = root.resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ReproductionError("output directory escapes project root") from exc
    current = root
    for component in relative.parts:
        if component in {"", ".", ".."}:
            raise ReproductionError("unsafe output directory component")
        candidate = current / component
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            if not create:
                raise ReproductionError("required output directory is absent")
            candidate.mkdir()
            metadata = candidate.lstat()
        if candidate.is_symlink() or not candidate.is_dir():
            raise ReproductionError("output directory contains a link or non-directory")
        current = candidate
    resolved = current.resolve(strict=True)
    if root not in resolved.parents and resolved != root:
        raise ReproductionError("output directory resolves outside project root")
    return resolved


def _read_regular_at(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ReproductionError("reproduction output is not an unlinked regular file")
        if metadata.st_size > max_bytes:
            raise ReproductionError("reproduction output exceeds its deterministic bound")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ReproductionError("reproduction output exceeds its deterministic bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _atomic_write(root: Path, path: Path, data: bytes) -> None:
    """Create a deterministic file, accepting an identical prior result."""

    root = root.resolve(strict=True)
    try:
        parent_relative = path.parent.relative_to(root)
        directory_fd = open_confined_directory_fd(
            root, parent_relative, create=True
        )
    except (ValueError, PathSecurityError) as exc:
        raise ReproductionError("reproduction output directory is unsafe") from exc
    partial_name = (
        f".{path.name}.{_sha256(data)[:16]}.{os.urandom(8).hex()}.partial"
    )
    descriptor: int | None = None
    try:
        try:
            existing = _read_regular_at(directory_fd, path.name, max_bytes=len(data))
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ReproductionError("unsafe existing reproduction artifact") from exc
        if existing is not None:
            if existing != data:
                raise ReproductionError(f"immutable reproduction collision: {path.name}")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(partial_name, flags, 0o600, dir_fd=directory_fd)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ReproductionError("short reproduction write")
            offset += written
        os.fsync(descriptor)
        held = os.fstat(descriptor)
        named = os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or (held.st_dev, held.st_ino, held.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
        ):
            raise ReproductionError(
                "reproduction partial identity changed before publication"
            )
        try:
            os.link(
                partial_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _read_regular_at(directory_fd, path.name, max_bytes=len(data)) != data:
                raise ReproductionError(f"immutable reproduction collision: {path.name}")
        published_fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            published = os.fstat(published_fd)
            if (
                (published.st_dev, published.st_ino, published.st_size)
                != (held.st_dev, held.st_ino, len(data))
            ):
                raise ReproductionError(
                    "published reproduction identity differs from held bytes"
                )
        finally:
            os.close(published_fd)
        os.unlink(partial_name, dir_fd=directory_fd)
        os.close(descriptor)
        descriptor = None
        if _read_regular_at(directory_fd, path.name, max_bytes=len(data)) != data:
            raise ReproductionError(
                "published reproduction failed final byte verification"
            )
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(partial_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _safe_run_dir(root: Path, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ReproductionError("invalid run ID")
    try:
        return secure_directory(root, Path("runs") / run_id, create=False)
    except PathSecurityError as exc:
        raise ReproductionError("unsafe run directory") from exc


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = safe_json_loads(payload)
    except (UnsafeSerializationError, UnicodeDecodeError, ValueError) as exc:
        raise ReproductionError(f"malformed frozen {label}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"frozen {label} must be a JSON object")
    return value


def _registry_artifact(
    project_root: Path,
    registry: ArtifactRegistry,
    record: Mapping[str, Any],
    logical_type: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    """Resolve one manifest record to a bounded immutable registry snapshot."""

    digest = record.get("sha256")
    if not isinstance(digest, str):
        raise ReproductionError(f"{logical_type} has no content digest")
    try:
        metadata = registry.get_metadata(digest)
        if metadata.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError(f"{logical_type} exceeds the replay size bound")
        payload = read_confined_bytes(
            project_root,
            metadata.path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except (ArtifactError, PathSecurityError) as exc:
        raise ReproductionError(f"{logical_type} registry evidence is absent or unsafe") from exc
    if payload is None:
        raise ReproductionError(f"{logical_type} registry evidence disappeared")
    if (
        metadata.logical_type != logical_type
        or metadata.path != record.get("registry_path")
        or metadata.metadata_path != record.get("registry_metadata_path")
        or metadata.record_hash != record.get("registry_record_hash")
        or metadata.size != len(payload)
        or metadata.sha256 != _sha256(payload)
        or metadata.frozen is not True
        or metadata.validation_result != "PASS"
    ):
        raise ReproductionError(f"{logical_type} registry binding is invalid")
    descriptor = {
        "sha256": metadata.sha256,
        "logical_type": metadata.logical_type,
        "size": metadata.size,
        "registry_path": metadata.path,
        "registry_metadata_path": metadata.metadata_path,
        "registry_record_hash": metadata.record_hash,
    }
    return descriptor, payload, _json_object(payload, logical_type)


def _descriptor_artifact(
    project_root: Path,
    registry: ArtifactRegistry,
    descriptor: Mapping[str, Any],
    logical_type: str,
) -> tuple[bytes, dict[str, Any]]:
    """Reopen frozen bytes solely through a published source descriptor."""

    digest = descriptor.get("sha256")
    if not isinstance(digest, str):
        raise ReproductionError(f"published {logical_type} descriptor is incomplete")
    try:
        metadata = registry.get_metadata(digest)
        if metadata.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError(f"published {logical_type} exceeds its bound")
        payload = read_confined_bytes(
            project_root,
            metadata.path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except (ArtifactError, PathSecurityError) as exc:
        raise ReproductionError(f"published {logical_type} evidence is unavailable") from exc
    expected = {
        "sha256": metadata.sha256,
        "logical_type": metadata.logical_type,
        "size": metadata.size,
        "registry_path": metadata.path,
        "registry_metadata_path": metadata.metadata_path,
        "registry_record_hash": metadata.record_hash,
    }
    if payload is None or dict(descriptor) != expected or _sha256(payload) != digest:
        raise ReproductionError(f"published {logical_type} descriptor no longer resolves")
    return payload, _json_object(payload, logical_type)


def _inventory_matches_live(project_root: Path, payload: Mapping[str, Any]) -> bool:
    """Compare a frozen source/config inventory to one fd-pinned live snapshot."""

    kind = payload.get("kind")
    if kind == "FROZEN_SOURCE_INVENTORY":
        directory, suffix = Path("src/scientist_one"), ".py"
        expected_launcher = next(
            (
                item
                for item in payload.get("entries", ())
                if isinstance(item, Mapping)
                and item.get("path") == "scripts/scientist_one_cli.py"
            ),
            None,
        )
        if not isinstance(expected_launcher, Mapping):
            return False
    elif kind == "FROZEN_CONFIGURATION_INVENTORY":
        directory, suffix = Path("configs"), ".json"
    else:
        return False
    entries = payload.get("entries")
    if (
        payload.get("schema_version") != "1.0"
        or not isinstance(entries, list)
        or not entries
        or payload.get("aggregate_sha256")
        != _sha256(canonical_json_bytes(entries) + b"\n")
    ):
        return False
    try:
        directory_fd = open_confined_directory_fd(
            project_root, directory, create=False
        )
        try:
            collected: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if entry.name.endswith(suffix):
                        if len(collected) >= MAX_INVENTORY_ENTRIES:
                            return False
                        collected.append(entry.name)
            names = tuple(sorted(collected))
            directory_entries = [
                item
                for item in entries
                if isinstance(item, Mapping)
                and Path(str(item.get("path", ""))).parent == directory
            ]
            if names != tuple(Path(str(item.get("path", ""))).name for item in directory_entries):
                return False
            observed: list[dict[str, Any]] = []
            aggregate_bytes = 0
            for name in names:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_size > 4 * 1024 * 1024
                    ):
                        return False
                    chunks: list[bytes] = []
                    total = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        total += len(chunk)
                        if total > 4 * 1024 * 1024:
                            return False
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    aggregate_bytes += len(data)
                    if aggregate_bytes > MAX_INVENTORY_TOTAL_BYTES:
                        return False
                finally:
                    os.close(descriptor)
                observed.append(
                    {
                        "path": (directory / name).as_posix(),
                        "sha256": _sha256(data),
                        "size": len(data),
                    }
                )
        finally:
            os.close(directory_fd)
    except (OSError, PathSecurityError, TypeError, ValueError):
        return False
    if kind == "FROZEN_SOURCE_INVENTORY":
        try:
            launcher = read_confined_bytes(
                project_root,
                "scripts/scientist_one_cli.py",
                reject_hardlinks=True,
                max_bytes=4 * 1024 * 1024,
            )
        except PathSecurityError:
            return False
        if launcher is None:
            return False
        observed.append(
            {
                "path": "scripts/scientist_one_cli.py",
                "sha256": _sha256(launcher),
                "size": len(launcher),
            }
        )
        observed.sort(key=lambda item: item["path"])
    return observed == entries


def _mean(values: Sequence[Any], label: str) -> float:
    if not values:
        raise ReproductionError(f"{label} values are empty")
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in values):
        raise ReproductionError(f"{label} contains a non-numeric value")
    converted: list[float] = []
    try:
        for item in values:
            numeric = float(item)
            if not math.isfinite(numeric):
                raise ReproductionError(f"{label} contains a non-finite value")
            converted.append(numeric)
        result = math.fsum(converted) / len(converted)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError(f"{label} cannot be represented finitely") from exc
    if not math.isfinite(result):
        raise ReproductionError(f"{label} mean is non-finite")
    return result


def reproduce_run(
    root: str | Path,
    run_id: str,
    *,
    timestamp: str | None = None,
) -> ReproductionResult:
    """Replay the frozen primary synthetic result in a clean local directory.

    The reproduction identifier is derived from source evidence, so repeated
    calls are idempotent.  The original run artifacts are only read.
    """

    project_root = Path(root).resolve(strict=True)
    run_dir = _safe_run_dir(project_root, run_id)
    manifest = _read_json(run_dir / "manifest.json", project_root)
    if manifest.get("run_id") != run_id:
        raise ReproductionError("run manifest identity mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReproductionError("run manifest has no artifact registry")
    ledger = EventLedger(project_root, Path("runs") / run_id / "events.jsonl").validate()
    if not ledger.valid or not ledger.events:
        raise ReproductionError("authoritative event ledger is invalid or empty")
    if (
        manifest.get("ledger_head_hash") != ledger.head_hash
        or manifest.get("event_count") != len(ledger.events)
    ):
        raise ReproductionError("run manifest is not anchored to the authoritative ledger")
    ledger_artifacts: dict[str, str] = {}
    ledger_record_hashes: dict[str, str] = {}
    for event in ledger.events:
        artifact_types = event.metadata.get("artifact_types", [])
        record_hashes = event.metadata.get("artifact_record_hashes", [])
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            artifact_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", record_hash)
            ):
                raise ReproductionError("ledger artifact type is malformed")
            prior = ledger_artifacts.get(logical_type)
            prior_record = ledger_record_hashes.get(logical_type)
            if (
                (prior is not None and prior != digest)
                or (prior_record is not None and prior_record != record_hash)
            ):
                raise ReproductionError("ledger contains conflicting logical artifact identities")
            ledger_artifacts[logical_type] = digest
            ledger_record_hashes[logical_type] = record_hash

    required_sources = (
        "machine_results",
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    )
    source_records: dict[str, Mapping[str, Any]] = {}
    for logical_type in required_sources:
        record = artifacts.get(logical_type)
        if (
            not isinstance(record, dict)
            or record.get("sha256") != ledger_artifacts.get(logical_type)
            or record.get("registry_record_hash")
            != ledger_record_hashes.get(logical_type)
        ):
            raise ReproductionError(
                f"mutable manifest projection disagrees with ledger: {logical_type}"
            )
        source_records[logical_type] = record
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    frozen_descriptors: dict[str, dict[str, Any]] = {}
    frozen_payloads: dict[str, dict[str, Any]] = {}
    for logical_type in required_sources:
        descriptor, _, parsed = _registry_artifact(
            project_root, registry, source_records[logical_type], logical_type
        )
        frozen_descriptors[logical_type] = descriptor
        frozen_payloads[logical_type] = parsed
    source_record = source_records["machine_results"]
    protocol_record = source_records["frozen_protocol"]
    source = frozen_payloads["machine_results"]
    protocol = frozen_payloads["frozen_protocol"]
    if not _inventory_matches_live(
        project_root, frozen_payloads["frozen_source_inventory"]
    ) or not _inventory_matches_live(
        project_root, frozen_payloads["frozen_configuration_inventory"]
    ):
        raise ReproductionError("live code or configuration differs from the frozen replay inputs")

    if source.get("evidence_class") != "SYNTHETIC_CONFIRMATORY_FIXTURE":
        raise ReproductionError("no local replay adapter for this evidence class")
    code_fingerprint = source.get("code_fingerprint")
    configuration_hash = source.get("configuration_sha256")
    if code_fingerprint != manifest.get("code_fingerprint"):
        raise ReproductionError("source result code fingerprint does not match run manifest")
    if configuration_hash != manifest.get("configuration_sha256"):
        raise ReproductionError("source result configuration hash does not match run manifest")
    for label, value in (("code fingerprint", code_fingerprint), ("configuration hash", configuration_hash)):
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ReproductionError(f"invalid {label}")
    if (
        frozen_payloads["frozen_source_inventory"].get("aggregate_sha256")
        != code_fingerprint
        or frozen_payloads["frozen_configuration_inventory"].get(
            "aggregate_sha256"
        )
        != configuration_hash
    ):
        raise ReproductionError(
            "frozen inventory aggregates do not bind the recorded code/configuration"
        )
    input_hashes = source.get("input_hashes")
    expected_input_types = {
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    if (
        not isinstance(input_hashes, dict)
        or set(input_hashes) != expected_input_types
        or input_hashes.get("frozen_protocol") != protocol_record["sha256"]
    ):
        raise ReproductionError("source result is not bound to the frozen protocol")
    for logical_type, digest in input_hashes.items():
        if not isinstance(logical_type, str) or not isinstance(digest, str):
            raise ReproductionError("malformed source input hashes")
        corresponding = {
            "frozen_protocol": "frozen_protocol",
            "blind_interpretation": "blind_interpretation",
            "custody_record": "custody_record",
            "frozen_source_inventory": "frozen_source_inventory",
            "frozen_configuration_inventory": "frozen_configuration_inventory",
        }.get(logical_type)
        if corresponding is None:
            raise ReproductionError(f"unsupported frozen input: {logical_type}")
        record = source_records.get(corresponding)
        if not isinstance(record, Mapping) or record.get("sha256") != digest:
            raise ReproductionError(f"frozen input binding mismatch: {logical_type}")
    fixture_ids = source.get("dataset_fixture_ids")
    seeds = source.get("random_seeds")
    if not isinstance(fixture_ids, list) or not fixture_ids or not all(isinstance(item, str) and item for item in fixture_ids):
        raise ReproductionError("dataset or fixture identifiers are required")
    if not isinstance(seeds, list) or not seeds or any(isinstance(item, bool) or not isinstance(item, int) for item in seeds):
        raise ReproductionError("frozen random seeds are required")
    fixture = source.get("frozen_fixture")
    if not isinstance(fixture, dict):
        raise ReproductionError("machine results omit the frozen fixture")
    control = fixture.get("control")
    treatment = fixture.get("treatment")
    if not isinstance(control, list) or not isinstance(treatment, list):
        raise ReproductionError("frozen fixture groups must be arrays")
    expected_raw = source.get("primary_estimate")
    if isinstance(expected_raw, bool) or not isinstance(expected_raw, (int, float)):
        raise ReproductionError("primary estimate is not numeric")
    try:
        expected = float(expected_raw)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("primary estimate cannot be represented finitely") from exc
    if not math.isfinite(expected):
        raise ReproductionError("primary estimate must be finite")
    tolerance_raw = protocol.get("reproduction_tolerance", 1e-12)
    if isinstance(tolerance_raw, bool) or not isinstance(tolerance_raw, (int, float)):
        raise ReproductionError("reproduction tolerance is not numeric")
    try:
        tolerance = float(tolerance_raw)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("reproduction tolerance cannot be represented finitely") from exc
    if not math.isfinite(tolerance) or tolerance < 0:
        raise ReproductionError("reproduction tolerance cannot be negative")
    source_output_hashes = source.get("output_hashes")
    if not isinstance(source_output_hashes, dict) or not isinstance(
        source_output_hashes.get("result_core"), str
    ):
        raise ReproductionError("frozen source output hash is missing")

    identity_payload = {
        "run_id": run_id,
        "source_result_sha256": source_record["sha256"],
        "protocol_sha256": protocol_record["sha256"],
        "code_fingerprint": code_fingerprint,
        "configuration_hash": configuration_hash,
        "input_hashes": input_hashes,
        "dataset_fixture_ids": fixture_ids,
        "random_seeds": seeds,
        "source_output_hashes": source_output_hashes,
        "algorithm": "difference_of_arithmetic_means_v1",
        "tolerance": tolerance,
    }
    reproduction_id = _sha256(_canonical_json(identity_payload))[:20]
    reproduction_dir = run_dir / "reproductions" / reproduction_id
    created_at = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    frozen_manifest = {
        "schema_version": "1.0",
        "kind": "FROZEN_REPRODUCTION_MANIFEST",
        "run_id": run_id,
        "reproduction_id": reproduction_id,
        "created_at": created_at,
        "offline": True,
        "command": [
            "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
            "reproduce", run_id
        ],
        "algorithm": "difference_of_arithmetic_means_v1",
        "source_artifacts": {
            key: frozen_descriptors[key] for key in sorted(frozen_descriptors)
        },
        "source_ledger": {
            "head_hash": ledger.head_hash,
            "event_count": len(ledger.events),
        },
        "environment": {
            "python_version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "architecture": platform.machine(),
            "platform": sys.platform,
            "python_executable_name": Path(sys.executable).name,
        },
        "device_execution": {
            "selected_device": "cpu",
            "dtype": "float32",
            "operation": "difference_of_arithmetic_means_v1",
            "mps_used": False,
            "parity_required": False,
            "parity_evidence": "CPU deterministic standard-library replay; no accelerator invoked",
        },
        "code_fingerprint": code_fingerprint,
        "configuration_sha256": configuration_hash,
        "dataset_fixture_ids": list(fixture_ids),
        "random_seeds": list(seeds),
        "input_hashes": dict(sorted(input_hashes.items())),
        "expected_source_output_hashes": dict(sorted(source_output_hashes.items())),
        "accepted_tolerance": tolerance,
        "expected_primary_estimate": expected,
        "provider": "BUILTIN_LOCAL_SYNTHETIC_FIXTURE",
        "external_integrations_used": [],
    }
    manifest_name = f"manifest-{_sha256(_canonical_json(frozen_manifest))[:16]}.json"
    _atomic_write(project_root, reproduction_dir / manifest_name, _canonical_json(frozen_manifest))

    # Replay strictly from the just-published immutable manifest and re-opened
    # content-addressed inputs, never from mutable in-memory run metadata.
    replay_manifest = _read_json(reproduction_dir / manifest_name, project_root)
    if replay_manifest != frozen_manifest:
        raise ReproductionError("frozen reproduction manifest changed after publication")
    replay_run_id = replay_manifest.get("run_id")
    replay_sources = replay_manifest.get("source_artifacts")
    replay_ledger_anchor = replay_manifest.get("source_ledger")
    if (
        replay_run_id != run_id
        or not isinstance(replay_sources, dict)
        or not isinstance(replay_ledger_anchor, dict)
    ):
        raise ReproductionError("published reproduction identity is malformed")
    replay_ledger = EventLedger(
        project_root, Path("runs") / replay_run_id / "events.jsonl"
    ).validate()
    if (
        not replay_ledger.valid
        or replay_ledger.head_hash != replay_ledger_anchor.get("head_hash")
        or len(replay_ledger.events) != replay_ledger_anchor.get("event_count")
    ):
        raise ReproductionError("published reproduction ledger anchor no longer verifies")
    replay_ledger_artifacts: dict[str, str] = {}
    replay_ledger_record_hashes: dict[str, str] = {}
    for event in replay_ledger.events:
        artifact_types = event.metadata.get("artifact_types", [])
        record_hashes = event.metadata.get("artifact_record_hashes", [])
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("published ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            artifact_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", record_hash)
            ):
                raise ReproductionError("published ledger artifact record hash is malformed")
            prior = replay_ledger_artifacts.get(logical_type)
            prior_record = replay_ledger_record_hashes.get(logical_type)
            if (
                (prior is not None and prior != digest)
                or (prior_record is not None and prior_record != record_hash)
            ):
                raise ReproductionError("published ledger contains conflicting artifact bindings")
            replay_ledger_artifacts[logical_type] = digest
            replay_ledger_record_hashes[logical_type] = record_hash
    replay_registry = ArtifactRegistry(
        project_root, Path("runs") / replay_run_id / "registry"
    )
    replay_payloads: dict[str, dict[str, Any]] = {}
    for logical_type in required_sources:
        descriptor = replay_sources.get(logical_type)
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("sha256") != replay_ledger_artifacts.get(logical_type)
            or descriptor.get("registry_record_hash")
            != replay_ledger_record_hashes.get(logical_type)
        ):
            raise ReproductionError(
                f"published {logical_type} is not anchored in the ledger"
            )
        _, parsed = _descriptor_artifact(
            project_root, replay_registry, descriptor, logical_type
        )
        replay_payloads[logical_type] = parsed
    replay_source = replay_payloads["machine_results"]
    if not _inventory_matches_live(
        project_root, replay_payloads["frozen_source_inventory"]
    ) or not _inventory_matches_live(
        project_root, replay_payloads["frozen_configuration_inventory"]
    ):
        raise ReproductionError("published replay inventories no longer match the workspace")
    replay_code = replay_manifest.get("code_fingerprint")
    replay_configuration = replay_manifest.get("configuration_sha256")
    if (
        replay_source.get("code_fingerprint") != replay_code
        or replay_source.get("configuration_sha256") != replay_configuration
        or replay_payloads["frozen_source_inventory"].get("aggregate_sha256")
        != replay_code
        or replay_payloads["frozen_configuration_inventory"].get(
            "aggregate_sha256"
        )
        != replay_configuration
    ):
        raise ReproductionError(
            "published replay inventories do not bind the code/configuration identity"
        )
    replay_fixture = replay_source.get("frozen_fixture")
    if not isinstance(replay_fixture, dict):
        raise ReproductionError("frozen replay fixture is missing")
    replay_control = replay_fixture.get("control")
    replay_treatment = replay_fixture.get("treatment")
    if not isinstance(replay_control, list) or not isinstance(replay_treatment, list):
        raise ReproductionError("frozen replay fixture groups are invalid")
    replay_expected = replay_manifest.get("expected_primary_estimate")
    replay_tolerance = replay_manifest.get("accepted_tolerance")
    if (
        isinstance(replay_expected, bool)
        or not isinstance(replay_expected, (int, float))
        or isinstance(replay_tolerance, bool)
        or not isinstance(replay_tolerance, (int, float))
        or replay_tolerance < 0
    ):
        raise ReproductionError("published numeric replay contract is malformed")
    try:
        replay_expected = float(replay_expected)
        replay_tolerance = float(replay_tolerance)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("published numeric replay contract is not finite") from exc
    if not math.isfinite(replay_expected) or not math.isfinite(replay_tolerance):
        raise ReproductionError("published numeric replay contract is not finite")
    observed = _mean(replay_treatment, "treatment") - _mean(replay_control, "control")
    difference = abs(observed - replay_expected)
    if not math.isfinite(observed) or not math.isfinite(difference):
        raise ReproductionError("replayed numeric result is non-finite")
    passed = difference <= replay_tolerance
    reproduced_core = {
        "primary_estimate": observed,
        "control_mean": _mean(replay_control, "control"),
        "treatment_mean": _mean(replay_treatment, "treatment"),
        "n_control": len(replay_control),
        "n_treatment": len(replay_treatment),
    }
    reproduced_core_hash = _sha256(_canonical_json(reproduced_core))
    replay_output_hashes = replay_manifest.get("expected_source_output_hashes")
    replay_input_hashes = replay_manifest.get("input_hashes")
    replay_fixture_ids = replay_manifest.get("dataset_fixture_ids")
    replay_seeds = replay_manifest.get("random_seeds")
    if not isinstance(replay_output_hashes, dict) or replay_output_hashes.get("result_core") != reproduced_core_hash:
        raise ReproductionError("replayed output hash differs from the frozen source output")
    if (
        not isinstance(replay_input_hashes, dict)
        or set(replay_input_hashes) != expected_input_types
        or replay_source.get("input_hashes") != replay_input_hashes
        or any(
            replay_sources[name].get("sha256") != replay_input_hashes[name]
            for name in expected_input_types
        )
        or not isinstance(replay_fixture_ids, list)
        or not isinstance(replay_seeds, list)
    ):
        raise ReproductionError("published replay provenance is malformed")
    replay_source_sha = replay_sources["machine_results"]["sha256"]
    result_payload = {
        "schema_version": "1.0",
        "kind": "REPRODUCTION_RESULT",
        "run_id": run_id,
        "reproduction_id": reproduction_id,
        "status": "PASS" if passed else "FAIL",
        "expected_primary_estimate": replay_expected,
        "observed_primary_estimate": observed,
        "absolute_difference": difference,
        "accepted_tolerance": replay_tolerance,
        "numeric_comparison_passed": passed,
        "reproduced_output_hashes": {"result_core": reproduced_core_hash},
        "expected_source_output_hashes": dict(sorted(replay_output_hashes.items())),
        "input_hashes": dict(sorted(replay_input_hashes.items())),
        "code_fingerprint": replay_manifest.get("code_fingerprint"),
        "configuration_sha256": replay_manifest.get("configuration_sha256"),
        "dataset_fixture_ids": list(replay_fixture_ids),
        "random_seeds": list(replay_seeds),
        "source_result_sha256": replay_source_sha,
        "frozen_manifest_sha256": _sha256(_canonical_json(replay_manifest)),
        "discrepancies": [] if passed else ["primary estimate differs beyond tolerance"],
    }
    result_name = f"result-{_sha256(_canonical_json(result_payload))[:16]}.json"
    _atomic_write(project_root, reproduction_dir / result_name, _canonical_json(result_payload))
    if not passed:
        raise ReproductionError("primary-result reproduction failed")

    return ReproductionResult(
        run_id=run_id,
        status="PASS",
        reproduction_id=reproduction_id,
        expected=replay_expected,
        observed=observed,
        absolute_difference=difference,
        tolerance=replay_tolerance,
        manifest_path=(reproduction_dir / manifest_name).relative_to(project_root).as_posix(),
        result_path=(reproduction_dir / result_name).relative_to(project_root).as_posix(),
        source_result_sha256=replay_source_sha,
    )


def verify_frozen_reproduction(
    root: str | Path,
    run_id: str,
    frozen_record: Mapping[str, Any],
) -> ReproductionResult:
    """Recompute and verify an already-published reproduction packet.

    The replay consumes only the immutable manifest, its run-scoped registry
    descriptors, and the ledger prefix named by that manifest.  It never
    creates a new manifest from the later mutable run projection.
    """

    project_root = Path(root).resolve(strict=True)
    _safe_run_dir(project_root, run_id)
    if set(frozen_record) != FROZEN_RECORD_KEYS:
        raise ReproductionError("frozen reproduction summary schema is malformed")
    manifest_path = frozen_record.get("manifest_path")
    result_path = frozen_record.get("result_path")
    if (
        not isinstance(manifest_path, str)
        or not isinstance(result_path, str)
        or Path(manifest_path).is_absolute()
        or Path(result_path).is_absolute()
    ):
        raise ReproductionError("frozen reproduction paths are malformed")
    try:
        manifest_bytes = read_confined_bytes(
            project_root,
            manifest_path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        result_bytes = read_confined_bytes(
            project_root,
            result_path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except PathSecurityError as exc:
        raise ReproductionError("frozen reproduction packet is unsafe") from exc
    if manifest_bytes is None or result_bytes is None:
        raise ReproductionError("frozen reproduction packet is absent")
    if (
        _sha256(manifest_bytes) != frozen_record.get("manifest_sha256")
        or _sha256(result_bytes) != frozen_record.get("result_sha256")
    ):
        raise ReproductionError("frozen reproduction packet digest mismatch")
    replay_manifest = _json_object(manifest_bytes, "reproduction manifest")
    replay_result = _json_object(result_bytes, "reproduction result")
    reproduction_id = replay_manifest.get("reproduction_id")
    if (
        set(replay_manifest) != FROZEN_MANIFEST_KEYS
        or set(replay_result) != REPRODUCTION_RESULT_KEYS
        or replay_manifest.get("schema_version") != "1.0"
        or replay_result.get("schema_version") != "1.0"
        or replay_manifest.get("kind") != "FROZEN_REPRODUCTION_MANIFEST"
        or replay_result.get("kind") != "REPRODUCTION_RESULT"
        or replay_manifest.get("run_id") != run_id
        or replay_result.get("run_id") != run_id
        or replay_result.get("reproduction_id") != reproduction_id
        or frozen_record.get("reproduction_id") != reproduction_id
        or replay_result.get("frozen_manifest_sha256") != _sha256(manifest_bytes)
    ):
        raise ReproductionError("frozen reproduction identity is malformed")

    anchor = replay_manifest.get("source_ledger")
    if not isinstance(anchor, Mapping) or set(anchor) != {"head_hash", "event_count"}:
        raise ReproductionError("frozen reproduction ledger anchor is absent")
    ledger = EventLedger(
        project_root, Path("runs") / run_id / "events.jsonl"
    ).validate()
    anchor_count = anchor.get("event_count")
    if (
        not ledger.valid
        or isinstance(anchor_count, bool)
        or not isinstance(anchor_count, int)
        or anchor_count < 1
        or anchor_count > len(ledger.events)
        or ledger.events[anchor_count - 1].event_hash != anchor.get("head_hash")
    ):
        raise ReproductionError("frozen reproduction ledger prefix is invalid")
    prefix = ledger.events[:anchor_count]
    ledger_hashes: dict[str, str] = {}
    ledger_records: dict[str, str] = {}
    for event in prefix:
        logical_types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        if (
            not isinstance(logical_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(logical_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("frozen ledger projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            logical_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_hash) is None
            ):
                raise ReproductionError("frozen ledger provenance is malformed")
            if (
                logical_type in ledger_hashes
                and (
                    ledger_hashes[logical_type] != digest
                    or ledger_records[logical_type] != record_hash
                )
            ):
                raise ReproductionError("frozen ledger provenance conflicts")
            ledger_hashes[logical_type] = digest
            ledger_records[logical_type] = record_hash

    required = {
        "machine_results",
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    descriptors = replay_manifest.get("source_artifacts")
    if not isinstance(descriptors, Mapping) or set(descriptors) != required:
        raise ReproductionError("frozen reproduction source set is incomplete")
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    payloads: dict[str, dict[str, Any]] = {}
    for logical_type in required:
        descriptor = descriptors.get(logical_type)
        if (
            not isinstance(descriptor, Mapping)
            or descriptor.get("sha256") != ledger_hashes.get(logical_type)
            or descriptor.get("registry_record_hash")
            != ledger_records.get(logical_type)
        ):
            raise ReproductionError(
                f"frozen reproduction source is not ledger-bound: {logical_type}"
            )
        _, payloads[logical_type] = _descriptor_artifact(
            project_root, registry, descriptor, logical_type
        )
    packet_metadata: dict[str, Any] = {}
    for logical_type in ("reproduction_manifest", "reproduction_result"):
        digest_key = "manifest_sha256" if logical_type.endswith("manifest") else "result_sha256"
        record_key = "manifest_record_hash" if logical_type.endswith("manifest") else "result_record_hash"
        try:
            metadata = registry.get_metadata(str(frozen_record.get(digest_key)))
            registered_bytes = registry.get_bytes(metadata.sha256)
        except ArtifactError as exc:
            raise ReproductionError("registered reproduction packet is absent") from exc
        expected_bytes = (
            manifest_bytes if logical_type.endswith("manifest") else result_bytes
        )
        if (
            metadata.logical_type != logical_type
            or metadata.record_hash != frozen_record.get(record_key)
            or metadata.sha256 != frozen_record.get(digest_key)
            or metadata.frozen is not True
            or registered_bytes != expected_bytes
            or not registry.verify(metadata.sha256)
        ):
            raise ReproductionError("registered reproduction packet binding differs")
        packet_metadata[logical_type] = metadata
    if (
        tuple(packet_metadata["reproduction_manifest"].parent_artifacts)
        != (str(descriptors["machine_results"].get("sha256")),)
        or tuple(packet_metadata["reproduction_result"].parent_artifacts)
        != (str(frozen_record.get("manifest_sha256")),)
    ):
        raise ReproductionError("registered reproduction packet parent lineage differs")

    full_projection: dict[str, tuple[str, str]] = {}
    for event in ledger.events:
        logical_types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        if (
            not isinstance(logical_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(logical_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            continue
        for logical_type, digest, record_hash in zip(
            logical_types, event.artifact_hashes, record_hashes, strict=True
        ):
            prior = full_projection.get(str(logical_type))
            current = (str(digest), str(record_hash))
            if prior is not None and prior != current:
                raise ReproductionError("full ledger reproduction projection conflicts")
            full_projection[str(logical_type)] = current
    if "reproduction_report" in full_projection:
        try:
            report_metadata = registry.get_metadata(
                full_projection["reproduction_report"][0]
            )
            report_payload = _json_object(
                registry.get_bytes(report_metadata.sha256), "reproduction report"
            )
        except ArtifactError as exc:
            raise ReproductionError("ledger-bound reproduction report is absent") from exc
        if (
            report_metadata.record_hash
            != full_projection["reproduction_report"][1]
            or report_payload != dict(frozen_record)
            or tuple(report_metadata.parent_artifacts)
            != (
                str(descriptors["machine_results"].get("sha256")),
                str(frozen_record.get("manifest_sha256")),
                str(frozen_record.get("result_sha256")),
            )
        ):
            raise ReproductionError("supplied reproduction record is not ledger-bound")

    code_hash = replay_manifest.get("code_fingerprint")
    configuration_hash = replay_manifest.get("configuration_sha256")
    expected_command = [
        "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
        "reproduce", run_id,
    ]
    expected_environment = {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "architecture": platform.machine(),
        "platform": sys.platform,
        "python_executable_name": Path(sys.executable).name,
    }
    expected_device = {
        "selected_device": "cpu",
        "dtype": "float32",
        "operation": "difference_of_arithmetic_means_v1",
        "mps_used": False,
        "parity_required": False,
        "parity_evidence": (
            "CPU deterministic standard-library replay; no accelerator invoked"
        ),
    }
    if (
        replay_manifest.get("created_at") is None
        or not isinstance(replay_manifest.get("created_at"), str)
        or re.fullmatch(r"[0-9a-f]{20}", str(reproduction_id)) is None
        or replay_manifest.get("offline") is not True
        or replay_manifest.get("command") != expected_command
        or replay_manifest.get("algorithm")
        != "difference_of_arithmetic_means_v1"
        or replay_manifest.get("provider")
        != "BUILTIN_LOCAL_SYNTHETIC_FIXTURE"
        or replay_manifest.get("external_integrations_used") != []
        or replay_manifest.get("environment") != expected_environment
        or replay_manifest.get("device_execution") != expected_device
        or re.fullmatch(r"[0-9a-f]{64}", str(code_hash)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(configuration_hash)) is None
        or payloads["frozen_source_inventory"].get("aggregate_sha256") != code_hash
        or payloads["frozen_configuration_inventory"].get("aggregate_sha256")
        != configuration_hash
        or not _inventory_matches_live(
            project_root, payloads["frozen_source_inventory"]
        )
        or not _inventory_matches_live(
            project_root, payloads["frozen_configuration_inventory"]
        )
    ):
        raise ReproductionError("frozen reproduction inventory no longer verifies")
    machine = payloads["machine_results"]
    expected_input_types = {
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    machine_inputs = machine.get("input_hashes")
    protocol = payloads["frozen_protocol"]
    if (
        machine.get("code_fingerprint") != code_hash
        or machine.get("configuration_sha256") != configuration_hash
        or machine.get("evidence_class") != "SYNTHETIC_CONFIRMATORY_FIXTURE"
        or not isinstance(machine_inputs, Mapping)
        or set(machine_inputs) != expected_input_types
        or any(
            machine_inputs[name] != descriptors[name].get("sha256")
            for name in expected_input_types
        )
        or replay_manifest.get("input_hashes") != machine_inputs
        or machine.get("dataset_fixture_ids")
        != replay_manifest.get("dataset_fixture_ids")
        or machine.get("random_seeds") != replay_manifest.get("random_seeds")
    ):
        raise ReproductionError("frozen machine-result lineage is malformed")
    fixture = machine.get("frozen_fixture")
    if not isinstance(fixture, Mapping):
        raise ReproductionError("frozen reproduction fixture is absent")
    control = fixture.get("control")
    treatment = fixture.get("treatment")
    if not isinstance(control, list) or not isinstance(treatment, list):
        raise ReproductionError("frozen reproduction fixture is malformed")
    observed = _mean(treatment, "treatment") - _mean(control, "control")
    expected = replay_manifest.get("expected_primary_estimate")
    tolerance = replay_manifest.get("accepted_tolerance")
    if (
        isinstance(expected, bool)
        or not isinstance(expected, (int, float))
        or isinstance(tolerance, bool)
        or not isinstance(tolerance, (int, float))
    ):
        raise ReproductionError("frozen reproduction numeric contract is malformed")
    try:
        expected = float(expected)
        tolerance = float(tolerance)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("frozen reproduction numeric contract is non-finite") from exc
    difference = abs(observed - expected)
    reproduced_core = {
        "primary_estimate": observed,
        "control_mean": _mean(control, "control"),
        "treatment_mean": _mean(treatment, "treatment"),
        "n_control": len(control),
        "n_treatment": len(treatment),
    }
    expected_output_hashes = replay_manifest.get("expected_source_output_hashes")
    machine_output_hashes = machine.get("output_hashes")
    reproduced_hash = _sha256(_canonical_json(reproduced_core))
    fixture_ids = replay_manifest.get("dataset_fixture_ids")
    seeds = replay_manifest.get("random_seeds")
    protocol_tolerance = protocol.get("reproduction_tolerance")
    try:
        normalized_protocol_tolerance = float(protocol_tolerance)
    except (TypeError, OverflowError, ValueError) as exc:
        raise ReproductionError("frozen protocol tolerance is malformed") from exc
    identity = {
        "run_id": run_id,
        "source_result_sha256": descriptors["machine_results"].get("sha256"),
        "protocol_sha256": descriptors["frozen_protocol"].get("sha256"),
        "code_fingerprint": code_hash,
        "configuration_hash": configuration_hash,
        "input_hashes": dict(machine_inputs),
        "dataset_fixture_ids": fixture_ids,
        "random_seeds": seeds,
        "source_output_hashes": expected_output_hashes,
        "algorithm": replay_manifest.get("algorithm"),
        "tolerance": tolerance,
    }
    result_reproduced_hashes = replay_result.get("reproduced_output_hashes")
    result_expected_hashes = replay_result.get("expected_source_output_hashes")
    if (
        not all(math.isfinite(value) for value in (observed, expected, tolerance, difference))
        or tolerance < 0
        or not math.isfinite(normalized_protocol_tolerance)
        or normalized_protocol_tolerance != tolerance
        or difference > tolerance
        or machine.get("primary_estimate") != expected
        or machine.get("scientific_protocol_sha256")
        != protocol.get("protocol_sha256")
        or not isinstance(fixture_ids, list)
        or not fixture_ids
        or any(not isinstance(item, str) or not item for item in fixture_ids)
        or not isinstance(seeds, list)
        or not seeds
        or any(isinstance(item, bool) or not isinstance(item, int) for item in seeds)
        or not isinstance(machine_output_hashes, Mapping)
        or not isinstance(expected_output_hashes, Mapping)
        or set(machine_output_hashes) != {"result_core"}
        or set(expected_output_hashes) != {"result_core"}
        or machine_output_hashes != expected_output_hashes
        or expected_output_hashes.get("result_core") != reproduced_hash
        or _sha256(_canonical_json(identity))[:20] != reproduction_id
        or replay_result.get("status") != "PASS"
        or replay_result.get("expected_primary_estimate") != expected
        or replay_result.get("observed_primary_estimate") != observed
        or replay_result.get("absolute_difference") != difference
        or replay_result.get("accepted_tolerance") != tolerance
        or replay_result.get("numeric_comparison_passed") is not True
        or not isinstance(result_reproduced_hashes, Mapping)
        or not isinstance(result_expected_hashes, Mapping)
        or set(result_reproduced_hashes) != {"result_core"}
        or result_reproduced_hashes.get("result_core") != reproduced_hash
        or result_expected_hashes != expected_output_hashes
        or replay_result.get("input_hashes") != machine_inputs
        or replay_result.get("code_fingerprint") != code_hash
        or replay_result.get("configuration_sha256") != configuration_hash
        or replay_result.get("dataset_fixture_ids") != fixture_ids
        or replay_result.get("random_seeds") != seeds
        or replay_result.get("discrepancies") != []
        or replay_result.get("source_result_sha256")
        != descriptors["machine_results"].get("sha256")
    ):
        raise ReproductionError("frozen reproduction result does not recompute")
    base = ReproductionResult(
        run_id=run_id,
        status="PASS",
        reproduction_id=str(reproduction_id),
        expected=expected,
        observed=observed,
        absolute_difference=difference,
        tolerance=tolerance,
        manifest_path=manifest_path,
        result_path=result_path,
        source_result_sha256=str(descriptors["machine_results"].get("sha256")),
    )
    if any(frozen_record.get(key) != value for key, value in base.to_dict().items()):
        raise ReproductionError("frozen reproduction summary differs from replayed bytes")
    return base
