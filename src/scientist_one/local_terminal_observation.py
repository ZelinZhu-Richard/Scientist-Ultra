"""Strict, immutable operational capture values; not scientific provenance.

Only LocalMacBackend produces/replays these values. Constructing or decoding a
value does not attest execution, network isolation, population validity, or
scientific authority. The registry/ledger remain the scientific source owners.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ValidationError
from .models import validate_identifier, validate_sha256
from .security import DEFAULT_MAX_JSON_BYTES, canonical_json_bytes, safe_json_loads


LOCAL_TERMINAL_CAPTURE_METADATA_KEY = "local_terminal_capture"
LOCAL_TERMINAL_CAPTURE_PROFILE = MappingProxyType(
    {
        "schema_version": "SCIENTIST_ONE_LOCAL_TERMINAL_CAPTURE_PROFILE_V1",
        "profile_id": "EXPLORATORY_BOUND_CPU_TERMINAL_V1",
    }
)
LOCAL_TERMINAL_OBSERVATION_SCHEMA = "SCIENTIST_ONE_LOCAL_TERMINAL_OBSERVATION_V1"
LOCAL_TERMINAL_OBSERVATION_FILENAME = "terminal-observation.json"
LOCAL_TERMINAL_MAX_FILE_BYTES = 2 * 1024 * 1024
LOCAL_TERMINAL_MAX_TOTAL_BYTES = 4 * 1024 * 1024
LOCAL_TERMINAL_MAX_SOURCE_BYTES = 2 * 1024 * 1024
LOCAL_TERMINAL_MAX_JSON_BYTES = DEFAULT_MAX_JSON_BYTES
LOCAL_TERMINAL_MAX_OUTPUTS = 128
LOCAL_TERMINAL_MAX_LOG_BYTES = 1024 * 1024
LOCAL_TERMINAL_MAX_FILES = LOCAL_TERMINAL_MAX_OUTPUTS + 12
# Each path has at most 1024 characters (at most six JSON bytes per
# character); seven signed 4096-bit identity integers need <1240 bytes
# each. The remaining per-file fields fit 512 bytes. 64KiB is reserved
# for all top-level fields. Base64 padding is reserved separately per file.
LOCAL_TERMINAL_METADATA_RESERVE_BYTES = (
    LOCAL_TERMINAL_MAX_FILES * (6 * 1024 + 7 * 1240 + 512) + 64 * 1024
)
LOCAL_TERMINAL_WORST_CASE_JSON_BYTES = (
    4 * ((LOCAL_TERMINAL_MAX_TOTAL_BYTES + 2 * LOCAL_TERMINAL_MAX_FILES) // 3)
    + LOCAL_TERMINAL_METADATA_RESERVE_BYTES
    + 1
)


def validate_terminal_capture_limits() -> None:
    """Reject a profile whose deterministic envelope exceeds the shared codec."""

    if (
        LOCAL_TERMINAL_MAX_FILE_BYTES > LOCAL_TERMINAL_MAX_TOTAL_BYTES
        or LOCAL_TERMINAL_MAX_SOURCE_BYTES > LOCAL_TERMINAL_MAX_TOTAL_BYTES
        or LOCAL_TERMINAL_WORST_CASE_JSON_BYTES > LOCAL_TERMINAL_MAX_JSON_BYTES
        or LOCAL_TERMINAL_MAX_JSON_BYTES > DEFAULT_MAX_JSON_BYTES
    ):
        raise ValidationError("terminal capture exceeds the shared canonical codec")


def _exact_keys(value: Any, names: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise ValidationError("terminal capture has an invalid closed schema")
    return value


@dataclass(frozen=True)
class LocalTerminalFile:
    """One declared path observation, with no bytes inferred for unsafe files.

    identity is dev/inode/mode/nlink/size/mtime_ns/ctime_ns. It is local runtime
    identity, not portable scientific provenance. Missing/unsafe observations
    do not establish that any seed ran or failed.
    """

    role: str
    path: str
    status: str
    identity: tuple[int, ...] | None
    payload: bytes | None = field(repr=False)

    def __post_init__(self) -> None:
        if self.role not in {"source", "log", "manifest", "output"}:
            raise ValidationError("unknown terminal file role")
        if not isinstance(self.path, str) or not 1 <= len(self.path) <= 1024:
            raise ValidationError("terminal path is not bounded")
        try:
            self.path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValidationError(
                "terminal decoded path is not canonical UTF-8"
            ) from exc
        if self.status not in {
            "CAPTURED",
            "MISSING",
            "UNSAFE",
            "OVER_LIMIT",
            "UNAVAILABLE",
            "ERROR",
        }:
            raise ValidationError("unknown terminal file status")
        if self.identity is not None and (
            type(self.identity) is not tuple
            or len(self.identity) != 7
            or any(
                type(value) is not int or value.bit_length() > 4096
                for value in self.identity
            )
        ):
            raise ValidationError("terminal file identity is invalid")
        if self.status == "CAPTURED":
            if (
                type(self.payload) is not bytes
                or len(self.payload) > LOCAL_TERMINAL_MAX_FILE_BYTES
                or self.identity is None
                or len(self.payload) != self.identity[4]
            ):
                raise ValidationError("terminal captured bytes are invalid")
        elif self.payload is not None:
            raise ValidationError("uncaptured terminal file cannot claim bytes")
        if self.status == "MISSING" and self.identity is not None:
            raise ValidationError("missing terminal file cannot claim an identity")

    @property
    def sha256(self) -> str | None:
        return (
            hashlib.sha256(self.payload).hexdigest()
            if self.payload is not None
            else None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "status": self.status,
            "identity": list(self.identity) if self.identity is not None else None,
            "sha256": self.sha256,
            "payload_base64": (
                base64.b64encode(self.payload).decode("ascii")
                if self.payload is not None
                else None
            ),
        }

    @classmethod
    def from_mapping(cls, value: Any) -> LocalTerminalFile:
        value = _exact_keys(
            value,
            {
                "role",
                "path",
                "status",
                "identity",
                "sha256",
                "payload_base64",
            },
        )
        encoded = value["payload_base64"]
        if encoded is not None and (
            type(encoded) is not str
            or len(encoded) > ((LOCAL_TERMINAL_MAX_FILE_BYTES + 2) // 3) * 4
        ):
            raise ValidationError("terminal encoded bytes exceed the profile")
        try:
            payload = (
                base64.b64decode(encoded, validate=True)
                if encoded is not None
                else None
            )
        except (ValueError, TypeError) as exc:
            raise ValidationError("terminal encoded bytes are malformed") from exc
        identity = value["identity"]
        if identity is not None and type(identity) is not list:
            raise ValidationError("terminal file identity must be a list")
        result = cls(
            role=value["role"],
            path=value["path"],
            status=value["status"],
            identity=tuple(identity) if identity is not None else None,
            payload=payload,
        )
        if result.sha256 != value["sha256"]:
            raise ValidationError("terminal file content digest differs")
        return result


@dataclass(frozen=True)
class LocalTerminalObservation:
    """A byte-exact backend operational observation, never a scientific Result."""

    job_id: str
    submission_idempotency_key: str
    spec_sha256: str
    execution_plan_sha256: str
    execution_input_binding_sha256: str
    directory_identity: tuple[int, int]
    state: str
    reason: str
    invocation_count: int
    proven_popen_launch_count: int
    launch_observation: str
    returncode: int | None
    timed_out: bool | None
    stdout_truncated: bool | None
    stderr_truncated: bool | None
    stdout_capture_status: str
    stderr_capture_status: str
    log_capture_complete: bool
    delivery_inventory_status: str
    accepted_manifest_sha256: str | None
    files: tuple[LocalTerminalFile, ...]
    execution_mode: str = "BOUND_BUILTIN"
    scientific_evidence: bool = False
    independent_execution_attested: bool = False
    network_use_status: str = "UNKNOWN_UNATTESTED"
    network_isolation_attested: bool = False
    schema_version: str = LOCAL_TERMINAL_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        validate_terminal_capture_limits()
        validate_identifier(self.job_id, "terminal job ID")
        validate_identifier(self.submission_idempotency_key, "terminal submission key")
        for digest in (
            self.spec_sha256,
            self.execution_plan_sha256,
            self.execution_input_binding_sha256,
        ):
            validate_sha256(digest, "terminal source SHA-256")
        if self.accepted_manifest_sha256 is not None:
            validate_sha256(self.accepted_manifest_sha256, "terminal manifest SHA-256")
        if (
            type(self.directory_identity) is not tuple
            or len(self.directory_identity) != 2
            or any(
                type(item) is not int or item.bit_length() > 4096
                for item in self.directory_identity
            )
        ):
            raise ValidationError("terminal directory identity is invalid")
        if self.state not in {"SUCCEEDED", "FAILED", "INVALID_OUTPUT", "CANCELLED"}:
            raise ValidationError("terminal state is invalid")
        if (
            type(self.reason) is not str
            or not 1 <= len(self.reason) <= 128
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789:-"
                for character in self.reason
            )
        ):
            raise ValidationError("terminal reason must be a bounded backend code")
        if (
            type(self.invocation_count) is not int
            or type(self.proven_popen_launch_count) is not int
            or not 0 <= self.proven_popen_launch_count <= self.invocation_count <= 1
        ):
            raise ValidationError("terminal invocation/launch count is invalid")
        if self.returncode is not None and (
            type(self.returncode) is not int or self.returncode.bit_length() > 4096
        ):
            raise ValidationError("terminal return code must be an integer or unknown")
        expected_launch = (
            "NOT_INVOKED"
            if self.invocation_count == 0
            else "POPEN_RETURNED"
            if self.proven_popen_launch_count == 1
            else "UNKNOWN_AFTER_INVOCATION"
        )
        if self.launch_observation != expected_launch:
            raise ValidationError(
                "terminal launch observation contradicts native counts"
            )
        if (self.returncode is not None) != (self.proven_popen_launch_count == 1):
            raise ValidationError(
                "terminal process completion is unresolved or contradictory"
            )
        for value in (self.timed_out, self.stdout_truncated, self.stderr_truncated):
            if value is not None and type(value) is not bool:
                raise ValidationError(
                    "terminal process flags must be boolean or unknown"
                )
        if type(self.log_capture_complete) is not bool:
            raise ValidationError("terminal log completeness is invalid")
        for value in (self.stdout_capture_status, self.stderr_capture_status):
            if value not in {"COMPLETE", "INCOMPLETE", "UNAVAILABLE"}:
                raise ValidationError("terminal stream capture status is invalid")
        if self.log_capture_complete != (
            self.stdout_capture_status == self.stderr_capture_status == "COMPLETE"
        ):
            raise ValidationError("terminal stream completeness is inconsistent")
        if self.delivery_inventory_status not in {
            "MANIFEST_DECLARED_PATHS",
            "UNRESOLVED_MANIFEST",
        }:
            raise ValidationError("terminal output inventory scope is invalid")
        if (
            self.execution_mode != "BOUND_BUILTIN"
            or self.scientific_evidence is not False
            or self.independent_execution_attested is not False
            or self.network_use_status != "UNKNOWN_UNATTESTED"
            or self.network_isolation_attested is not False
            or self.schema_version != LOCAL_TERMINAL_OBSERVATION_SCHEMA
        ):
            raise ValidationError(
                "terminal capture cannot claim execution/scientific attestation"
            )
        if (
            type(self.files) is not tuple
            or not 11 <= len(self.files) <= LOCAL_TERMINAL_MAX_OUTPUTS + 12
            or any(not isinstance(item, LocalTerminalFile) for item in self.files)
            or len({item.path for item in self.files}) != len(self.files)
            or sum(len(item.payload or b"") for item in self.files)
            > LOCAL_TERMINAL_MAX_TOTAL_BYTES
        ):
            raise ValidationError("terminal files are invalid or exceed the profile")
        if self.state == "SUCCEEDED":
            if (
                self.accepted_manifest_sha256 is None
                or self.returncode != 0
                or self.timed_out is not False
                or not self.log_capture_complete
                or self.proven_popen_launch_count != 1
                or self.delivery_inventory_status != "MANIFEST_DECLARED_PATHS"
                or any(item.status != "CAPTURED" for item in self.files)
            ):
                raise ValidationError("successful terminal capture is incomplete")
        elif self.accepted_manifest_sha256 is not None:
            raise ValidationError(
                "unsuccessful terminal capture cannot accept a manifest"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name not in {"files", "directory_identity"}
            },
            "directory_identity": list(self.directory_identity),
            "files": [item.to_dict() for item in self.files],
        }

    @property
    def payload(self) -> bytes:
        return canonical_json_bytes(self.to_dict()) + b"\n"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> LocalTerminalObservation:
        value = _exact_keys(
            safe_json_loads(payload, max_bytes=LOCAL_TERMINAL_MAX_JSON_BYTES),
            set(cls.__dataclass_fields__),
        )
        if (
            type(value["files"]) is not list
            or len(value["files"]) > LOCAL_TERMINAL_MAX_OUTPUTS + 12
        ):
            raise ValidationError("terminal file list exceeds the profile")
        if type(value["directory_identity"]) is not list:
            raise ValidationError("terminal directory identity must be a list")
        result = cls(
            **{
                **value,
                "files": tuple(
                    LocalTerminalFile.from_mapping(item) for item in value["files"]
                ),
                "directory_identity": tuple(value["directory_identity"]),
            }
        )
        if result.payload != payload:
            raise ValidationError("terminal observation must use exact canonical bytes")
        return result
